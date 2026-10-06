# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Run a server as a child process that we fully control.

What this gives you:
  - stdout is read line by line in a background thread
  - stderr is kept, but only the last part, so a noisy server cannot fill memory
  - a watchdog stops the server if it uses too much memory, CPU, or processes
  - stop() kills the whole process tree, even children the server started

What this does NOT give you:
  - it is not a security wall. The server runs as your user and can read your files
    if it really wants to. Use the Docker sandbox for untrusted servers.
"""

from __future__ import annotations

import logging
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import psutil

from mcp_scanner.core.errors import SandboxError
from mcp_scanner.models.observations import NetworkEvent, ProcessEvent, SandboxObservations

log = logging.getLogger(__name__)

STDERR_TAIL_BYTES = 16_384
_EOF = object()


@dataclass
class ProcessLimits:
    memory_mb: int = 1024
    max_processes: int = 32
    cpu_seconds: int = 300
    max_line_bytes: int = 16 * 1024 * 1024
    watch_network: bool = True
    poll_seconds: float = 0.5


@dataclass
class _WatchState:
    seen_pids: set[int] = field(default_factory=set)
    seen_conns: set[tuple[int, str]] = field(default_factory=set)


class SandboxedProcess:
    """A running server process with pipes, a watchdog, and safe shutdown."""

    def __init__(
        self,
        argv: Sequence[str],
        env: dict[str, str],
        cwd: str,
        limits: ProcessLimits,
        *,
        sandbox_mode: str = "process",
        watch_tree: bool = True,
        on_stop: Callable[[], None] | None = None,
    ) -> None:
        self.argv = list(argv)
        self.limits = limits
        self.observations = SandboxObservations(sandbox_mode=sandbox_mode)
        self.phase = "startup"
        self._lines: queue.Queue[object] = queue.Queue()
        self._stderr: deque[bytes] = deque()
        self._stderr_size = 0
        self._stop_event = threading.Event()
        self._watch = _WatchState()
        self._on_stop = on_stop
        self._watch_tree = watch_tree
        self._lock = threading.Lock()
        self.oversized_lines = 0
        self._popen = self._spawn(env, cwd)
        self._threads = [
            threading.Thread(target=self._read_stdout, name="server-stdout", daemon=True),
            threading.Thread(target=self._read_stderr, name="server-stderr", daemon=True),
        ]
        if watch_tree:
            self._threads.append(threading.Thread(target=self._watchdog, name="server-watchdog", daemon=True))
        for thread in self._threads:
            thread.start()

    # ---- start -------------------------------------------------------------

    def _spawn(self, env: dict[str, str], cwd: str) -> subprocess.Popen[bytes]:
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            # A new process group lets us stop the server without hitting the scanner.
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        else:
            # A new session makes the server the leader of its own process group,
            # so we can kill the whole group later.
            kwargs["start_new_session"] = True
            kwargs["preexec_fn"] = _posix_limits(self.limits)
        try:
            return subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=cwd,
                bufsize=0,
                **kwargs,
            )
        except OSError as exc:
            raise SandboxError(f"Could not start server '{self.argv[0]}': {exc.strerror or exc}") from exc

    # ---- pipes -------------------------------------------------------------

    def _read_stdout(self) -> None:
        stream = self._popen.stdout
        assert stream is not None
        try:
            while True:
                line = stream.readline(self.limits.max_line_bytes)
                if not line:
                    break
                if not line.endswith(b"\n") and len(line) >= self.limits.max_line_bytes:
                    # A single message is too big. Drop it and skip to the next line.
                    self.oversized_lines += 1
                    self._skip_to_newline(stream)
                    continue
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._lines.put(_EOF)

    @staticmethod
    def _skip_to_newline(stream: object) -> None:
        reader = stream.readline  # type: ignore[attr-defined]
        while True:
            chunk = reader(65536)
            if not chunk or chunk.endswith(b"\n"):
                return

    def _read_stderr(self) -> None:
        stream = self._popen.stderr
        assert stream is not None
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                with self._lock:
                    self._stderr.append(chunk)
                    self._stderr_size += len(chunk)
                    while self._stderr_size > STDERR_TAIL_BYTES and len(self._stderr) > 1:
                        self._stderr_size -= len(self._stderr.popleft())
        except (OSError, ValueError):
            pass

    def write_line(self, data: bytes) -> None:
        stdin = self._popen.stdin
        if stdin is None or self._popen.poll() is not None:
            raise BrokenPipeError("server process has exited")
        stdin.write(data + b"\n")
        stdin.flush()

    def read_line(self, timeout: float) -> bytes | None:
        """Return the next stdout line, or None on timeout. Raises EOFError when stdout closed."""
        try:
            item = self._lines.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None
        if item is _EOF:
            self._lines.put(_EOF)  # keep the EOF marker for later readers
            raise EOFError("server closed its output")
        assert isinstance(item, bytes)
        return item

    def stderr_tail(self) -> str:
        with self._lock:
            data = b"".join(self._stderr)
        return data[-STDERR_TAIL_BYTES:].decode("utf-8", errors="replace")

    @property
    def pid(self) -> int:
        return self._popen.pid

    def is_alive(self) -> bool:
        return self._popen.poll() is None

    # ---- watchdog ----------------------------------------------------------

    def _watchdog(self) -> None:
        try:
            root = psutil.Process(self._popen.pid)
        except psutil.Error:
            return
        # Look right away, then on every tick, so short lived children are seen too.
        while True:
            if not self.is_alive():
                return
            try:
                procs = [root, *root.children(recursive=True)]
            except psutil.Error:
                return
            reason = self._check_tree(procs)
            if reason:
                log.warning("Stopping server: %s", reason)
                self.observations.killed_reason = reason
                self._kill_tree()
                return
            if self._stop_event.wait(self.limits.poll_seconds):
                return

    def _check_tree(self, procs: list[psutil.Process]) -> str | None:
        rss = 0
        cpu = 0.0
        for proc in procs:
            try:
                with proc.oneshot():
                    # Record first: reading memory can fail for a moment while a process starts.
                    self._record_process(proc)
                    rss += proc.memory_info().rss
                    times = proc.cpu_times()
                    cpu += times.user + times.system
                    if self.limits.watch_network:
                        self._record_connections(proc)
            except psutil.Error:
                continue
        memory_mb = rss / (1024 * 1024)
        self.observations.peak_memory_mb = max(self.observations.peak_memory_mb, round(memory_mb, 1))
        if memory_mb > self.limits.memory_mb:
            return f"memory limit reached ({memory_mb:.0f} MB > {self.limits.memory_mb} MB)"
        if len(procs) > self.limits.max_processes:
            return f"process limit reached ({len(procs)} > {self.limits.max_processes})"
        if cpu > self.limits.cpu_seconds:
            return f"CPU time limit reached ({cpu:.0f}s > {self.limits.cpu_seconds}s)"
        return None

    def _record_process(self, proc: psutil.Process) -> None:
        if proc.pid == self._popen.pid or proc.pid in self._watch.seen_pids:
            return
        self._watch.seen_pids.add(proc.pid)
        try:
            cmdline = " ".join(proc.cmdline())[:300]
        except psutil.Error:
            cmdline = ""
        event = ProcessEvent(pid=proc.pid, name=proc.name(), cmdline=cmdline, phase=self.phase)
        self.observations.child_processes.append(event)

    def _record_connections(self, proc: psutil.Process) -> None:
        try:
            conns = proc.net_connections(kind="inet")
        except (psutil.Error, OSError):
            return
        for conn in conns:
            if not conn.raddr:
                continue
            address = f"{conn.raddr.ip}:{conn.raddr.port}"
            key = (proc.pid, address)
            if key in self._watch.seen_conns:
                continue
            self._watch.seen_conns.add(key)
            self.observations.network_connections.append(
                NetworkEvent(pid=proc.pid, remote_address=address, status=str(conn.status), phase=self.phase)
            )

    # ---- stop --------------------------------------------------------------

    def stop(self, grace_seconds: float = 2.0) -> SandboxObservations:
        """Stop the server and every process it started. Safe to call twice."""
        self._stop_event.set()
        # Find the children first. On Windows, once the parent exits, its children can no
        # longer be found through it, and they would keep running.
        known = self._descendants()
        try:
            if self._popen.stdin:
                self._popen.stdin.close()
        except OSError:
            pass
        try:
            self._popen.wait(timeout=min(grace_seconds, 1.0))
        except subprocess.TimeoutExpired:
            self._kill_tree(grace_seconds, known)
        else:
            self._kill_tree(0.5, known)  # the parent left, but children may still run
        if self._on_stop:
            self._on_stop()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self.observations.exit_code = self._popen.poll()
        self.observations.stderr_tail = self.stderr_tail()[-4000:]
        return self.observations

    def _descendants(self) -> list[psutil.Process]:
        if not self._watch_tree:
            return []
        try:
            children = psutil.Process(self._popen.pid).children(recursive=True)
        except psutil.Error:
            return []
        for child in children:
            try:
                self._record_process(child)
            except psutil.Error:
                continue
        return children

    def _kill_tree(self, grace_seconds: float = 1.0, known: list[psutil.Process] | None = None) -> None:
        try:
            parent = psutil.Process(self._popen.pid)
            children = parent.children(recursive=True)
        except psutil.Error:
            parent, children = None, []
        # psutil checks the start time too, so a reused process ID is never killed by mistake.
        pids = {c.pid for c in children}
        children += [p for p in known or [] if p.pid not in pids and p.is_running()]
        if sys.platform != "win32":
            try:
                os.killpg(self._popen.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        procs = [p for p in [*children, parent] if p is not None]
        for proc in procs:
            try:
                proc.terminate()
            except psutil.Error:
                pass
        _, alive = psutil.wait_procs(procs, timeout=grace_seconds)
        for proc in alive:
            try:
                proc.kill()
            except psutil.Error:
                pass
        if sys.platform != "win32":
            try:
                os.killpg(self._popen.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            self._popen.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self._popen.kill()


def _posix_limits(limits: ProcessLimits) -> Callable[[], None] | None:
    """Kernel limits for Linux and macOS. Memory is watched by the watchdog instead,
    because a hard address-space limit breaks Node.js, which reserves a lot of virtual memory."""
    if sys.platform == "win32":
        return None

    def apply() -> None:
        import resource

        cpu = limits.cpu_seconds
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        file_limit = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    return apply


def wait_until(predicate: Callable[[], bool], timeout: float, step: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()
