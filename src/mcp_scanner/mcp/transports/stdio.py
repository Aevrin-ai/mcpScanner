# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""stdio transport: one JSON message per line on the server's stdin and stdout."""

from __future__ import annotations

import json
import time

from mcp_scanner.core.errors import MCPConnectionError
from mcp_scanner.mcp.transports.base import Message, Transport
from mcp_scanner.sandbox.process import SandboxedProcess


class StdioTransport(Transport):
    def __init__(self, process: SandboxedProcess) -> None:
        super().__init__()
        self.process = process

    def send(self, message: Message) -> None:
        data = json.dumps(message, separators=(",", ":")).encode("utf-8")
        try:
            self.process.write_line(data)
        except (BrokenPipeError, OSError) as exc:
            raise MCPConnectionError(self._exit_detail("Server stopped reading input")) from exc

    def receive(self, timeout: float) -> Message | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                line = self.process.read_line(remaining)
            except EOFError as exc:
                raise MCPConnectionError(self._exit_detail("Server closed the connection")) from exc
            if line is None:
                return None
            message = self._parse(line)
            if message is not None:
                return message

    def _parse(self, line: bytes) -> Message | None:
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            return None
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            # Many servers print logs to stdout by mistake. It breaks some clients.
            self.note("non-json-output", text)
            return None
        if not isinstance(value, dict):
            self.note("invalid-message", f"expected a JSON object, got {type(value).__name__}")
            return None
        return value

    def _exit_detail(self, prefix: str) -> str:
        tail = self.process.stderr_tail().strip().splitlines()[-5:]
        hint = " | ".join(line[:200] for line in tail)
        killed = self.process.observations.killed_reason
        parts = [prefix]
        if killed:
            parts.append(f"(stopped by watchdog: {killed})")
        if hint:
            parts.append(f"- last server output: {hint}")
        return " ".join(parts)

    def close(self) -> None:
        # The process is stopped by the connection, which owns it.
        return None
