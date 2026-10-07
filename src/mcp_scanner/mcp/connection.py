# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Connect to one MCP server, whatever its transport.

Example:

    server = MCPServer(spec, settings, HostPolicy(allow_host=True))
    with server.connect() as connection:
        tools = connection.list_tools()

Leaving the `with` block always stops the server and deletes its workspace.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from mcp_scanner.config.expand import expand_mapping
from mcp_scanner.config.settings import Settings
from mcp_scanner.core.errors import MCPError, MCPTimeoutError, ScannerError
from mcp_scanner.mcp.session import MCPSession
from mcp_scanner.mcp.transports.base import Transport
from mcp_scanner.mcp.transports.http import HttpTransport
from mcp_scanner.mcp.transports.sse import SseTransport
from mcp_scanner.mcp.transports.stdio import StdioTransport
from mcp_scanner.models.mcp import ToolInfo
from mcp_scanner.models.observations import SandboxObservations
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.sandbox.canary import CanarySet
from mcp_scanner.sandbox.launcher import HostPolicy, launch
from mcp_scanner.sandbox.process import SandboxedProcess
from mcp_scanner.sandbox.workspace import CACHE_PREFIXES, Workspace

log = logging.getLogger(__name__)


class Connection:
    """A live, initialized MCP session plus the things around it."""

    def __init__(
        self,
        spec: ServerSpec,
        session: MCPSession,
        canary: CanarySet,
        process: SandboxedProcess | None = None,
        workspace: Workspace | None = None,
    ) -> None:
        self.spec = spec
        self.session = session
        self.canary = canary
        self.process = process
        self.workspace = workspace
        # Filled when the connection closes.
        self.sandbox_observations = SandboxObservations(sandbox_mode="remote" if process is None else "process")

    @property
    def initialize_result(self) -> dict[str, Any]:
        return self.session.initialize_result

    def set_phase(self, phase: str) -> None:
        """Tell the watchdog what the scan is doing now, so events can be labelled."""
        if self.process is not None:
            self.process.phase = phase

    def list_tools(self) -> list[ToolInfo]:
        return [ToolInfo.from_wire(t) for t in self.session.list_all("tools/list", "tools")]


class MCPServer:
    def __init__(
        self,
        spec: ServerSpec,
        settings: Settings,
        host_policy: HostPolicy | None = None,
        canary: CanarySet | None = None,
    ) -> None:
        if spec.transport == TransportType.OFFLINE:
            raise ScannerError("Offline tool files do not need a connection")
        self.spec = spec
        self.settings = settings
        self.host_policy = host_policy or HostPolicy(allow_host=settings.sandbox.allow_host)
        self.canary = canary or CanarySet()
        # What the sandbox saw on the last run, even when the connection failed.
        self.last_observations: SandboxObservations | None = None

    @contextmanager
    def connect(self) -> Iterator[Connection]:
        if self.spec.is_local_process:
            with self._connect_stdio() as connection:
                yield connection
        else:
            with self._connect_remote() as connection:
                yield connection

    @contextmanager
    def _connect_stdio(self) -> Iterator[Connection]:
        sandbox = self.settings.sandbox
        workspace = Workspace(self.canary, with_decoys=sandbox.isolate_home, keep=sandbox.keep_workspace)
        process: SandboxedProcess | None = None
        connection: Connection | None = None
        try:
            process = launch(
                self.spec, sandbox, workspace, self.canary, self.host_policy, self.settings.timeouts.install
            )
            transport = StdioTransport(process)
            session = MCPSession(transport, self.settings.timeouts.request)
            self._initialize(session, process)
            connection = Connection(self.spec, session, self.canary, process, workspace)
            connection.set_phase("listing")
            yield connection
        finally:
            observations = process.stop() if process is not None else SandboxObservations()
            observations.files_written = workspace.changed_files(CACHE_PREFIXES)
            self.last_observations = observations
            if connection is not None:
                connection.sandbox_observations = observations
            workspace.cleanup()

    def _initialize(self, session: MCPSession, process: SandboxedProcess) -> None:
        try:
            session.initialize(timeout=self.settings.timeouts.startup)
        except MCPTimeoutError as exc:
            tail = process.stderr_tail().strip().splitlines()[-3:]
            hint = f" Last server output: {' | '.join(tail)}" if tail else ""
            raise MCPTimeoutError(f"{exc}.{hint}") from exc

    @contextmanager
    def _connect_remote(self) -> Iterator[Connection]:
        transport = self._remote_transport()
        try:
            session = MCPSession(transport, self.settings.timeouts.request)
            session.initialize(timeout=self.settings.timeouts.startup)
            yield Connection(self.spec, session, self.canary)
        finally:
            try:
                transport.close()
            except (MCPError, OSError):
                log.debug("Error while closing transport", exc_info=True)

    def _remote_transport(self) -> Transport:
        url = self.spec.url or ""
        headers = expand_mapping(self.spec.headers)
        timeout = self.settings.timeouts.request
        max_bytes = self.settings.sandbox.max_message_mb * 1024 * 1024
        if self.spec.transport == TransportType.SSE:
            return SseTransport(url, headers, timeout, max_bytes)
        return HttpTransport(url, headers, timeout, max_bytes)
