# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""An MCP client session over any transport.

The scanner is a careful client:
  - It tells the server it supports no extra features (no sampling, no roots, no elicitation).
  - If the server still asks for them, we refuse and record it as evidence.
  - Every request has a timeout.
"""

from __future__ import annotations

import itertools
import logging
import time
from typing import Any

from mcp_scanner import __version__
from mcp_scanner.core.errors import (
    MCPConnectionError,
    MCPProtocolError,
    MCPRemoteError,
    MCPTimeoutError,
)
from mcp_scanner.mcp.transports.base import Message, Transport

log = logging.getLogger(__name__)

LATEST_PROTOCOL_VERSION = "2025-11-25"
CLIENT_INFO = {"name": "aevrin-mcp-scanner", "version": __version__}
MAX_PAGES = 50
MAX_ITEMS = 5000


class MCPSession:
    def __init__(self, transport: Transport, request_timeout: float = 30.0) -> None:
        self.transport = transport
        self.request_timeout = request_timeout
        self._ids = itertools.count(1)
        self.initialize_result: dict[str, Any] = {}
        self.notifications: list[str] = []
        self.list_changed_seen = False

    # ---- low level ---------------------------------------------------------

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: Message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.transport.send(message)

    def request(
        self, method: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        """Send a request and wait for its answer."""
        request_id = next(self._ids)
        message: Message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.transport.send(message)
        deadline = time.monotonic() + (timeout or self.request_timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPTimeoutError(f"No answer to '{method}' in {timeout or self.request_timeout:.0f}s")
            incoming = self.transport.receive(remaining)
            if incoming is None:
                continue
            if self._is_response_to(incoming, request_id):
                return self._result_of(incoming, method)
            self._handle_other(incoming)

    @staticmethod
    def _is_response_to(message: Message, request_id: int) -> bool:
        return "method" not in message and message.get("id") == request_id

    @staticmethod
    def _result_of(message: Message, method: str) -> dict[str, Any]:
        error = message.get("error")
        if isinstance(error, dict):
            raise MCPRemoteError(int(error.get("code", -32603)), str(error.get("message", "")), method)
        result = message.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError(f"Answer to '{method}' has no result object")
        return result

    def _handle_other(self, message: Message) -> None:
        method = message.get("method")
        if not isinstance(method, str):
            self.transport.note("unexpected-message", "an answer to a request we did not send")
            return
        if "id" in message:
            self._answer_server_request(message, method)
            return
        self.notifications.append(method)
        if method.endswith("/list_changed"):
            self.list_changed_seen = True

    def _answer_server_request(self, message: Message, method: str) -> None:
        """The server asked US something. We only answer ping."""
        if method == "ping":
            self._reply(message["id"], result={})
            return
        self.transport.note("server-request", f"server asked the client to run '{method}'", method=method)
        self._reply(message["id"], error={"code": -32601, "message": "Not supported by this client"})

    def _reply(self, request_id: Any, *, result: Any = None, error: Any = None) -> None:
        reply: Message = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            reply["error"] = error
        else:
            reply["result"] = result
        try:
            self.transport.send(reply)
        except MCPConnectionError:
            log.debug("Could not answer server request", exc_info=True)

    # ---- MCP methods -------------------------------------------------------

    def initialize(self, timeout: float | None = None) -> dict[str, Any]:
        params = {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        }
        result = self.request("initialize", params, timeout=timeout)
        version = result.get("protocolVersion")
        if isinstance(version, str):
            self.transport.set_protocol_version(version)
        self.initialize_result = result
        self.notify("notifications/initialized")
        return result

    @property
    def server_capabilities(self) -> dict[str, Any]:
        caps = self.initialize_result.get("capabilities")
        return caps if isinstance(caps, dict) else {}

    def list_all(self, method: str, key: str) -> list[dict[str, Any]]:
        """Call a list method and follow every page."""
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(MAX_PAGES):
            params = {"cursor": cursor} if cursor else None
            result = self.request(method, params)
            page = result.get(key)
            if isinstance(page, list):
                items.extend(item for item in page if isinstance(item, dict))
            cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
            if not cursor or cursor in seen_cursors or len(items) >= MAX_ITEMS:
                break
            seen_cursors.add(cursor)
        else:
            self.transport.note("pagination-limit", f"{method} still had more pages after {MAX_PAGES}")
        return items[:MAX_ITEMS]

    def call_tool(self, name: str, arguments: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)

    def get_prompt(self, name: str, arguments: dict[str, str], timeout: float | None = None) -> dict[str, Any]:
        return self.request("prompts/get", {"name": name, "arguments": arguments}, timeout=timeout)

    def read_resource(self, uri: str, timeout: float | None = None) -> dict[str, Any]:
        return self.request("resources/read", {"uri": uri}, timeout=timeout)
