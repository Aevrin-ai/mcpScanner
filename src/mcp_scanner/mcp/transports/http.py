# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Streamable HTTP transport (the modern remote MCP transport).

Each message is an HTTP POST. The answer comes back either as plain JSON or as
a short server-sent event stream.
"""

from __future__ import annotations

import json
import queue
from typing import Any

import httpx

from mcp_scanner import __version__
from mcp_scanner.core.errors import MCPAuthError, MCPConnectionError, MCPTimeoutError
from mcp_scanner.mcp.sse import parse_sse_lines
from mcp_scanner.mcp.transports.base import Message, Transport

USER_AGENT = f"aevrin-mcp-scanner/{__version__}"


def make_client(headers: dict[str, str], timeout: float) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": USER_AGENT, **headers},
        timeout=httpx.Timeout(timeout, connect=min(timeout, 15.0)),
        follow_redirects=True,
        max_redirects=3,
    )


def auth_hint(response: httpx.Response) -> str:
    """Which credentials the server asks for, from its WWW-Authenticate header."""
    challenge = response.headers.get("WWW-Authenticate", "")
    scheme = challenge.split(" ", 1)[0].lower()
    if "resource_metadata" in challenge:
        return (
            "It uses MCP OAuth: sign in with its provider to get an access token, then pass "
            "--header 'Authorization: Bearer <token>'."
        )
    if scheme == "bearer":
        return "It expects a bearer token: --header 'Authorization: Bearer <token>'."
    if scheme == "basic":
        return "It expects a user name and password: --header 'Authorization: Basic <base64 of user:password>'."
    return "Add credentials with --header, for example --header 'Authorization: Bearer <token>'."


def raise_for_status(response: httpx.Response, url: str) -> None:
    status = response.status_code
    if status in (401, 403):
        raise MCPAuthError(f"The server at {url} refused access (HTTP {status}). {auth_hint(response)}")
    if status >= 400:
        raise MCPConnectionError(f"The server at {url} answered HTTP {status}")


class HttpTransport(Transport):
    def __init__(self, url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> None:
        super().__init__()
        self.url = url
        self.max_bytes = max_bytes
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._client = make_client(headers, timeout)
        self._inbox: queue.Queue[Message] = queue.Queue()

    def set_protocol_version(self, version: str) -> None:
        self.protocol_version = version

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return headers

    def send(self, message: Message) -> None:
        body = json.dumps(message).encode("utf-8")
        try:
            with self._client.stream("POST", self.url, content=body, headers=self._headers()) as response:
                self._handle_response(response, message.get("id"))
        except httpx.TimeoutException as exc:
            raise MCPTimeoutError(f"No answer from {self.url} in time") from exc
        except httpx.HTTPError as exc:
            raise MCPConnectionError(f"Could not reach {self.url}: {type(exc).__name__}") from exc

    def _handle_response(self, response: httpx.Response, request_id: Any) -> None:
        session = response.headers.get("mcp-session-id")
        if session:
            self.session_id = session
        if response.status_code in (202, 204):
            return
        if response.status_code == 404 and self.session_id:
            raise MCPConnectionError("The server ended the session (HTTP 404)")
        if response.status_code == 405:
            raise MCPConnectionError(f"{self.url} does not accept POST. It may be an SSE server: try --transport sse")
        raise_for_status(response, self.url)
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            self._read_event_stream(response, request_id)
        else:
            self._read_json_body(response)

    def _read_json_body(self, response: httpx.Response) -> None:
        data = bytearray()
        for chunk in response.iter_bytes():
            data.extend(chunk)
            if len(data) > self.max_bytes:
                self.note("oversized-message", f"HTTP body larger than {self.max_bytes} bytes")
                raise MCPConnectionError("Server answer is too large")
        if not data.strip():
            return
        try:
            self._push(json.loads(data))
        except json.JSONDecodeError:
            self.note("non-json-output", data[:200].decode("utf-8", errors="replace"))

    def _read_event_stream(self, response: httpx.Response, request_id: Any) -> None:
        size = 0
        for event in parse_sse_lines(response.iter_lines()):
            size += len(event.data)
            if size > self.max_bytes:
                self.note("oversized-message", "event stream larger than limit")
                raise MCPConnectionError("Server answer is too large")
            try:
                value = json.loads(event.data)
            except json.JSONDecodeError:
                self.note("non-json-output", event.data)
                continue
            self._push(value)
            if isinstance(value, dict) and "id" in value and value.get("id") == request_id and "method" not in value:
                return  # we have our answer

    def _push(self, value: Any) -> None:
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                self._inbox.put(item)
            else:
                self.note("invalid-message", "expected a JSON object")

    def receive(self, timeout: float) -> Message | None:
        try:
            return self._inbox.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    def close(self) -> None:
        if self.session_id:
            try:
                self._client.delete(self.url, headers=self._headers(), timeout=5.0)
            except httpx.HTTPError:
                pass
            self.session_id = None
        self._client.close()
