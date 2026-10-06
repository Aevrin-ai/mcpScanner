# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The older HTTP + SSE transport.

1. We open a long GET request that streams events.
2. The first event ("endpoint") tells us where to POST our messages.
3. Answers arrive as "message" events on the GET stream.

Safety: the endpoint must be on the same host as the SSE URL. Otherwise a hostile
server could make the scanner send requests to any other machine.
"""

from __future__ import annotations

import json
import queue
import threading
from urllib.parse import urljoin, urlparse

import httpx

from mcp_scanner.core.errors import MCPConnectionError, MCPProtocolError, MCPTimeoutError
from mcp_scanner.mcp.sse import parse_sse_lines
from mcp_scanner.mcp.transports.base import Message, Transport
from mcp_scanner.mcp.transports.http import make_client, raise_for_status

_CLOSED = object()


def same_origin(first: str, second: str) -> bool:
    a, b = urlparse(first), urlparse(second)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


class SseTransport(Transport):
    def __init__(self, url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> None:
        super().__init__()
        self.url = url
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.endpoint: str | None = None
        self._client = make_client(headers, timeout)
        self._inbox: queue.Queue[object] = queue.Queue()
        self._endpoint_ready = threading.Event()
        self._error: Exception | None = None
        self._response: httpx.Response | None = None
        self._closing = False
        self._thread = threading.Thread(target=self._listen, name="sse-listener", daemon=True)
        self._thread.start()

    def _listen(self) -> None:
        try:
            # The GET stream stays open for the whole session, so no read timeout here.
            stream_timeout = httpx.Timeout(self.timeout, read=None)
            headers = {"Accept": "text/event-stream"}
            with self._client.stream("GET", self.url, headers=headers, timeout=stream_timeout) as response:
                self._response = response
                raise_for_status(response, self.url)
                self._consume(response)
        except Exception as exc:
            if not self._closing:
                self._error = exc
        finally:
            self._endpoint_ready.set()
            self._inbox.put(_CLOSED)

    def _consume(self, response: httpx.Response) -> None:
        size = 0
        for event in parse_sse_lines(response.iter_lines()):
            size += len(event.data)
            if size > self.max_bytes * 4:
                self.note("oversized-message", "SSE stream sent too much data")
                raise MCPConnectionError("SSE stream sent too much data")
            if event.event == "endpoint":
                self._set_endpoint(event.data.strip())
            elif event.event == "message":
                self._push(event.data)

    def _set_endpoint(self, value: str) -> None:
        endpoint = urljoin(self.url, value)
        if not same_origin(self.url, endpoint):
            self.note("cross-origin-endpoint", f"server asked us to post to {endpoint}")
            raise MCPProtocolError("The server's SSE endpoint points to another host. Refusing to use it.")
        self.endpoint = endpoint
        self._endpoint_ready.set()

    def _push(self, data: str) -> None:
        try:
            value = json.loads(data)
        except json.JSONDecodeError:
            self.note("non-json-output", data)
            return
        if isinstance(value, dict):
            self._inbox.put(value)
        else:
            self.note("invalid-message", "expected a JSON object")

    def send(self, message: Message) -> None:
        if not self._endpoint_ready.wait(self.timeout):
            raise MCPTimeoutError("The SSE server never sent its endpoint")
        if self.endpoint is None:
            raise MCPConnectionError(self._error_text())
        try:
            response = self._client.post(self.endpoint, json=message)
        except httpx.TimeoutException as exc:
            raise MCPTimeoutError("Timed out sending a message") from exc
        except httpx.HTTPError as exc:
            raise MCPConnectionError(f"Could not send to {self.endpoint}: {type(exc).__name__}") from exc
        raise_for_status(response, self.endpoint)

    def receive(self, timeout: float) -> Message | None:
        try:
            item = self._inbox.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None
        if item is _CLOSED:
            self._inbox.put(_CLOSED)
            raise MCPConnectionError(self._error_text())
        assert isinstance(item, dict)
        return item

    def _error_text(self) -> str:
        if isinstance(self._error, MCPConnectionError | MCPProtocolError):
            return str(self._error)
        if self._error is not None:
            return f"SSE connection failed: {type(self._error).__name__}"
        return "SSE connection closed"

    def close(self) -> None:
        self._closing = True
        try:
            if self._response is not None:
                self._response.close()
        except httpx.HTTPError:
            pass
        self._client.close()
        self._thread.join(timeout=2.0)
