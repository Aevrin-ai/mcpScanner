# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The interface every transport follows.

A transport only moves JSON messages. It does not know what they mean.
The session on top of it handles requests, answers, and timeouts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mcp_scanner.models.observations import ProtocolEvent

Message = dict[str, Any]


class Transport(ABC):
    def __init__(self) -> None:
        # Strange things we saw on the wire, for example lines that are not JSON.
        self.events: list[ProtocolEvent] = []

    @abstractmethod
    def send(self, message: Message) -> None:
        """Send one JSON-RPC message."""

    @abstractmethod
    def receive(self, timeout: float) -> Message | None:
        """Return the next message, or None if nothing came before the timeout."""

    @abstractmethod
    def close(self) -> None:
        """Release everything. Must be safe to call more than once."""

    def note(self, kind: str, detail: str, method: str | None = None) -> None:
        # Keep the list short. A hostile server could send millions of bad lines.
        if len(self.events) < 200:
            self.events.append(ProtocolEvent(kind=kind, detail=detail[:300], method=method))

    def set_protocol_version(self, version: str) -> None:  # noqa: B027 - optional hook
        """HTTP transports send this in a header after initialize."""
