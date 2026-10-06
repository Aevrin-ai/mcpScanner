# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""A tiny parser for server-sent events (SSE)."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass


@dataclass
class SSEEvent:
    event: str = "message"
    data: str = ""
    id: str | None = None


def parse_sse_lines(lines: Iterable[str]) -> Iterator[SSEEvent]:
    """Turn raw SSE lines into events. An empty line ends one event."""
    event, event_id = "message", None
    data_lines: list[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if data_lines:
                yield SSEEvent(event=event, data="\n".join(data_lines), id=event_id)
            event, data_lines, event_id = "message", [], None
            continue
        if line.startswith(":"):
            continue  # a comment, often used to keep the connection open
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field == "event":
            event = value or "message"
        elif field == "data":
            data_lines.append(value)
        elif field == "id":
            event_id = value
    if data_lines:
        yield SSEEvent(event=event, data="\n".join(data_lines), id=event_id)
