# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Facts gathered while a server was running (dynamic analysis)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ProcessEvent(BaseModel):
    pid: int
    name: str
    cmdline: str = ""
    # When we first saw it: "startup", "listing", or "probing".
    phase: str = "startup"


class NetworkEvent(BaseModel):
    pid: int
    remote_address: str
    status: str = ""
    phase: str = "startup"


class SandboxObservations(BaseModel):
    """What the sandbox saw the server process do."""

    sandbox_mode: str = "none"
    child_processes: list[ProcessEvent] = Field(default_factory=list)
    network_connections: list[NetworkEvent] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    peak_memory_mb: float = 0.0
    killed_reason: str | None = None
    exit_code: int | None = None
    stderr_tail: str = ""
    limits_note: str = ""


class ProtocolEvent(BaseModel):
    """Something odd the server did on the protocol level."""

    kind: str  # for example "server-request", "invalid-json", "oversized-message"
    detail: str
    method: str | None = None


class ToolCallRecord(BaseModel):
    """One safe test call that dynamic analysis made."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool = False
    is_error: bool = False
    output_text: str = ""
    error: str | None = None
    duration_ms: float = 0.0
    timed_out: bool = False


class ToolChange(BaseModel):
    """A tool that looked different the second time we asked."""

    tool: str
    change: str  # "added", "removed", "changed"
    before_hash: str | None = None
    after_hash: str | None = None
    when: str = "during-session"  # or "since-last-scan"


class DynamicObservations(BaseModel):
    enabled: bool = False
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    skipped_tools: dict[str, str] = Field(default_factory=dict)
    tool_changes: list[ToolChange] = Field(default_factory=list)
    # Tool definitions that were added or changed during the session, as the server sent them.
    changed_tool_definitions: list[dict[str, Any]] = Field(default_factory=list)
    protocol_events: list[ProtocolEvent] = Field(default_factory=list)
    canary_values: list[str] = Field(default_factory=list, exclude=True)
    canary_hits: list[str] = Field(default_factory=list)
    sandbox: SandboxObservations = Field(default_factory=SandboxObservations)
