# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Tool pins: a hash of every tool definition, saved between scans.

If a tool's hash changes, the tool changed. That is how we spot a "rug pull":
a server that looked fine when you approved it, but changed later.

New servers and new tools are pinned automatically (trust on first use).
A changed pin is only overwritten when you ask (`--update-pins`), so a change
keeps showing up until someone has looked at it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_scanner.models.mcp import ToolInfo
from mcp_scanner.models.observations import ToolChange
from mcp_scanner.models.server import ServerSpec

log = logging.getLogger(__name__)
PIN_FORMAT = 1


def tool_hash(tool: ToolInfo) -> str:
    """A stable hash of everything the agent sees about a tool."""
    data = {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations,
    }
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def tool_hashes(tools: list[ToolInfo]) -> dict[str, str]:
    return {tool.name: tool_hash(tool) for tool in tools}


def compare(before: dict[str, str], after: dict[str, str], when: str) -> list[ToolChange]:
    changes: list[ToolChange] = []
    for name in sorted(set(before) | set(after)):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        change = "added" if old is None else "removed" if new is None else "changed"
        changes.append(ToolChange(tool=name, change=change, before_hash=old, after_hash=new, when=when))
    return changes


def server_key(spec: ServerSpec) -> str:
    return f"{spec.name}|{spec.transport.value}|{spec.display_target()}"


class PinStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.data: dict[str, Any] = {"format": PIN_FORMAT, "servers": {}}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Ignoring unreadable pin file %s: %s", self.path, exc)
            return
        if isinstance(doc, dict) and isinstance(doc.get("servers"), dict):
            self.data = doc

    def pins_for(self, spec: ServerSpec) -> dict[str, str] | None:
        entry = self.data["servers"].get(server_key(spec))
        return dict(entry.get("tools", {})) if isinstance(entry, dict) else None

    def check(self, spec: ServerSpec, tools: list[ToolInfo]) -> list[ToolChange]:
        """Changes since the last scan. Empty for a server we have never seen."""
        old = self.pins_for(spec)
        if old is None:
            return []
        return compare(old, tool_hashes(tools), "since-last-scan")

    def record(self, spec: ServerSpec, tools: list[ToolInfo], *, overwrite: bool) -> None:
        """Pin new tools. Changed tools are only re-pinned when `overwrite` is True."""
        current = tool_hashes(tools)
        old = self.pins_for(spec) or {}
        # Without overwrite, old pins win: changed tools keep their old hash and removed tools
        # stay pinned, so the change is reported again on the next scan until someone accepts it.
        merged = current if overwrite else {**current, **old}
        self.data["servers"][server_key(spec)] = {
            "tools": merged,
            "updated": datetime.now(UTC).isoformat(timespec="seconds"),
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temp file first, so a crash never leaves a half written pin file.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".pins-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            Path(tmp).unlink(missing_ok=True)
            raise
