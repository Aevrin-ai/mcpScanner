# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Load a server inventory from a JSON or YAML file, without running anything.

Accepted shapes:
    [ {tool}, {tool} ]
    {"tools": [...], "prompts": [...], "resources": [...], "instructions": "..."}
    {"result": {"tools": [...]}}        a saved tools/list answer
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_scanner.core.errors import TargetError
from mcp_scanner.models.mcp import PromptInfo, ResourceInfo, ServerInventory, ToolInfo
from mcp_scanner.utils import jsonc


def load_offline_inventory(path: str | Path) -> ServerInventory:
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
        doc: Any = yaml.safe_load(text) if file_path.suffix.lower() in (".yaml", ".yml") else jsonc.loads(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise TargetError(f"Could not read tools file {file_path}: {exc}") from exc
    if isinstance(doc, list):
        doc = {"tools": doc}
    if not isinstance(doc, dict):
        raise TargetError(f"{file_path} must hold a list of tools or an object with 'tools'")
    if isinstance(doc.get("result"), dict):
        doc = doc["result"]
    server = doc.get("serverInfo") if isinstance(doc.get("serverInfo"), dict) else {}
    return ServerInventory(
        server_name=server.get("name") or file_path.stem,
        server_version=server.get("version"),
        instructions=doc.get("instructions") if isinstance(doc.get("instructions"), str) else None,
        capabilities=doc.get("capabilities") if isinstance(doc.get("capabilities"), dict) else {},
        tools=[ToolInfo.from_wire(t) for t in doc.get("tools") or [] if isinstance(t, dict)],
        prompts=[PromptInfo.from_wire(p) for p in doc.get("prompts") or [] if isinstance(p, dict)],
        resources=[ResourceInfo.from_wire(r) for r in doc.get("resources") or [] if isinstance(r, dict)],
    )
