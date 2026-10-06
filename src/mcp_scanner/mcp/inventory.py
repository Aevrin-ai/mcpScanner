# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Collect everything a server lists: tools, prompts, resources, and instructions."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from mcp_scanner.core.errors import MCPError, MCPRemoteError
from mcp_scanner.mcp.session import MCPSession
from mcp_scanner.models.mcp import (
    PromptInfo,
    ResourceInfo,
    ResourceTemplateInfo,
    ServerInventory,
    ToolInfo,
)
from mcp_scanner.models.result import ScanError

log = logging.getLogger(__name__)


def is_missing_feature(exc: Exception) -> bool:
    """True when the server simply does not support a method. That is not a scan error."""
    if isinstance(exc, MCPRemoteError):
        if exc.is_method_not_found:
            return True
        text = exc.remote_message.lower()
        return any(word in text for word in ("not found", "not implemented", "unsupported", "not supported"))
    return False


def build_inventory_header(init: dict[str, Any]) -> ServerInventory:
    raw_info, raw_caps = init.get("serverInfo"), init.get("capabilities")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    caps: dict[str, Any] = raw_caps if isinstance(raw_caps, dict) else {}
    instructions = init.get("instructions")
    return ServerInventory(
        server_name=str(info.get("name")) if info.get("name") else None,
        server_version=str(info.get("version")) if info.get("version") else None,
        protocol_version=str(init.get("protocolVersion")) if init.get("protocolVersion") else None,
        capabilities=caps,
        instructions=instructions if isinstance(instructions, str) else None,
    )


def collect_inventory(session: MCPSession) -> tuple[ServerInventory, list[ScanError]]:
    """Read every list the server offers. Missing features are skipped quietly."""
    inventory = build_inventory_header(session.initialize_result)
    errors: list[ScanError] = []
    caps = inventory.capabilities

    def gather(name: str, method: str, key: str, build: Callable[[dict[str, Any]], Any], wanted: bool) -> list[Any]:
        if not wanted:
            return []
        try:
            return [build(item) for item in session.list_all(method, key)]
        except MCPError as exc:
            if not is_missing_feature(exc):
                errors.append(ScanError(stage="inventory", message=f"Could not list {name}: {exc}"))
            return []

    # Some servers forget to declare "tools", so we always ask for tools.
    inventory.tools = gather("tools", "tools/list", "tools", ToolInfo.from_wire, True)
    inventory.prompts = gather("prompts", "prompts/list", "prompts", PromptInfo.from_wire, "prompts" in caps)
    inventory.resources = gather(
        "resources", "resources/list", "resources", ResourceInfo.from_wire, "resources" in caps
    )
    inventory.resource_templates = gather(
        "resource templates",
        "resources/templates/list",
        "resourceTemplates",
        ResourceTemplateInfo.from_wire,
        "resources" in caps,
    )
    return inventory, errors
