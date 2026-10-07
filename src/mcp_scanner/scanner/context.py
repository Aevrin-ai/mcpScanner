# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""ScanContext: everything a rule may read about one server.

Rules only read from the context. They never start servers or call the network.
Expensive facts (text surfaces, capabilities) are computed once, on first use.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import cached_property

from mcp_scanner.analyzers.capabilities import ToolCapabilities, analyze_inventory
from mcp_scanner.analyzers.dependencies import DependencyFacts
from mcp_scanner.analyzers.source.facts import SourceFacts
from mcp_scanner.analyzers.text import (
    TextSurface,
    inventory_surfaces,
    output_surfaces,
    tool_surfaces,
)
from mcp_scanner.config.settings import Settings
from mcp_scanner.models.mcp import ServerInventory, ToolInfo
from mcp_scanner.models.observations import DynamicObservations
from mcp_scanner.models.server import ServerSpec


@dataclass
class ScanContext:
    spec: ServerSpec
    inventory: ServerInventory
    settings: Settings = field(default_factory=Settings)
    observations: DynamicObservations = field(default_factory=DynamicObservations)
    source: SourceFacts | None = None
    dependencies: DependencyFacts | None = None
    # Tool names from the other servers in the same scan: {tool name: server name}.
    peer_tools: dict[str, str] = field(default_factory=dict)
    # True when we really talked to the server (not an offline tools file).
    connected: bool = False

    @cached_property
    def surfaces(self) -> list[TextSurface]:
        """All text the agent will read: metadata first, then runtime content."""
        changed = []
        for raw in self.observations.changed_tool_definitions:
            tool = ToolInfo.from_wire(raw)
            label = f"tool {tool.name}"
            for surface in tool_surfaces(tool):
                # The location says this text only appeared after the tool changed.
                changed.append(replace(surface, location=surface.location.replace(label, f"{label} (after change)", 1)))
        return inventory_surfaces(self.inventory) + changed + output_surfaces(self.observations)

    @property
    def metadata_surfaces(self) -> list[TextSurface]:
        return [s for s in self.surfaces if not s.dynamic]

    @property
    def dynamic_surfaces(self) -> list[TextSurface]:
        return [s for s in self.surfaces if s.dynamic]

    @cached_property
    def capabilities(self) -> dict[str, ToolCapabilities]:
        return analyze_inventory(self.inventory.tools)

    @property
    def tools(self) -> list[ToolInfo]:
        return self.inventory.tools

    @cached_property
    def tool_names(self) -> set[str]:
        return {t.name for t in self.inventory.tools}

    @property
    def dynamic_enabled(self) -> bool:
        return self.observations.enabled
