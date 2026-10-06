# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Quality problems that make a server harder to use safely."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from mcp_scanner.analyzers.capabilities import Capability
from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import Rule
from mcp_scanner.scanner.context import ScanContext

LONG_DESCRIPTION = 3000


class MissingDescription(Rule):
    id = "MCP-QUALITY-001"
    title = "Tool has no description"
    category = Category.QUALITY
    severity = Severity.INFO
    description = "A tool has an empty description."
    why_it_matters = "People and models cannot tell what the tool does, so they cannot judge if a call is safe."
    attack_scenario = "Not an attack by itself. It hides what a tool is for."
    recommendation = "Add a short, plain description of what the tool does and what it changes."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            if not tool.description.strip():
                yield self.finding(
                    TargetKind.TOOL,
                    tool.name,
                    f"Tool '{tool.name}' has no description.",
                    [Evidence.make("schema", f"tool {tool.name} > description", "(empty)")],
                    confidence=Confidence.HIGH,
                )


class WeakSchema(Rule):
    id = "MCP-QUALITY-002"
    title = "Tool input schema is loose"
    category = Category.QUALITY
    severity = Severity.INFO
    description = "A tool's input schema is missing, is not an object, or has parameters with no type."
    why_it_matters = "Loose schemas let any value through. Clear types and limits block many bad inputs early."
    attack_scenario = "Not an attack by itself. It makes injection easier."
    recommendation = "Give every parameter a type, and use enums or patterns where values are limited."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            schema = tool.input_schema
            where = f"tool {tool.name} > input schema"
            if not schema or schema.get("type") not in ("object", None):
                yield self.finding(
                    TargetKind.TOOL,
                    tool.name,
                    f"Tool '{tool.name}' has no object input schema.",
                    [Evidence.make("schema", where, str(schema)[:200] or "(missing)")],
                    confidence=Confidence.HIGH,
                )
                continue
            untyped = [
                n
                for n, p in tool.properties().items()
                if not any(k in p for k in ("type", "enum", "const", "anyOf", "oneOf", "$ref", "allOf"))
            ]
            if untyped:
                yield self.finding(
                    TargetKind.TOOL,
                    tool.name,
                    f"Parameters without a type: {', '.join(untyped[:8])}.",
                    [Evidence.make("schema", where, ", ".join(untyped[:8]))],
                    confidence=Confidence.HIGH,
                )


class LongDescription(Rule):
    id = "MCP-QUALITY-003"
    title = "Tool description is very long"
    category = Category.QUALITY
    severity = Severity.LOW
    description = f"A tool description is longer than {LONG_DESCRIPTION} characters."
    why_it_matters = (
        "Long descriptions are where hidden instructions are easiest to miss, and they waste the agent's context."
    )
    attack_scenario = (
        "A normal looking first paragraph is followed by pages of text with an order buried in the middle."
    )
    recommendation = "Keep descriptions short. Move documentation to a README or a resource."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            if len(tool.description) > LONG_DESCRIPTION:
                yield self.finding(
                    TargetKind.TOOL,
                    tool.name,
                    f"Tool '{tool.name}' has a {len(tool.description)} character description.",
                    [Evidence.make("schema", f"tool {tool.name} > description", tool.description[:200])],
                    confidence=Confidence.HIGH,
                )


class DuplicateTools(Rule):
    id = "MCP-QUALITY-004"
    title = "Server lists the same tool name twice"
    category = Category.TOOL_SHADOWING
    severity = Severity.MEDIUM
    description = "Two tools on one server have the same name."
    why_it_matters = (
        "Clients pick one of them, and which one is not defined. A second copy can hide a different definition."
    )
    attack_scenario = "The server lists 'search' twice. The client shows the first, but calls go to the second."
    recommendation = "Give every tool a unique name."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for name, count in Counter(t.name for t in ctx.tools).items():
            if count > 1:
                yield self.finding(
                    TargetKind.TOOL,
                    name,
                    f"The name '{name}' is used by {count} tools.",
                    [Evidence.make("schema", f"tool {name} > name", name, f"{count} copies")],
                    confidence=Confidence.HIGH,
                )


class MissingAnnotations(Rule):
    id = "MCP-QUALITY-005"
    title = "Risky tool has no safety annotations"
    category = Category.QUALITY
    severity = Severity.INFO
    description = "A tool that runs commands or changes files does not set readOnlyHint or destructiveHint."
    why_it_matters = "Clients use these hints to decide when to ask the user. Without them, the client must guess."
    attack_scenario = "Not an attack by itself. It removes a signal clients use for approval prompts."
    recommendation = "Set destructiveHint and readOnlyHint on every tool."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None or not (caps.strong(Capability.EXEC) or caps.strong(Capability.FS_WRITE)):
                continue
            if "destructiveHint" in tool.annotations or "readOnlyHint" in tool.annotations:
                continue
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' has no readOnlyHint or destructiveHint.",
                [Evidence.make("schema", f"tool {tool.name} > annotations", str(tool.annotations)[:200] or "(none)")],
                confidence=Confidence.HIGH,
            )
