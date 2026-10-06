# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Dynamic analysis: watch the live server.

What it does, in order:
  1. lists tools again and compares (a change in the same session is a rug pull)
  2. reads prompts and text resources (their content goes into the agent's context)
  3. calls tools that are safe to call, with harmless arguments
  4. lists tools a last time, because some servers change tools after the first call
  5. looks for our planted canary secrets in everything the server returned

Every step is optional and bounded by a call budget and the scan deadline.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from mcp_scanner.analyzers.capabilities import analyze_inventory
from mcp_scanner.analyzers.dynamic.pins import compare, tool_hashes
from mcp_scanner.analyzers.dynamic.probes import build_arguments, call_policy
from mcp_scanner.config.settings import Settings
from mcp_scanner.core.errors import MCPError, MCPTimeoutError
from mcp_scanner.mcp.connection import Connection
from mcp_scanner.models.mcp import ServerInventory, ToolInfo
from mcp_scanner.models.observations import DynamicObservations, ToolCallRecord
from mcp_scanner.models.result import ScanError
from mcp_scanner.utils.timing import Deadline

log = logging.getLogger(__name__)
MAX_PROMPTS = 20
MAX_RESOURCES = 20
MAX_TIMEOUTS_IN_A_ROW = 2
TEXT_MIME_PREFIXES = ("text/", "application/json", "application/xml", "application/yaml", "application/x-yaml")


def content_text(result: dict[str, Any], limit: int) -> str:
    """Join every piece of text in a tool, prompt, or resource answer."""
    parts: list[str] = []
    for item in result.get("content") or []:
        parts.extend(_item_text(item))
    for message in result.get("messages") or []:
        if isinstance(message, dict):
            content = message.get("content")
            for item in content if isinstance(content, list) else [content]:
                parts.extend(_item_text(item))
    for item in result.get("contents") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(item["text"])
    structured = result.get("structuredContent")
    if structured is not None:
        parts.append(json.dumps(structured, ensure_ascii=False)[:limit])
    return "\n".join(parts)[:limit]


def _item_text(item: Any) -> list[str]:
    if not isinstance(item, dict):
        return [item] if isinstance(item, str) else []
    texts = []
    if isinstance(item.get("text"), str):
        texts.append(item["text"])
    resource = item.get("resource")
    if isinstance(resource, dict) and isinstance(resource.get("text"), str):
        texts.append(resource["text"])
    return texts


class DynamicAnalyzer:
    def __init__(self, settings: Settings, deadline: Deadline, unsafe_tools: dict[str, str] | None = None) -> None:
        self.settings = settings
        # Tools that source code analysis showed to be dangerous: {tool: reason}.
        self.unsafe_tools = unsafe_tools or {}
        self.dynamic = settings.dynamic
        self.deadline = deadline
        self.errors: list[ScanError] = []
        self._relisted: list[ToolInfo] = []

    def run(self, connection: Connection, inventory: ServerInventory) -> DynamicObservations:
        obs = DynamicObservations(enabled=True, canary_values=connection.canary.secret_values())
        baseline = tool_hashes(inventory.tools)
        self._relist(connection, baseline, obs)
        connection.set_phase("probing")
        if self.dynamic.read_prompts:
            self._read_prompts(connection, inventory, obs)
        if self.dynamic.read_resources:
            self._read_resources(connection, inventory, obs)
        if self.dynamic.call_tools:
            self._call_tools(connection, inventory, obs)
        self._relist(connection, baseline, obs)
        for location in canary_locations(obs.canary_values, inventory, obs.tool_calls, self._relisted):
            if location not in obs.canary_hits:
                obs.canary_hits.append(location)
        return obs

    # ---- 1 and 4: list again --------------------------------------------------

    def _relist(self, connection: Connection, baseline: dict[str, str], obs: DynamicObservations) -> None:
        if self.deadline.expired:
            return
        try:
            tools = connection.list_tools()
        except MCPError as exc:
            self.errors.append(ScanError(stage="dynamic", message=f"Could not list tools again: {exc}"))
            return
        known = {(c.tool, c.after_hash) for c in obs.tool_changes}
        by_name = {t.name: t for t in tools}
        for change in compare(baseline, tool_hashes(tools), "during-session"):
            if (change.tool, change.after_hash) not in known:
                obs.tool_changes.append(change)
                if change.tool in by_name:
                    obs.changed_tool_definitions.append(by_name[change.tool].raw or by_name[change.tool].model_dump())
        self._relisted = tools

    # ---- 2: prompts and resources ---------------------------------------------

    def _read_prompts(self, connection: Connection, inventory: ServerInventory, obs: DynamicObservations) -> None:
        for prompt in inventory.prompts[:MAX_PROMPTS]:
            if self.deadline.expired:
                return
            args = {a.name: "example" for a in prompt.arguments if a.required}
            try:
                result = connection.session.get_prompt(prompt.name, args, timeout=self._timeout())
            except MCPError as exc:
                log.debug("prompts/get %s failed: %s", prompt.name, exc)
                continue
            prompt.rendered_text = content_text(result, self.dynamic.max_content_chars) or None

    def _read_resources(self, connection: Connection, inventory: ServerInventory, obs: DynamicObservations) -> None:
        for resource in inventory.resources[:MAX_RESOURCES]:
            if self.deadline.expired:
                return
            if resource.mime_type and not resource.mime_type.startswith(TEXT_MIME_PREFIXES):
                continue
            try:
                result = connection.session.read_resource(resource.uri, timeout=self._timeout())
            except MCPError as exc:
                log.debug("resources/read %s failed: %s", resource.uri, exc)
                continue
            resource.text = content_text(result, self.dynamic.max_content_chars) or None

    # ---- 3: safe tool calls ---------------------------------------------------

    def _call_tools(self, connection: Connection, inventory: ServerInventory, obs: DynamicObservations) -> None:
        caps = analyze_inventory(inventory.tools)
        budget = self.dynamic.max_tool_calls
        timeouts_in_a_row = 0
        for tool in inventory.tools:
            reason = call_policy(tool, caps.get(tool.name), self.dynamic.call_dangerous_tools)
            if reason is None and not self.dynamic.call_dangerous_tools and tool.name in self.unsafe_tools:
                reason = f"source code {self.unsafe_tools[tool.name]}"
            if reason:
                obs.skipped_tools[tool.name] = reason
                continue
            if budget <= 0 or self.deadline.expired:
                obs.skipped_tools[tool.name] = "call budget or time limit reached"
                continue
            if timeouts_in_a_row >= MAX_TIMEOUTS_IN_A_ROW:
                # The server waits for something that is not in the sandbox (a desktop app, a
                # service). More calls would only wait too, so stop here and save the time.
                obs.skipped_tools[tool.name] = "earlier calls timed out, the server seems to wait for an outside app"
                continue
            budget -= 1
            record = self._call(connection, tool)
            timeouts_in_a_row = timeouts_in_a_row + 1 if record.timed_out else 0
            obs.tool_calls.append(record)

    def _call(self, connection: Connection, tool: ToolInfo) -> ToolCallRecord:
        arguments = build_arguments(tool, connection.canary)
        record = ToolCallRecord(tool=tool.name, arguments=arguments)
        start = time.perf_counter()
        try:
            result = connection.session.call_tool(
                tool.name, arguments, timeout=self._timeout(self.settings.timeouts.tool_call)
            )
            record.ok = True
            record.is_error = bool(result.get("isError"))
            record.output_text = content_text(result, self.dynamic.max_content_chars)
        except MCPTimeoutError as exc:
            record.error = str(exc)[:300]
            record.timed_out = True
        except MCPError as exc:
            record.error = str(exc)[:300]
        record.duration_ms = round((time.perf_counter() - start) * 1000, 1)
        return record

    def _timeout(self, base: float | None = None) -> float:
        return self.deadline.cap(base or self.settings.timeouts.request)


def canary_locations(
    values: list[str],
    inventory: ServerInventory,
    calls: list[ToolCallRecord] | None = None,
    extra_tools: list[ToolInfo] | None = None,
) -> list[str]:
    """Every place where a planted canary secret came back from the server.

    This also runs without dynamic analysis: a server can put a stolen value
    straight into its tool descriptions or its instructions.
    """
    if not values:
        return []
    calls = calls or []
    places: list[tuple[str, str]] = [("server instructions", inventory.instructions or "")]
    places += [(f"tool {c.tool} > call result", c.output_text) for c in calls]
    places += [(f"tool {c.tool} > call error", c.error or "") for c in calls]
    places += [(f"prompt {p.name} > rendered text", p.rendered_text or "") for p in inventory.prompts]
    places += [(f"prompt {p.name} > description", p.description) for p in inventory.prompts]
    places += [(f"resource {r.name or r.uri} > content", r.text or "") for r in inventory.resources]
    for tool in [*inventory.tools, *(extra_tools or [])]:
        places.append((f"tool {tool.name} > definition", json.dumps(tool.raw or tool.model_dump(), ensure_ascii=False)))
    found: list[str] = []
    for location, text in places:
        if text and location not in found and any(value in text for value in values):
            found.append(location)
    return found
