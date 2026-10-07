# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Find every piece of text an AI agent will read from a server.

Attackers do not only hide instructions in the tool description. They also use
parameter descriptions, enum values, default values, prompt templates, resource
text, and the server "instructions" field. We collect all of them as "surfaces".
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from mcp_scanner.models.finding import TargetKind
from mcp_scanner.models.mcp import ServerInventory, ToolInfo
from mcp_scanner.models.observations import DynamicObservations

MAX_SCHEMA_DEPTH = 6
_SCHEMA_CHILD_KEYS = ("items", "additionalProperties", "not")
_SCHEMA_LIST_KEYS = ("anyOf", "oneOf", "allOf", "prefixItems")


@dataclass(frozen=True)
class TextSurface:
    """One piece of text, plus where it came from."""

    kind: str  # for example "tool-description", "param-description", "tool-output"
    target_kind: TargetKind
    target_name: str
    location: str  # human readable, for example "tool add > param sidenote > description"
    text: str
    dynamic: bool = False

    @property
    def is_metadata(self) -> bool:
        return not self.dynamic


def tool_surfaces(tool: ToolInfo) -> Iterator[TextSurface]:
    base = f"tool {tool.name}"

    def make(kind: str, where: str, text: str) -> TextSurface:
        return TextSurface(kind, TargetKind.TOOL, tool.name, f"{base} > {where}", text)

    yield make("tool-name", "name", tool.name)
    if tool.title:
        yield make("tool-title", "title", tool.title)
    if tool.description:
        yield make("tool-description", "description", tool.description)
    for key, value in tool.annotations.items():
        if isinstance(value, str) and value:
            yield make("tool-annotation", f"annotation {key}", value)
    yield from _schema_surfaces(tool.input_schema, base, tool.name, "input", 0)


def _schema_surfaces(schema: Any, base: str, tool: str, path: str, depth: int) -> Iterator[TextSurface]:
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return

    def make(kind: str, where: str, text: str) -> TextSurface:
        return TextSurface(kind, TargetKind.TOOL, tool, f"{base} > {where}", text)

    for key in ("description", "title"):
        if isinstance(schema.get(key), str) and schema[key] and path != "input":
            yield make("param-description", f"{path} > {key}", schema[key])
    for key in ("default", "const", "examples", "enum"):
        for text in _strings_in(schema.get(key)):
            yield make("param-value", f"{path} > {key}", text)
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            yield make("param-name", f"param {name} > name", str(name))
            yield from _schema_surfaces(sub, base, tool, f"param {name}", depth + 1)
    for key in _SCHEMA_CHILD_KEYS:
        yield from _schema_surfaces(schema.get(key), base, tool, f"{path} > {key}", depth + 1)
    for key in _SCHEMA_LIST_KEYS:
        for i, sub in enumerate(schema.get(key) or []):
            yield from _schema_surfaces(sub, base, tool, f"{path} > {key}[{i}]", depth + 1)
    for key in ("$defs", "definitions"):
        defs = schema.get(key)
        if isinstance(defs, dict):
            for name, sub in defs.items():
                yield from _schema_surfaces(sub, base, tool, f"{key} {name}", depth + 1)


def _strings_in(value: Any) -> Iterator[str]:
    if isinstance(value, str) and value:
        yield value
    elif isinstance(value, list):
        for item in value[:200]:
            if isinstance(item, str) and item:
                yield item


def inventory_surfaces(inventory: ServerInventory) -> list[TextSurface]:
    """Every text surface the server listed (no tool calls needed)."""
    surfaces: list[TextSurface] = []
    if inventory.instructions:
        surfaces.append(
            TextSurface(
                "instructions", TargetKind.SERVER, "instructions", "server instructions", inventory.instructions
            )
        )
    for tool in inventory.tools:
        surfaces.extend(tool_surfaces(tool))
    for prompt in inventory.prompts:
        where = f"prompt {prompt.name}"
        if prompt.description:
            surfaces.append(
                TextSurface(
                    "prompt-description", TargetKind.PROMPT, prompt.name, f"{where} > description", prompt.description
                )
            )
        for arg in prompt.arguments:
            if arg.description:
                surfaces.append(
                    TextSurface(
                        "prompt-argument",
                        TargetKind.PROMPT,
                        prompt.name,
                        f"{where} > argument {arg.name}",
                        arg.description,
                    )
                )
        if prompt.rendered_text:
            surfaces.append(
                TextSurface(
                    "prompt-text",
                    TargetKind.PROMPT,
                    prompt.name,
                    f"{where} > rendered text",
                    prompt.rendered_text,
                    dynamic=True,
                )
            )
    for resource in inventory.resources:
        label = resource.name or resource.uri
        where = f"resource {label}"
        if resource.description:
            surfaces.append(
                TextSurface(
                    "resource-description", TargetKind.RESOURCE, label, f"{where} > description", resource.description
                )
            )
        if resource.text:
            surfaces.append(
                TextSurface(
                    "resource-text", TargetKind.RESOURCE, label, f"{where} > content", resource.text, dynamic=True
                )
            )
    for template in inventory.resource_templates:
        if template.description:
            label = template.name or template.uri_template
            surfaces.append(
                TextSurface(
                    "resource-description",
                    TargetKind.RESOURCE,
                    label,
                    f"resource template {label} > description",
                    template.description,
                )
            )
    return surfaces


def output_surfaces(observations: DynamicObservations) -> list[TextSurface]:
    """Text that came back from our safe tool calls."""
    return [
        TextSurface(
            "tool-output", TargetKind.TOOL, call.tool, f"tool {call.tool} > call result", call.output_text, dynamic=True
        )
        for call in observations.tool_calls
        if call.output_text
    ]


# ---- text helpers ----------------------------------------------------------

ZERO_WIDTH = {"​", "‌", "‍", "‎", "‏", "⁠", "⁡", "⁢", "⁣", "⁤", "﻿"}
BIDI_CONTROLS = {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}


def is_tag_char(ch: str) -> bool:
    """Unicode "tag" characters are invisible, but each one maps to an ASCII letter.
    Attackers use them to hide whole sentences ("ASCII smuggling")."""
    return 0xE0000 <= ord(ch) <= 0xE007F


def decode_tag_chars(text: str) -> str:
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if is_tag_char(ch) and 0x20 <= ord(ch) - 0xE0000 < 0x7F)


def normalize(text: str) -> str:
    """Make text easier to match: fold lookalike forms and drop invisible characters."""
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if ch not in ZERO_WIDTH and ch not in BIDI_CONTROLS and not is_tag_char(ch))


def excerpt(text: str, start: int, end: int, pad: int = 60) -> str:
    """A short piece of text around a match, on one line."""
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    piece = text[left:right].replace("\n", " ").replace("\r", " ")
    return ("..." if left else "") + piece.strip() + ("..." if right < len(text) else "")
