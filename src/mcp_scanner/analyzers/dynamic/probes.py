# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Decide which tools are safe to call, and build harmless arguments for them.

We only want to see what a tool returns. We never want it to change anything.
So tools that run commands, write files, send messages, query databases, or call
the network are skipped unless the user explicitly allows dangerous calls.
Arguments are boring values plus a canary marker string.
"""

from __future__ import annotations

from typing import Any

from mcp_scanner.analyzers.capabilities import Capability, ToolCapabilities, split_words
from mcp_scanner.models.mcp import ToolInfo
from mcp_scanner.sandbox.canary import CanarySet

DANGEROUS = (
    Capability.EXEC,
    Capability.FS_WRITE,
    Capability.MESSAGING,
    Capability.DATABASE,
    Capability.NETWORK,
    Capability.BROWSER,
)
CHANGE_WORDS = {
    "delete",
    "remove",
    "drop",
    "destroy",
    "wipe",
    "purge",
    "truncate",
    "kill",
    "terminate",
    "rm",
    "send",
    "post",
    "publish",
    "create",
    "update",
    "write",
    "set",
    "push",
    "deploy",
    "install",
    "uninstall",
    "transfer",
    "pay",
    "buy",
    "order",
    "book",
    "merge",
    "close",
    "archive",
    "move",
    "rename",
    "upload",
    "execute",
    "run",
    "exec",
    "shutdown",
    "restart",
    "reset",
    "commit",
    "approve",
    "invite",
    "save",
    "store",
    "insert",
    "edit",
    "modify",
    "change",
    "replace",
    "patch",
    "submit",
    "cancel",
    "revoke",
    "grant",
    "apply",
    "sync",
    "import",
    "clear",
}
MATH_WORDS = {"number", "numbers", "num", "nums", "sum", "int", "ints", "integers", "values", "two", "math"}
MAX_DEPTH = 3


def call_policy(tool: ToolInfo, caps: ToolCapabilities | None, allow_dangerous: bool) -> str | None:
    """Return why the tool must not be called, or None when it is safe to call."""
    if allow_dangerous:
        return None
    if tool.annotations.get("destructiveHint") is True and tool.annotations.get("readOnlyHint") is not True:
        return "marked destructive"
    if caps is not None:
        risky = [c.value for c in DANGEROUS if caps.has(c)]
        if risky:
            return f"may have side effects ({', '.join(risky)})"
    if tool.annotations.get("readOnlyHint") is True:
        return None
    words = set(split_words(tool.name))
    changes = words & CHANGE_WORDS
    # "add" changes state ("add_observations"), unless it is math ("add_numbers").
    if "add" in words and not words & MATH_WORDS:
        changes = changes | {"add"}
    if changes:
        return f"name suggests it changes something ({', '.join(sorted(changes))})"
    return None


def build_arguments(tool: ToolInfo, canary: CanarySet) -> dict[str, Any]:
    """Values for the required parameters only."""
    schema = tool.input_schema
    return _object_value(schema, canary, 0) if isinstance(schema, dict) else {}


def _object_value(schema: dict[str, Any], canary: CanarySet, depth: int) -> dict[str, Any]:
    raw_props, raw_required = schema.get("properties"), schema.get("required")
    props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}
    required: list[Any] = raw_required if isinstance(raw_required, list) else []
    result: dict[str, Any] = {}
    for name in required:
        sub = props.get(name)
        result[str(name)] = value_for(str(name), sub if isinstance(sub, dict) else {}, canary, depth + 1)
    return result


def value_for(name: str, schema: dict[str, Any], canary: CanarySet, depth: int = 0) -> Any:
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    for key in ("anyOf", "oneOf"):
        options = schema.get(key)
        if isinstance(options, list):
            usable = [o for o in options if isinstance(o, dict) and o.get("type") != "null"]
            if usable:
                return value_for(name, usable[0], canary, depth)
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")
    minimum = schema.get("minimum")
    if kind == "integer":
        return int(minimum) if isinstance(minimum, int | float) else 1
    if kind == "number":
        return float(minimum) if isinstance(minimum, int | float) else 1.0
    if kind == "boolean":
        return False
    if kind == "array":
        raw_items = schema.get("items")
        items: dict[str, Any] = raw_items if isinstance(raw_items, dict) else {}
        count = int(schema.get("minItems", 0) or 0)
        return [value_for(name, items, canary, depth + 1) for _ in range(min(count, 3))] if depth < MAX_DEPTH else []
    if kind == "object":
        return _object_value(schema, canary, depth) if depth < MAX_DEPTH else {}
    return _string_value(name, schema, canary)


def _string_value(name: str, schema: dict[str, Any], canary: CanarySet) -> str:
    fmt = schema.get("format")
    words = set(split_words(name))
    if fmt in ("uri", "url") or words & {"url", "uri", "link", "endpoint"}:
        return "https://example.com/"
    if fmt == "email" or "email" in words:
        return "canary@example.com"
    if fmt == "date":
        return "2025-01-01"
    if fmt == "date-time":
        return "2025-01-01T00:00:00Z"
    if words & {"path", "file", "filename", "dir", "directory", "folder"}:
        return "aevrin-canary.txt"
    value = canary.input_value
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and max_len < len(value):
        value = value[:max_len]
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and min_len > len(value):
        value = value + "x" * (min_len - len(value))
    return value
