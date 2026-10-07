# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Tool names and descriptions from Go and Rust servers, read with patterns.

Go and Rust code is not analyzed for dangerous calls. These patterns only list the
tools, so the text rules (hidden instructions, risky descriptions) can still run:

  Go, mcp-go:           mcp.NewTool("name", mcp.WithDescription("..."))
  Go, the official SDK: &mcp.Tool{Name: "name", Description: "..."}
  Rust, rmcp:           #[tool(description = "...")] async fn name(...)
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp_scanner.analyzers.source.walker import SKIP_DIRS
from mcp_scanner.models.mcp import ToolInfo

GO_EXT = ".go"
RUST_EXT = ".rs"
MAX_FILES = 2000
MAX_FILE_BYTES = 1_000_000
# Go strings: "double quoted" with escapes, or `raw backticks`.
_GO_STRING = r'(?:"((?:[^"\\\n]|\\.)*)"|`([^`]*)`)'
# A description is often wrapped in a translation call: t("TOOL_X_DESCRIPTION", "the text").
# The text is the last string in that call.
_GO_TEXT = r"(?:[\w.]+\(\s*(?:\"(?:[^\"\\\n]|\\.)*\"\s*,\s*)?)?" + _GO_STRING
_GO_NEW_TOOL = re.compile(r"mcp\.NewTool\(\s*" + _GO_STRING)
_GO_WITH_DESCRIPTION = re.compile(r"mcp\.WithDescription\(\s*" + _GO_TEXT)
_GO_TOOL_STRUCT = re.compile(r"\bmcp\.Tool\s*\{")
_GO_FIELD_NAME = re.compile(r"\bName:\s*" + _GO_STRING)
_GO_FIELD_DESCRIPTION = re.compile(r"\bDescription:\s*" + _GO_TEXT)
_RUST_TOOL = re.compile(
    r"#\[tool\((?P<attrs>[^\]]*)\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<fn>\w+)",
    re.DOTALL,
)
_RUST_ATTR = re.compile(r'\b(name|description)\s*=\s*"((?:[^"\\]|\\.)*)"')


def _go_value(match: re.Match[str], first: int = 1) -> str:
    raw = match.group(first)
    if raw is not None:
        return raw.replace('\\"', '"').replace("\\n", "\n")
    return match.group(first + 1) or ""


def _tool(name: str, description: str) -> ToolInfo:
    schema = {"type": "object", "properties": {}}
    return ToolInfo(
        name=name,
        description=description,
        input_schema=schema,
        raw={"name": name, "description": description, "inputSchema": schema},
    )


def _go_block(text: str, start: int, limit: int = 20_000) -> str:
    """The text between the brace at `start` and its closing brace. Braces inside strings do not count."""
    depth, quote, position = 0, "", start
    end = min(len(text), start + limit)
    while position < end:
        char = text[position]
        if quote:
            if char == "\\" and quote == '"':
                position += 1
            elif char == quote:
                quote = ""
        elif char in ('"', "`"):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : position]
        position += 1
    return text[start + 1 : end]


def extract_go(text: str) -> list[ToolInfo]:
    tools: list[ToolInfo] = []
    for match in _GO_NEW_TOOL.finditer(text):
        # The options follow the name inside the same call. Look a short way ahead for the description.
        window = text[match.end() : match.end() + 2000]
        description = _GO_WITH_DESCRIPTION.search(window)
        tools.append(_tool(_go_value(match), _go_value(description) if description else ""))
    for match in _GO_TOOL_STRUCT.finditer(text):
        body = _go_block(text, match.end() - 1)
        name = _GO_FIELD_NAME.search(body)
        if name:
            description = _GO_FIELD_DESCRIPTION.search(body)
            tools.append(_tool(_go_value(name), _go_value(description) if description else ""))
    return tools


def extract_rust(text: str) -> list[ToolInfo]:
    tools: list[ToolInfo] = []
    for match in _RUST_TOOL.finditer(text):
        attrs = dict(_RUST_ATTR.findall(match.group("attrs")))
        description = attrs.get("description", "").replace('\\"', '"').replace("\\n", "\n")
        tools.append(_tool(attrs.get("name") or match.group("fn"), description))
    return tools


def extract_other_languages(root: Path) -> list[ToolInfo]:
    """Tools from every Go and Rust file under root. One entry per tool name."""
    found: dict[str, ToolInfo] = {}
    seen = 0
    for path in sorted(root.rglob("*")) if root.is_dir() else [root]:
        parts = path.relative_to(root).parts if root.is_dir() else ()
        if (
            path.suffix not in (GO_EXT, RUST_EXT)
            or path.name.endswith("_test.go")
            or any(part in SKIP_DIRS or part in ("vendor", "target", "testdata", "tests") for part in parts)
        ):
            continue
        seen += 1
        if seen > MAX_FILES:
            break
        try:
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for tool in extract_go(text) if path.suffix == GO_EXT else extract_rust(text):
            found.setdefault(tool.name, tool)
    return list(found.values())
