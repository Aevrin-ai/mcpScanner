# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Read a server's tools, prompts, and resources straight from its source code.

This lets the scanner check a server it cannot (or should not) start, for
example a GitHub repository, or a server that needs a desktop app running.
Nothing is executed. Python is read with `ast`; JavaScript and TypeScript with
patterns, so JavaScript results are less complete (often no parameter types).

What is found:
  Python   @x.tool / @x.prompt / @x.resource decorators (FastMCP, MCPServer),
           low-level Tool(name=..., description=..., inputSchema={...}) objects,
           instructions=... given to FastMCP / MCPServer / Server
  JS / TS  registerTool("name", {description: ...}), server.tool("name", "desc", ...),
           {name: "...", description: "..."} tool objects in list handlers
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from mcp_scanner.analyzers.source.python_sinks import dotted_name
from mcp_scanner.analyzers.source.walker import JS_EXT, PYTHON_EXT
from mcp_scanner.models.mcp import PromptArgument, PromptInfo, ResourceInfo, ServerInventory, ToolInfo

SERVER_CLASSES = {"FastMCP", "MCPServer", "Server", "McpServer"}
SKIP_PARAMS = {"self", "cls", "ctx", "context"}
CONTEXT_TYPES = ("Context", "RequestContext", "ServerSession")
PY_TYPES = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "List": "array",
    "Dict": "object",
    "Sequence": "array",
    "Mapping": "object",
    "tuple": "array",
    "set": "array",
    "bytes": "string",
    "Any": None,
}


def extract_inventory(files: list[Path]) -> ServerInventory:
    """Merge what every file declares. The first definition of a name wins."""
    inventory = ServerInventory()
    seen_tools: set[str] = set()
    seen_prompts: set[str] = set()
    seen_resources: set[str] = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix in PYTHON_EXT:
            try:
                found = extract_python(text)
            except (SyntaxError, ValueError, RecursionError):
                continue
        elif suffix in JS_EXT:
            found = extract_javascript(text)
        else:
            continue
        if found.instructions and not inventory.instructions:
            inventory.instructions = found.instructions
            inventory.server_name = found.server_name
        for tool in found.tools:
            if tool.name not in seen_tools:
                seen_tools.add(tool.name)
                inventory.tools.append(tool)
        for prompt in found.prompts:
            if prompt.name not in seen_prompts:
                seen_prompts.add(prompt.name)
                inventory.prompts.append(prompt)
        for resource in found.resources:
            if resource.uri not in seen_resources:
                seen_resources.add(resource.uri)
                inventory.resources.append(resource)
    return inventory


# ---- Python --------------------------------------------------------------------


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # an f-string: keep the plain parts
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None


def extract_python(text: str) -> ServerInventory:
    tree = ast.parse(text)
    inventory = ServerInventory()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _python_call(node, inventory)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            _python_function(node, inventory)
    return inventory


def _python_call(call: ast.Call, inventory: ServerInventory) -> None:
    name = (dotted_name(call.func) or "").rsplit(".", 1)[-1]
    if name in SERVER_CLASSES:
        instructions = _const_str(_kwarg(call, "instructions"))
        if instructions and not inventory.instructions:
            inventory.instructions = instructions
            inventory.server_name = _const_str(call.args[0] if call.args else _kwarg(call, "name"))
    elif name == "Tool":
        tool_name = _const_str(_kwarg(call, "name"))
        if tool_name:
            schema = _literal(_kwarg(call, "inputSchema") or _kwarg(call, "input_schema"))
            inventory.tools.append(
                ToolInfo.from_wire(
                    {
                        "name": tool_name,
                        "description": _const_str(_kwarg(call, "description")) or "",
                        "inputSchema": schema if isinstance(schema, dict) else {"type": "object"},
                    }
                )
            )


def _decorator_kind(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ast.expr] | None:
    for deco in func.decorator_list:
        name = (dotted_name(deco) or "").rsplit(".", 1)[-1]
        if name in ("tool", "prompt", "resource"):
            return name, deco
    return None


def _python_function(func: ast.FunctionDef | ast.AsyncFunctionDef, inventory: ServerInventory) -> None:
    found = _decorator_kind(func)
    if found is None:
        return
    kind, deco = found
    call = deco if isinstance(deco, ast.Call) else None
    explicit = None
    if call is not None:
        explicit = _const_str(_kwarg(call, "name"))
        if explicit is None and kind == "tool" and call.args:
            explicit = _const_str(call.args[0])
    description = (_const_str(_kwarg(call, "description")) if call else None) or ast.get_docstring(func) or ""
    if kind == "tool":
        data: dict[str, Any] = {"name": explicit or func.name, "description": description, "inputSchema": _schema(func)}
        if call is not None:
            title = _const_str(_kwarg(call, "title"))
            if title:
                data["title"] = title
            notes = _annotations(_kwarg(call, "annotations"))
            if notes:
                data["annotations"] = notes
        inventory.tools.append(ToolInfo.from_wire(data))
    elif kind == "prompt":
        schema = _schema(func)
        required = set(schema.get("required", []))
        args = [
            PromptArgument(name=n, description=str(p.get("description", "")), required=n in required)
            for n, p in schema.get("properties", {}).items()
        ]
        inventory.prompts.append(PromptInfo(name=explicit or func.name, description=description, arguments=args))
    else:
        uri = (
            _const_str(call.args[0])
            if call is not None and call.args
            else _const_str(_kwarg(call, "uri"))
            if call
            else None
        )
        if uri:
            inventory.resources.append(ResourceInfo(uri=uri, name=explicit or func.name, description=description))


def _annotations(node: ast.expr | None) -> dict[str, Any]:
    if node is None:
        return {}
    value = _literal(node)
    if isinstance(value, dict):
        return value
    if isinstance(node, ast.Call):  # ToolAnnotations(readOnlyHint=True, ...)
        return {k.arg: _literal(k.value) for k in node.keywords if k.arg and _literal(k.value) is not None}
    return {}


def _schema(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    args = func.args
    positional = [*args.posonlyargs, *args.args]
    defaults: dict[str, ast.expr] = {}
    for arg, default_node in zip(positional[len(positional) - len(args.defaults) :], args.defaults, strict=False):
        defaults[arg.arg] = default_node
    for arg, kw_default in zip(args.kwonlyargs, args.kw_defaults, strict=False):
        if kw_default is not None:
            defaults[arg.arg] = kw_default
    properties: dict[str, Any] = {}
    required: list[str] = []
    for arg in [*positional, *args.kwonlyargs]:
        if arg.arg in SKIP_PARAMS or _is_context(arg.annotation):
            continue
        prop = _type_schema(arg.annotation)
        default: ast.expr | None = defaults.get(arg.arg)
        field_call = (
            default if isinstance(default, ast.Call) and (dotted_name(default.func) or "").endswith("Field") else None
        )
        if field_call is not None:
            desc = _const_str(_kwarg(field_call, "description"))
            if desc:
                prop["description"] = desc
            default = _kwarg(field_call, "default") or (field_call.args[0] if field_call.args else None)
            if isinstance(default, ast.Constant) and default.value is Ellipsis:
                default = None
        if default is not None:
            value = _literal(default)
            if value is not None or (isinstance(default, ast.Constant) and default.value is None):
                prop["default"] = value
        else:
            required.append(arg.arg)
        properties[arg.arg] = prop
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _is_context(annotation: ast.expr | None) -> bool:
    text = ast.unparse(annotation) if annotation is not None else ""
    return any(name in text for name in CONTEXT_TYPES)


def _type_schema(annotation: ast.expr | None) -> dict[str, Any]:
    """Turn a Python type hint into a small JSON schema."""
    if annotation is None:
        return {}
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):  # a string annotation
        try:
            return _type_schema(ast.parse(annotation.value, mode="eval").body)
        except SyntaxError:
            return {}
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):  # X | None
        for side in (annotation.left, annotation.right):
            if not (isinstance(side, ast.Constant) and side.value is None):
                return _type_schema(side)
    if isinstance(annotation, ast.Subscript):
        base = (dotted_name(annotation.value) or "").rsplit(".", 1)[-1]
        inner = annotation.slice
        if base == "Optional":
            return _type_schema(inner)
        if base == "Annotated" and isinstance(inner, ast.Tuple) and inner.elts:
            schema = _type_schema(inner.elts[0])
            for extra in inner.elts[1:]:
                if isinstance(extra, ast.Call):
                    desc = _const_str(_kwarg(extra, "description"))
                    if desc:
                        schema["description"] = desc
                elif _const_str(extra):
                    schema["description"] = _const_str(extra)
            return schema
        if base == "Literal":
            values = [_literal(e) for e in (inner.elts if isinstance(inner, ast.Tuple) else [inner])]
            return {"enum": [v for v in values if v is not None]}
        if base == "Union" and isinstance(inner, ast.Tuple):
            usable = [e for e in inner.elts if not (isinstance(e, ast.Constant) and e.value is None)]
            return _type_schema(usable[0]) if usable else {}
        kind = PY_TYPES.get(base)
        return {"type": kind} if kind else {}
    name = (dotted_name(annotation) or "").rsplit(".", 1)[-1]
    kind = PY_TYPES.get(name)
    return {"type": kind} if kind else {}


# ---- JavaScript and TypeScript ---------------------------------------------------

_JS_STRING = r"""(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`((?:\\.|[^`\\$])*)`)"""
_REGISTER = re.compile(r"""(?:registerTool|addTool)\s*\(\s*""" + _JS_STRING + r"""\s*,\s*\{""")
_SERVER_TOOL = re.compile(r"""\.tool\s*\(\s*""" + _JS_STRING + r"""\s*,\s*""" + _JS_STRING)
_TOOL_OBJECT = re.compile(
    r"""\bname\s*:\s*"""
    + _JS_STRING
    + r"""\s*,\s*(?:title\s*:\s*"""
    + _JS_STRING
    + r"""\s*,\s*)?description\s*:\s*"""
    + _JS_STRING
)
_DESCRIPTION = re.compile(r"""\bdescription\s*:\s*""" + _JS_STRING)
_PROMPT = re.compile(r"""(?:registerPrompt|\.prompt)\s*\(\s*""" + _JS_STRING)
_JS_INSTRUCTIONS = re.compile(r"""\binstructions\s*:\s*""" + _JS_STRING)
_JS_SERVER_NAME = re.compile(r"""new\s+(?:McpServer|Server)\s*\(\s*\{\s*name\s*:\s*""" + _JS_STRING)


def _js_value(match: re.Match[str], first_group: int) -> str:
    raw = next((match.group(i) for i in range(first_group, first_group + 3) if match.group(i) is not None), "")
    return raw.replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'").replace("\\`", "`")


def extract_javascript(text: str) -> ServerInventory:
    inventory = ServerInventory()
    tools: dict[str, str] = {}
    for match in _REGISTER.finditer(text):
        name = _js_value(match, 1)
        body = text[match.end() : match.end() + 4000]
        desc = _DESCRIPTION.search(body)
        tools.setdefault(name, _js_value(desc, 1) if desc else "")
    for match in _SERVER_TOOL.finditer(text):
        tools.setdefault(_js_value(match, 1), _js_value(match, 4))
    for match in _TOOL_OBJECT.finditer(text):
        tools.setdefault(_js_value(match, 1), _js_value(match, 7))
    inventory.tools = [
        ToolInfo.from_wire({"name": n, "description": d, "inputSchema": {"type": "object"}})
        for n, d in tools.items()
        if n
    ]
    inventory.prompts = [PromptInfo(name=_js_value(m, 1)) for m in _PROMPT.finditer(text)]
    instructions = _JS_INSTRUCTIONS.search(text)
    if instructions:
        inventory.instructions = _js_value(instructions, 1)
    server = _JS_SERVER_NAME.search(text)
    if server:
        inventory.server_name = _js_value(server, 1)
    return inventory
