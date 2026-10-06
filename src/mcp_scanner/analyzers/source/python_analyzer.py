# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Find MCP tool functions in a Python file and the risky calls they make."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.analyzers.source.python_sinks import (
    DECODERS,
    IMPORT_SINKS,
    categorize,
    dotted_name,
    first_arg,
    resolve,
)
from mcp_scanner.analyzers.source.python_taint import (
    SKIP_PARAMS,
    function_params,
    propagate,
    tainted_names_in,
)
from mcp_scanner.rules.patterns import SENSITIVE_PATH, SUSPICIOUS_DOMAINS

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef
ENTRY_DECORATORS = {
    "tool": "tool",
    "call_tool": "tool",
    "prompt": "prompt",
    "get_prompt": "prompt",
    "resource": "resource",
    "read_resource": "resource",
}
MCP_MARKERS = re.compile(r"\b(?:mcp\.server|fastmcp|FastMCP|MCPServer|from\s+mcp\b|import\s+mcp\b)")
EXTRA_SENSITIVE = re.compile(
    r"(?:Library/Keychains|Login Data|\.bash_history|\.zsh_history|Cookies\.sqlite|key4\.db|logins\.json|"
    r"Local State|\.git-credentials|\.docker/config\.json|\.kube/config)",
    re.IGNORECASE,
)
PERSISTENCE_MARKERS = re.compile(
    r"(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|authorized_keys|crontab|/etc/cron|LaunchAgents|LaunchDaemons|"
    r"Start Menu\\\\Programs\\\\Startup|CurrentVersion\\\\Run|systemd/system)",
    re.IGNORECASE,
)
RAW_IP_URL = re.compile(r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|localhost)\d{1,3}(?:\.\d{1,3}){3}")
MAX_DEPTH = 3


@dataclass
class _Ctx:
    file: str
    lines: list[str]
    aliases: dict[str, str]
    functions: dict[str, FuncNode]
    hits: list[f.CodeHit] = field(default_factory=list)
    seen: set[tuple[str, int]] = field(default_factory=set)

    def snippet(self, line: int) -> str:
        return self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""

    def add(self, hit: f.CodeHit) -> None:
        # Tool entry points are scanned first, so the first hit on a line is the most informative one.
        key = (hit.category, hit.line)
        if key not in self.seen:
            self.seen.add(key)
            self.hits.append(hit)


def collect_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def collect_functions(tree: ast.Module) -> dict[str, FuncNode]:
    functions: dict[str, FuncNode] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.setdefault(node.name, node)
    return functions


def entry_kind(func: FuncNode) -> tuple[str, str] | None:
    """If the function is an MCP entry point, return (kind, name the agent sees)."""
    for deco in func.decorator_list:
        name = dotted_name(deco)
        if not name:
            continue
        last = name.rsplit(".", 1)[-1]
        if last not in ENTRY_DECORATORS:
            continue
        public = func.name
        if isinstance(deco, ast.Call):
            explicit = next((k.value for k in deco.keywords if k.arg == "name"), None)
            explicit = explicit or (deco.args[0] if deco.args and last == "tool" else None)
            if isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                public = explicit.value
        return ENTRY_DECORATORS[last], public
    return None


def analyze_python(text: str, rel_path: str) -> tuple[list[f.ToolFunction], list[f.CodeHit], bool]:
    """Return (tool functions, hits, file mentions MCP)."""
    tree = ast.parse(text)
    ctx = _Ctx(rel_path, text.splitlines(), collect_aliases(tree), collect_functions(tree))
    tools: list[f.ToolFunction] = []
    for func in ctx.functions.values():
        entry = entry_kind(func)
        if entry is None:
            continue
        kind, public = entry
        tools.append(f.ToolFunction(public, func.name, rel_path, func.lineno, kind))
        params = {p for p in function_params(func) if p not in SKIP_PARAMS}
        _scan_function(ctx, func, params, public, 0, set())
    for func in ctx.functions.values():
        _scan_function(ctx, func, set(), None, 0, set())
    _scan_constants(ctx, tree)
    return tools, ctx.hits, bool(MCP_MARKERS.search(text))


def _scan_function(
    ctx: _Ctx, func: FuncNode, tainted: set[str], tool: str | None, depth: int, visited: set[str]
) -> None:
    if func.name in visited or depth > MAX_DEPTH:
        return
    visited = visited | {func.name}
    origin = propagate(func, tainted, ctx.aliases) if tainted else {}
    sanitized_paths = _has_path_check(func) or _calls_path_checker(ctx, func)
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            _check_call(ctx, func, node, origin, tool, sanitized_paths)
            _follow_local_call(ctx, node, origin, tool, depth, visited)
    _check_env_dump(ctx, func, tool)
    _check_reverse_shell(ctx, func, tool)


def _check_call(
    ctx: _Ctx, func: FuncNode, call: ast.Call, origin: dict[str, set[str]], tool: str | None, sanitized: bool
) -> None:
    name = resolve(dotted_name(call.func), ctx.aliases)
    if not name:
        return
    params = sorted(set().union(*(origin[n] for n in _tainted_args(call, origin, ctx))) if origin else set())
    if name in IMPORT_SINKS and params:
        ctx.add(_hit(ctx, f.CODE_EVAL, call, func, tool, params, f"{name}() with tool input"))
        return
    found = categorize(call, name)
    if found is None:
        return
    category, detail = found
    if category == f.CODE_EVAL and _is_obfuscated(call, ctx):
        ctx.add(_hit(ctx, f.OBFUSCATED_EXEC, call, func, tool, params, "runs code that is decoded at run time"))
        return
    if not params and not _worth_reporting_untainted(category, call):
        return
    hit = _hit(ctx, category, call, func, tool, params, detail)
    hit.sanitized = sanitized and category in (f.FILE_READ, f.FILE_WRITE)
    ctx.add(hit)


def _worth_reporting_untainted(category: str, call: ast.Call) -> bool:
    """Without tool input, only some calls are worth a note."""
    arg = first_arg(call)
    literal = isinstance(arg, ast.Constant)
    if category == f.CODE_EVAL:
        return not literal
    if category == f.COMMAND:
        return not literal
    # Writes are kept even without tool input: rules use them to spot startup file changes.
    return category in (f.DESERIALIZATION, f.NETWORK, f.FILE_WRITE)


def _tainted_args(call: ast.Call, origin: dict[str, set[str]], ctx: _Ctx) -> set[str]:
    names: set[str] = set()
    for arg in [*call.args, *(k.value for k in call.keywords)]:
        names |= tainted_names_in(arg, set(origin), ctx.aliases)
    if isinstance(call.func, ast.Attribute):  # Path(user_path).write_text(...)
        names |= tainted_names_in(call.func.value, set(origin), ctx.aliases)
    return names


def _is_obfuscated(call: ast.Call, ctx: _Ctx) -> bool:
    arg = first_arg(call)
    if arg is None:
        return False
    for node in ast.walk(arg):
        if isinstance(node, ast.Call) and resolve(dotted_name(node.func), ctx.aliases) in DECODERS:
            return True
    return False


def _follow_local_call(
    ctx: _Ctx, call: ast.Call, origin: dict[str, set[str]], tool: str | None, depth: int, visited: set[str]
) -> None:
    """If a tool passes its input to a helper in the same file, check the helper too."""
    if not origin or tool is None:
        return
    name = dotted_name(call.func) or ""
    target = ctx.functions.get(name.rsplit(".", 1)[-1])
    if target is None:
        return
    params = [p for p in function_params(target) if p not in SKIP_PARAMS]
    tainted: set[str] = set()
    for i, arg in enumerate(call.args):
        if i < len(params) and tainted_names_in(arg, set(origin), ctx.aliases):
            tainted.add(params[i])
    for kw in call.keywords:
        if kw.arg in params and tainted_names_in(kw.value, set(origin), ctx.aliases):
            tainted.add(kw.arg)
    if tainted:
        _scan_function(ctx, target, tainted, tool, depth + 1, visited)


def _has_path_check(func: FuncNode) -> bool:
    """Does the function check that a path stays inside an allowed folder?"""
    source = ast.unparse(func)
    if any(word in source for word in ("is_relative_to(", "commonpath(", ".relative_to(")):
        return True  # these compare against a base folder on their own
    # A prefix check counts after the path is made absolute, or on the bare file name
    # ("only delete folders whose name starts with our own prefix").
    resolves = any(word in source for word in (".resolve(", "realpath(", "abspath(", "basename("))
    return resolves and ".startswith(" in source


def _calls_path_checker(ctx: _Ctx, func: FuncNode) -> bool:
    """Does the function pass paths through a local helper that checks the folder?"""
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            name = (dotted_name(node.func) or "").rsplit(".", 1)[-1]
            helper = ctx.functions.get(name)
            if helper is not None and helper is not func and _has_path_check(helper):
                return True
    return False


def _child_env_values(func: FuncNode) -> tuple[set[str], set[int]]:
    """Names and call nodes given to a child process as env=... . Copying the environment for
    a child process is normal, so those copies are not reported as reading every secret."""
    names: set[str] = set()
    nodes: set[int] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            value = next((k.value for k in node.keywords if k.arg == "env"), None)
            if isinstance(value, ast.Name):
                names.add(value.id)
            elif value is not None:
                nodes.update(id(n) for n in ast.walk(value))
    return names, nodes


def _check_env_dump(ctx: _Ctx, func: FuncNode, tool: str | None) -> None:
    child_names, child_nodes = _child_env_values(func)
    assigned_to = {
        id(node.value): {t.id for t in node.targets if isinstance(t, ast.Name)}
        for node in ast.walk(func)
        if isinstance(node, ast.Assign)
    }
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        name = resolve(dotted_name(node.func), ctx.aliases) or ""
        arg = first_arg(node)
        arg_name = resolve(dotted_name(arg), ctx.aliases) if arg is not None else None
        if name in ("os.environ.copy", "os.environ.items") or (
            name in ("dict", "str", "json.dumps", "repr") and arg_name == "os.environ"
        ):
            if id(node) in child_nodes or assigned_to.get(id(node), set()) & child_names:
                continue
            ctx.add(_hit(ctx, f.ENV_DUMP, node, func, tool, [], "reads the whole environment"))


def _check_reverse_shell(ctx: _Ctx, func: FuncNode, tool: str | None) -> None:
    calls = {resolve(dotted_name(n.func), ctx.aliases) for n in ast.walk(func) if isinstance(n, ast.Call)}
    if "os.dup2" in calls and any(c and c.startswith("socket") for c in calls):
        ctx.add(_hit(ctx, f.REVERSE_SHELL, func, func, tool, [], "connects a socket to a shell (os.dup2)"))


def _metadata_strings(tree: ast.Module) -> set[int]:
    """Docstrings and decorator arguments. They are tool descriptions (checked by the text
    rules), not code, so they must not count as code that touches files."""
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                skip.add(id(body[0].value))
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            for deco in node.decorator_list:
                skip.update(id(n) for n in ast.walk(deco) if isinstance(n, ast.Constant))
    return skip


def _scan_constants(ctx: _Ctx, tree: ast.Module) -> None:
    owner = _owner_map(tree)
    skip = _metadata_strings(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or len(node.value) < 4:
            continue
        if id(node) in skip:
            continue
        value = node.value
        func = owner.get(id(node))
        tool = _tool_for(func)
        if SENSITIVE_PATH.search(value) or EXTRA_SENSITIVE.search(value):
            ctx.add(_hit(ctx, f.SENSITIVE_PATH, node, func, tool, [], f"mentions '{value[:80]}'"))
        if SUSPICIOUS_DOMAINS.search(value) or RAW_IP_URL.search(value):
            ctx.add(_hit(ctx, f.EXFIL_ENDPOINT, node, func, tool, [], f"hardcoded destination '{value[:80]}'"))
        if PERSISTENCE_MARKERS.search(value):
            ctx.add(_hit(ctx, f.PERSISTENCE, node, func, tool, [], f"mentions '{value[:80]}'"))


def _owner_map(tree: ast.Module) -> dict[int, FuncNode]:
    owners: dict[int, FuncNode] = {}
    for func in ast.walk(tree):
        if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            for child in ast.walk(func):
                owners[id(child)] = func  # inner functions overwrite, which is what we want
    return owners


def _tool_for(func: FuncNode | None) -> str | None:
    if func is None:
        return None
    entry = entry_kind(func)
    return entry[1] if entry else None


def _hit(
    ctx: _Ctx, category: str, node: ast.AST, func: FuncNode | None, tool: str | None, params: list[str], detail: str
) -> f.CodeHit:
    line = getattr(node, "lineno", 0)
    return f.CodeHit(
        category=category,
        file=ctx.file,
        line=line,
        snippet=ctx.snippet(line),
        language="python",
        function=func.name if func is not None else None,
        tool=tool,
        tainted=bool(params),
        tainted_params=list(params),
        detail=detail,
    )
