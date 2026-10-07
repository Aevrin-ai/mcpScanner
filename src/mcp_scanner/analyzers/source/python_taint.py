# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Very small taint tracking for one Python function.

"Tainted" means "the agent controls this value". We start with the tool's
parameters and follow simple assignments. This is not perfect, but it is easy to
read and catches the common case: `cmd = f"ls {path}"; os.system(cmd)`.
"""

from __future__ import annotations

import ast

from mcp_scanner.analyzers.source.python_sinks import SANITIZERS, dotted_name, resolve

SKIP_PARAMS = {"self", "cls", "ctx", "context"}


def function_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = func.args
    names = [a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def tainted_names_in(expr: ast.AST, tainted: set[str], aliases: dict[str, str]) -> set[str]:
    """Which tainted names flow into this expression. Values passed through a sanitizer do not count."""
    found: set[str] = set()

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            name = resolve(dotted_name(node.func), aliases)
            # A hash or a fresh ID of the input cannot steer a path or a command.
            if name in SANITIZERS or (name or "").startswith(("hashlib.", "uuid.", "secrets.token_")):
                return
        if isinstance(node, ast.Name) and node.id in tainted:
            found.add(node.id)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(expr)
    return found


def _targets(node: ast.AST) -> list[ast.expr]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, ast.AnnAssign | ast.AugAssign):
        return [node.target]
    if isinstance(node, ast.For | ast.AsyncFor):
        return [node.target]
    if isinstance(node, ast.NamedExpr):
        return [node.target]
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return [node.optional_vars]
    return []


def _value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign | ast.NamedExpr):
        return node.value
    if isinstance(node, ast.For | ast.AsyncFor):
        return node.iter
    if isinstance(node, ast.withitem):
        return node.context_expr
    return None


def _names(target: ast.expr) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def propagate(func: ast.AST, start: set[str], aliases: dict[str, str]) -> dict[str, set[str]]:
    """Return {variable: {original params it came from}}. Runs until nothing changes."""
    origin: dict[str, set[str]] = {name: {name} for name in start}
    nodes = [n for n in ast.walk(func) if _targets(n)]
    changed = True
    rounds = 0
    while changed and rounds < 10:
        changed, rounds = False, rounds + 1
        for node in nodes:
            value = _value(node)
            if value is None:
                continue
            sources = tainted_names_in(value, set(origin), aliases)
            if not sources:
                continue
            params = set().union(*(origin[s] for s in sources))
            for target in _targets(node):
                for name in _names(target):
                    before = origin.get(name, set())
                    if not params <= before:
                        origin[name] = before | params
                        changed = True
    return origin
