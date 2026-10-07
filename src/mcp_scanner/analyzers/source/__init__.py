# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Static analysis of MCP server source code."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.analyzers.source.javascript_analyzer import LONG_LINE, analyze_javascript
from mcp_scanner.analyzers.source.python_analyzer import analyze_python
from mcp_scanner.analyzers.source.walker import (
    JS_EXT,
    PYTHON_EXT,
    SOURCE_EXT,
    entry_with_local_imports,
    walk_folder,
)
from mcp_scanner.models.server import ServerSpec
from mcp_scanner.utils.secrets import find_secrets

log = logging.getLogger(__name__)

__all__ = ["analyze_source", "find_source_root", "is_minified", "source_files"]

# A comment that says a key is public on purpose, for example "Yes, we're aware this API key is public."
PUBLIC_KEY_COMMENT = re.compile(
    r"(?:#|//|/\*|\*|<!--)[^\n]*(?:\bkey\b[^\n]*\bpublic\b|\bpublic\b[^\n]*\bkey\b|\bnot\s+(?:a\s+)?secret\b"
    r"|\bsafe\s+to\s+(?:commit|share|expose|publish)\b)",
    re.IGNORECASE,
)
# Reading an environment variable by name, in JavaScript and Python.
ENV_READ = re.compile(
    r"process\.env\.([A-Z][A-Z0-9_]{2,})"
    r"|process\.env\[\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]\s*\]"
    r"|os\.(?:environ\.get|getenv)\(\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]"
    r"|os\.environ\[\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]\s*\]"
)
# Minified or bundled JavaScript: one very long line, very long lines on average, or many long
# lines (a bundle that mixes normal and minified code).
MINIFIED_LONGEST_LINE = 5000
MINIFIED_AVERAGE_LINE = 400
MINIFIED_LONG_LINES = 50


def is_minified(text: str) -> bool:
    lines = text.splitlines()
    if not lines:
        return False
    if max(len(line) for line in lines) > MINIFIED_LONGEST_LINE or len(text) / len(lines) > MINIFIED_AVERAGE_LINE:
        return True
    return sum(1 for line in lines if len(line) > LONG_LINE) >= MINIFIED_LONG_LINES


def find_source_root(spec: ServerSpec) -> Path | None:
    """Where is the code? Use --source if given, else a local script in the launch command."""
    if spec.source_path:
        path = Path(spec.source_path).expanduser()
        return path if path.exists() else None
    for arg in spec.args:
        if arg.startswith("-"):
            continue
        path = Path(arg).expanduser()
        if not path.is_absolute() and spec.cwd:
            path = Path(spec.cwd).expanduser() / path
        try:
            if path.is_file() and path.suffix.lower() in SOURCE_EXT:
                return path
        except OSError:
            continue
    return None


def source_files(root: Path, project_root: Path | None = None) -> tuple[list[Path], Path]:
    """The files to read, and the folder their paths are shown relative to."""
    root = root.resolve()
    project = project_root.resolve() if project_root else None
    if root.is_file():
        return entry_with_local_imports(root, project_root=project), project or root.parent
    return walk_folder(root), project or root


def analyze_source(root: Path, project_root: Path | None = None) -> f.SourceFacts:
    root = root.resolve()
    files, base = source_files(root, project_root)
    facts = f.SourceFacts(root=str(root))
    for path in files:
        _analyze_file(path, base, facts)
    return facts


def _analyze_file(path: Path, base: Path, facts: f.SourceFacts) -> None:
    try:
        rel = path.relative_to(base).as_posix()
    except ValueError:
        rel = path.name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        facts.errors.append(f"{rel}: could not read ({exc.strerror})")
        return
    facts.files_scanned.append(rel)
    suffix = path.suffix.lower()
    try:
        if suffix in PYTHON_EXT:
            tools, hits, mcp = analyze_python(text, rel)
        elif suffix in JS_EXT and is_minified(text):
            # Code patterns in minified bundles give unreadable, mostly wrong evidence.
            # Secrets are still checked below.
            facts.minified_files.append(rel)
            tools, hits, mcp = [], [], False
        elif suffix in JS_EXT:
            tools, hits, mcp = analyze_javascript(text, rel)
            if any(len(line.strip()) > LONG_LINE for line in text.splitlines()):
                facts.minified_files.append(rel)  # its minified lines were skipped
        else:
            return
    except (SyntaxError, ValueError, RecursionError) as exc:
        facts.errors.append(f"{rel}: could not parse ({type(exc).__name__})")
        tools, hits, mcp = [], [], False
    facts.tool_functions.extend(tools)
    facts.hits.extend(hits)
    facts.mcp_detected = facts.mcp_detected or mcp
    facts.hits.extend(_secret_hits(text, rel, "python" if suffix in PYTHON_EXT else "javascript"))
    if facts.minified_files and facts.minified_files[-1] == rel and is_minified(text):
        return  # a bundle's variables belong to the libraries inside it, not to the server
    for match in ENV_READ.finditer(text):
        name = next(group for group in match.groups() if group)
        if name not in facts.env_reads:
            facts.env_reads.append(name)


def _secret_hits(text: str, rel: str, language: str) -> list[f.CodeHit]:
    hits = []
    lines = text.splitlines()
    for match in find_secrets(text):
        line = text.count("\n", 0, match.start) + 1
        hit = f.CodeHit(f.SECRET, rel, line, f"{match.kind}: {match.preview(text)}", language, detail=match.kind)
        # A comment on the same line or just above that says the key is public on purpose.
        nearby = "\n".join(lines[max(0, line - 3) : line])
        if PUBLIC_KEY_COMMENT.search(nearby):
            hit.note = "marked public"
        hits.append(hit)
    return hits
