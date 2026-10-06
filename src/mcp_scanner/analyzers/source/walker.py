# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Pick which source files to read.

Two modes:
  - a folder: walk it, skipping tests, dependencies, and build output
  - one entry file (for example `server.py` from the launch command): read it
    plus the local modules it imports, and nothing else
"""

from __future__ import annotations

import ast
import fnmatch
import re
from pathlib import Path

PYTHON_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx"}
SOURCE_EXT = PYTHON_EXT | JS_EXT
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    "dist",
    "build",
    "site-packages",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "coverage",
    ".next",
    "out",
    "tests",
    "test",
    "__tests__",
    "spec",
    "testdata",
}
MAX_FILES = 2000
MAX_FILE_BYTES = 5_000_000  # some real servers keep 30,000 lines in one file
IGNORE_FILE = ".aevrinignore"
_JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\s*\(\s*)['"](\.{1,2}/[^'"]+)['"]""")


def is_test_file(path: Path) -> bool:
    name = path.name
    return (
        name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js"))
        or name == "conftest.py"
    )


def load_ignore_patterns(root: Path) -> list[str]:
    ignore = root / IGNORE_FILE
    if not ignore.is_file():
        return []
    lines = ignore.read_text(encoding="utf-8", errors="replace").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _ignored(rel: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/") and (rel + "/").startswith(pattern):
            return True
        if fnmatch.fnmatch(rel, pattern):
            return True
    return False


def walk_folder(root: Path) -> list[Path]:
    patterns = load_ignore_patterns(root)
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(files) >= MAX_FILES:
            break
        if path.suffix.lower() not in SOURCE_EXT or not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel_parts[:-1]):
            continue
        if is_test_file(path) or path.name.endswith(".d.ts"):
            continue
        if _ignored(path.relative_to(root).as_posix(), patterns):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def entry_with_local_imports(entry: Path, limit: int = 300, project_root: Path | None = None) -> list[Path]:
    """The entry file plus local files it imports, found by following imports.

    `project_root` is the repository root. Imports like `from src.utils import x`
    are resolved from there as well as from the entry file's folder.
    """
    roots = [entry.parent] + ([project_root] if project_root else [])
    seen: list[Path] = []
    queue = [entry.resolve()]
    while queue and len(seen) < limit:
        current = queue.pop(0)
        if current in seen or not current.is_file():
            continue
        seen.append(current)
        try:
            text = current.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if current.suffix in PYTHON_EXT:
            queue.extend(_python_local_imports(text, current.parent, roots))
        elif current.suffix in JS_EXT:
            queue.extend(_js_local_imports(text, current.parent))
    return seen


def _python_local_imports(text: str, folder: Path, roots: list[Path]) -> list[Path]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.append(node.module)
            # "from pkg import mod" and "from . import mod" can import modules, not just names.
            names.extend(f"{node.module}.{a.name}" if node.module else a.name for a in node.names if a.name != "*")
    found = []
    for name in names:
        rel = Path(*name.split("."))
        for base in (folder, *roots):
            for candidate in (base / rel.with_suffix(".py"), base / rel / "__init__.py"):
                if candidate.is_file():
                    found.append(candidate.resolve())
    return found


def _js_local_imports(text: str, folder: Path) -> list[Path]:
    found = []
    for match in _JS_IMPORT.finditer(text):
        base = (folder / match.group(1)).resolve()
        for candidate in (base, *(base.with_suffix(ext) for ext in JS_EXT), base / "index.js", base / "index.ts"):
            if candidate.is_file():
                found.append(candidate)
                break
    return found
