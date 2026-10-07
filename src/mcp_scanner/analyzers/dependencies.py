# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Collect dependency facts: which packages a server uses and how it is installed.

Sources:
  - the launch command (`npx pkg@1.2.3`, `uvx pkg==1.0`), because most MCP servers
    are started straight from a package registry
  - requirements*.txt, pyproject.toml, setup.py
  - package.json and package-lock.json (lock files also show indirect packages)

Like every analyzer, this only collects facts. Rules decide what is a problem.
All checks are offline. The package lists live in `mcp_scanner/data`.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.sandbox.docker import command_basename

NPM_RUNNERS = {"npx", "bunx", "pnpx"}
NPM_DLX = {"pnpm", "yarn", "npm"}  # `pnpm dlx pkg`, `yarn dlx pkg`, `npm exec pkg`
PY_RUNNERS = {"uvx", "pipx"}
SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".py"}
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
RISKY_SCRIPT = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|iwr|powershell|bash\s+-c|sh\s+-c|node\s+-e|python\s+-c|eval|base64)\b|https?://",
    re.IGNORECASE,
)
URL_SPEC = re.compile(r"^(?:git\+|git://|github:|gitlab:|bitbucket:|https?://)", re.IGNORECASE)
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


@dataclass
class Dependency:
    name: str
    ecosystem: str  # "npm" or "pypi"
    source: str  # file name, or "launch command"
    spec: str = ""  # the version text as written, for example "^1.2.0"
    version: str | None = None  # an exact version, when we know it
    direct: bool = True
    line: int | None = None

    @property
    def location(self) -> str:
        return f"{self.source}:{self.line}" if self.line else self.source

    @property
    def is_url(self) -> bool:
        return bool(URL_SPEC.match(self.spec.strip()))

    @property
    def is_unpinned(self) -> bool:
        spec = self.spec.strip().lower()
        return spec in ("", "*", "latest", "x") and self.version is None


@dataclass
class InstallScript:
    file: str
    hook: str
    command: str

    @property
    def risky(self) -> bool:
        return bool(RISKY_SCRIPT.search(self.command))


@dataclass
class DependencyFacts:
    dependencies: list[Dependency] = field(default_factory=list)
    install_scripts: list[InstallScript] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def launch_packages(self) -> list[Dependency]:
        return [d for d in self.dependencies if d.source == "launch command"]


# ---- launch command ----------------------------------------------------------


def launch_packages(spec: ServerSpec) -> list[Dependency]:
    """Packages that the launch command downloads and runs."""
    if spec.transport != TransportType.STDIO or not spec.command:
        return []
    base = command_basename(spec.command)
    args = list(spec.args)
    if base in NPM_DLX and args and args[0] in ("dlx", "exec", "x"):
        base, args = "npx", args[1:]
    if base in NPM_RUNNERS:
        return _npm_launch(args)
    if base == "uvx" or (base == "pipx" and args[:1] == ["run"]):
        return _python_launch(args[1:] if base == "pipx" else args)
    return []


def _first_positional(args: list[str], value_flags: set[str]) -> tuple[str | None, list[str]]:
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in value_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg, args[i + 1 :]
    return None, []


def _npm_launch(args: list[str]) -> list[Dependency]:
    found: list[Dependency] = []
    for i, arg in enumerate(args):  # `npx -p pkg cmd` and `--package=pkg`
        if arg in ("-p", "--package") and i + 1 < len(args):
            found.append(_npm_dep(args[i + 1]))
        elif arg.startswith("--package="):
            found.append(_npm_dep(arg.split("=", 1)[1]))
    if not found:
        first, _ = _first_positional(args, {"-p", "--package", "-c", "--call"})
        if first and not first.startswith((".", "/", "\\")) and Path(first).suffix not in SCRIPT_SUFFIXES:
            found.append(_npm_dep(first))
    return found


def _npm_dep(text: str) -> Dependency:
    name, _, spec = text.rpartition("@") if text.rfind("@") > 0 else (text, "", "")
    if not name:
        name, spec = text, ""
    return Dependency(name=name, ecosystem="npm", source="launch command", spec=spec, version=_exact(spec))


def _python_launch(args: list[str]) -> list[Dependency]:
    for i, arg in enumerate(args):
        if arg == "--from" and i + 1 < len(args):
            return [_py_dep(args[i + 1], "launch command")]
        if arg.startswith("--from="):
            return [_py_dep(arg.split("=", 1)[1], "launch command")]
    first, _ = _first_positional(args, {"--python", "-p", "--with", "--index-url", "--index", "--spec"})
    return [_py_dep(first, "launch command")] if first else []


def _py_dep(text: str, source: str, line: int | None = None) -> Dependency:
    text = text.strip()
    if URL_SPEC.match(text) or " @ " in text:
        name = text.split(" @ ")[0].strip() if " @ " in text else text
        return Dependency(name=name, ecosystem="pypi", source=source, spec=text, line=line)
    match = _REQ_LINE.match(text)
    if not match:
        return Dependency(name=text, ecosystem="pypi", source=source, line=line)
    name, spec = match.group(1), match.group(3).split(";")[0].strip()
    exact = spec[2:].strip() if spec.startswith("==") and "*" not in spec else None
    return Dependency(name=name, ecosystem="pypi", source=source, spec=spec, version=exact, line=line)


def _exact(spec: str) -> str | None:
    spec = spec.strip().lstrip("=v")
    return spec if re.fullmatch(r"\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.\-]+)?", spec) else None


# ---- project files -----------------------------------------------------------


MANIFESTS = ("package.json", "pyproject.toml", "requirements.txt", "setup.py")
NOT_PROJECT_DIRS = {"node_modules", "tests", "test", "docs", "examples", "dist", "build", "vendor", "__pycache__"}


def dependency_roots(source_root: Path, repo_root: Path | None = None) -> list[Path]:
    """Folders that may hold dependency files for this source.

    For a repository, that is also its root and every top level folder with its own
    manifest, because one repository often ships several servers or packages.
    """
    folder = source_root if source_root.is_dir() else source_root.parent
    roots = [folder]
    if folder.name in ("src", "lib", "dist", "build") and folder.parent != folder:
        roots.append(folder.parent)
    if repo_root is not None:
        roots.append(repo_root)
        for child in sorted(repo_root.iterdir()) if repo_root.is_dir() else []:
            usable = child.is_dir() and not child.name.startswith(".") and child.name not in NOT_PROJECT_DIRS
            if usable and any((child / name).is_file() for name in MANIFESTS):
                roots.append(child)
    unique: list[Path] = []
    for root in roots:
        if root.resolve() not in [u.resolve() for u in unique]:
            unique.append(root)
    return unique


def analyze_dependencies(spec: ServerSpec, source_root: Path | None, repo_root: Path | None = None) -> DependencyFacts:
    facts = DependencyFacts(dependencies=launch_packages(spec))
    if source_root is None:
        return facts
    base = repo_root or (source_root if source_root.is_dir() else source_root.parent)
    for folder in dependency_roots(source_root, repo_root):
        for path in sorted(folder.glob("requirements*.txt")):
            _read_file(facts, path, _parse_requirements, base)
        for name, parser in (
            ("pyproject.toml", _parse_pyproject),
            ("setup.py", _parse_setup_py),
            ("package.json", _parse_package_json),
            ("package-lock.json", _parse_package_lock),
        ):
            path = folder / name
            if path.is_file():
                _read_file(facts, path, parser, base)
    return facts


def _read_file(facts: DependencyFacts, path: Path, parser: Any, base: Path | None = None) -> None:
    # "resolve-advanced/package.json" says more than "package.json" when a repository has several.
    try:
        label = path.resolve().relative_to(base.resolve()).as_posix() if base else path.name
    except ValueError:
        label = path.name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        parser(text, label, facts)
        facts.files_scanned.append(label)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        facts.errors.append(f"{label}: could not read ({type(exc).__name__})")


def _parse_requirements(text: str, name: str, facts: DependencyFacts) -> None:
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "-e .")):
            continue
        if line.startswith("-e "):
            line = line[3:].strip()
        facts.dependencies.append(_py_dep(line, name, number))


def _parse_pyproject(text: str, name: str, facts: DependencyFacts) -> None:
    doc = tomllib.loads(text)
    project = doc.get("project") or {}
    entries: list[str] = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        entries.extend(group or [])
    for entry in entries:
        if isinstance(entry, str):
            facts.dependencies.append(_py_dep(entry, name, _line_of(text, entry)))
    poetry = ((doc.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for dep_name, value in poetry.items():
        if dep_name.lower() == "python":
            continue
        spec = value if isinstance(value, str) else str((value or {}).get("version") or (value or {}).get("git") or "")
        dep = _py_dep(f"{dep_name}{_poetry_spec(spec)}", name, _line_of(text, dep_name))
        if isinstance(value, dict) and (value.get("git") or value.get("url")):
            dep.spec = str(value.get("git") or value.get("url"))
        facts.dependencies.append(dep)


def _poetry_spec(spec: str) -> str:
    spec = spec.strip()
    if not spec or spec == "*":
        return ""
    return f"=={spec}" if re.fullmatch(r"\d+(?:\.\d+)*", spec) else spec


def _parse_setup_py(text: str, name: str, facts: DependencyFacts) -> None:
    if "cmdclass" in text and re.search(r"\binstall\b", text):
        facts.install_scripts.append(InstallScript(name, "cmdclass", "setup.py replaces the install command"))


def _parse_package_json(text: str, name: str, facts: DependencyFacts) -> None:
    doc = json.loads(text)
    if not isinstance(doc, dict):
        return
    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for dep_name, spec in deps.items():
            spec_text = str(spec)
            facts.dependencies.append(
                Dependency(
                    name=str(dep_name),
                    ecosystem="npm",
                    source=name,
                    spec=spec_text,
                    version=_exact(spec_text),
                    line=_line_of(text, f'"{dep_name}"'),
                )
            )
    scripts = doc.get("scripts")
    if isinstance(scripts, dict):
        for hook in INSTALL_HOOKS:
            if isinstance(scripts.get(hook), str):
                facts.install_scripts.append(InstallScript(name, hook, scripts[hook]))


def _parse_package_lock(text: str, name: str, facts: DependencyFacts) -> None:
    doc = json.loads(text)
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, dict):
        return
    direct = {d.name for d in facts.dependencies if d.ecosystem == "npm"}
    for key, info in packages.items():
        if not key or not isinstance(info, dict) or "node_modules/" not in key:
            continue
        pkg = key.rsplit("node_modules/", 1)[-1]
        version = info.get("version") if isinstance(info.get("version"), str) else None
        if pkg in direct and key == f"node_modules/{pkg}":
            # Fill the exact version of a direct dependency from the lock file.
            for dep in facts.dependencies:
                if dep.name == pkg and dep.ecosystem == "npm" and dep.version is None:
                    dep.version = version
            continue
        facts.dependencies.append(
            Dependency(name=pkg, ecosystem="npm", source=name, spec=version or "", version=version, direct=False)
        )


def _line_of(text: str, needle: str) -> int | None:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else None


# ---- package lists -----------------------------------------------------------


@dataclass(frozen=True)
class MaliciousEntry:
    name: str
    ecosystem: str
    versions: tuple[str, ...]
    summary: str
    references: tuple[str, ...]


@lru_cache(maxsize=1)
def known_malicious() -> dict[tuple[str, str], MaliciousEntry]:
    doc = json.loads(resources.files("mcp_scanner.data").joinpath("known_malicious_packages.json").read_text("utf-8"))
    table: dict[tuple[str, str], MaliciousEntry] = {}
    for ecosystem in ("npm", "pypi"):
        for item in doc.get(ecosystem, []):
            entry = MaliciousEntry(
                name=item["name"],
                ecosystem=ecosystem,
                versions=tuple(item.get("versions") or ["*"]),
                summary=item.get("summary", ""),
                references=tuple(item.get("references") or []),
            )
            table[(ecosystem, normalize_name(item["name"], ecosystem))] = entry
    return table


@lru_cache(maxsize=1)
def popular_packages() -> dict[str, frozenset[str]]:
    doc = json.loads(resources.files("mcp_scanner.data").joinpath("popular_packages.json").read_text("utf-8"))
    return {eco: frozenset(normalize_name(n, eco) for n in doc.get(eco, [])) for eco in ("npm", "pypi")}


def normalize_name(name: str, ecosystem: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def parse_version(text: str) -> tuple[int, ...] | None:
    match = re.match(r"v?(\d+(?:\.\d+)*)", text.strip())
    return tuple(int(p) for p in match.group(1).split(".")) if match else None


def version_in(version: str, rule: str) -> bool:
    """Does one version match one rule like '1.2.3', '>=1.0.16', or '*'?"""
    rule = rule.strip()
    if rule == "*":
        return True
    for op in (">=", "<=", ">", "<", "=="):
        if rule.startswith(op):
            have, want = parse_version(version), parse_version(rule[len(op) :])
            if have is None or want is None:
                return False
            width = max(len(have), len(want))
            have, want = have + (0,) * (width - len(have)), want + (0,) * (width - len(want))
            return {">=": have >= want, "<=": have <= want, ">": have > want, "<": have < want, "==": have == want}[op]
    return version.strip().lstrip("v") == rule.lstrip("v")


@dataclass
class MaliciousMatch:
    dependency: Dependency
    entry: MaliciousEntry
    certain: bool  # False when we do not know the installed version


def match_malicious(dep: Dependency) -> MaliciousMatch | None:
    entry = known_malicious().get((dep.ecosystem, normalize_name(dep.name, dep.ecosystem)))
    if entry is None:
        return None
    if dep.version:
        return MaliciousMatch(dep, entry, True) if any(version_in(dep.version, v) for v in entry.versions) else None
    # Version unknown. Every version bad, or an open range: the newest release may be bad.
    if any(v == "*" or v.startswith(">") for v in entry.versions):
        return MaliciousMatch(dep, entry, any(v == "*" for v in entry.versions))
    return None


# Real packages that sit one letter away from a popular one.
LEGIT_NEIGHBORS = {
    "preact",
    "request",
    "colors",
    "redux",
    "pydantic-core",
    "httpcore",
    "psycopg",
    "mysql",
    "sqlite",
    "jinja",
    "openapi",
    "pandas-stubs",
    "types-requests",
}


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein distance (with swaps of two letters), stopping early above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def typosquat_target(dep: Dependency) -> str | None:
    """The popular package this name imitates, or None."""
    name = normalize_name(dep.name, dep.ecosystem)
    popular = popular_packages().get(dep.ecosystem, frozenset())
    if name in popular or name in LEGIT_NEIGHBORS:
        return None
    if dep.ecosystem == "npm" and name.startswith("@"):
        # A scope that only looks like the official one: "@model-context-protocol/sdk".
        scope = name.split("/", 1)[0]
        if scope != "@modelcontextprotocol" and "modelcontextprotocol" in re.sub(r"[-_.]", "", scope):
            return "@modelcontextprotocol/*"
    if len(name) < 5:
        return None
    for target in sorted(popular):
        if len(target) < 5 or target.startswith("@") != name.startswith("@"):
            continue
        if edit_distance(name, target, 1) <= 1:
            return target
        # "python3-dateutil" vs "python-dateutil": a digit added or removed.
        if re.sub(r"\d", "", name) == re.sub(r"\d", "", target) and name != target:
            return target
    return None
