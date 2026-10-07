# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Scan an MCP server from a git repository link, for example a GitHub URL.

Steps:
  1. parse the link (branch, tag, commit, and sub folder are supported)
  2. fetch a shallow copy into the scanner cache, with git features that could
     run code or leave the folder turned off (hooks, submodules, LFS filters, symlinks)
  3. find how the server is started: README config blocks, pyproject.toml scripts,
     package.json bin, or common entry files that contain MCP code

Fetching never runs code from the repository. Starting it is a separate,
opt-in step (`--run`), and then only inside the Docker sandbox.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import httpx

from mcp_scanner.analyzers.source.walker import JS_EXT, PYTHON_EXT, SKIP_DIRS, entry_with_local_imports
from mcp_scanner.core.errors import TargetError
from mcp_scanner.utils import jsonc

log = logging.getLogger(__name__)

KNOWN_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}
FETCH_TIMEOUT = 300
MAX_ZIP_BYTES = 300 * 1024 * 1024
_SHA = re.compile(r"^[0-9a-f]{7,40}$")
MCP_CODE = re.compile(
    r"\b(?:FastMCP|MCPServer|McpServer|mcp\.server|@modelcontextprotocol/sdk|ListToolsRequestSchema|registerTool|from\s+mcp\b)"
)
ENTRY_CANDIDATES = (
    "server.py",
    "main.py",
    "app.py",
    "mcp_server.py",
    "src/server.py",
    "src/main.py",
    "index.js",
    "index.mjs",
    "server.js",
    "dist/index.js",
    "build/index.js",
    "src/index.js",
    "src/index.ts",
)


@dataclass
class RepoRef:
    url: str  # what the user typed
    clone_url: str
    host: str
    owner: str
    name: str
    ref: str | None = None  # branch, tag, or commit
    subdir: str | None = None  # a folder (or file) inside the repository

    @property
    def cache_key(self) -> str:
        return hashlib.sha256(self.clone_url.lower().encode()).hexdigest()[:16]


def parse_repo_url(text: str) -> RepoRef | None:
    """Return a RepoRef for a repository link, or None when the text is something else."""
    raw = text.strip()
    if raw.startswith("git+"):
        raw = raw[4:]
    ssh = re.match(r"^git@([\w.-]+):([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", raw)
    if ssh:
        host, owner, name = ssh.groups()
        return RepoRef(text, f"https://{host}/{owner}/{name}.git", host, owner, name)
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname.lower().removeprefix("www.")
    parts = [p for p in parsed.path.split("/") if p]
    if host not in KNOWN_HOSTS and not parsed.path.endswith(".git"):
        return None
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1].removesuffix(".git")
    ref = subdir = None
    rest = parts[2:]
    if host == "gitlab.com" and rest[:1] == ["-"]:
        rest = rest[1:]
    if len(rest) >= 2 and rest[0] in ("tree", "blob", "src"):
        ref = rest[1]
        subdir = "/".join(rest[2:]) or None
    return RepoRef(text, f"https://{host}/{owner}/{name}.git", host, owner, name, ref, subdir)


def cache_root() -> Path:
    path = Path.home() / ".aevrin-mcp-scanner" / "repos"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _git(args: list[str], cwd: Path | None = None, timeout: float = FETCH_TIMEOUT) -> str:
    exe = shutil.which("git")
    if exe is None:
        raise FileNotFoundError("git")
    env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "HOME", "USERPROFILE", "TEMP", "TMP")},
        "GIT_TERMINAL_PROMPT": "0",  # never ask for a password
        "GIT_LFS_SKIP_SMUDGE": "1",  # do not run LFS download filters
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    safe = [
        "-c",
        "core.symlinks=false",  # a link to ~/.ssh/id_rsa becomes a plain text file
        "-c",
        "core.hooksPath=" + os.devnull,
        "-c",
        "protocol.file.allow=never",
        "-c",
        "submodule.recurse=false",
        "-c",
        "advice.detachedHead=false",
    ]
    result = subprocess.run(
        [exe, *safe, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        raise TargetError(f"git {args[0]} failed: {result.stderr.strip().splitlines()[-1:] or ['unknown error']}")
    return result.stdout.strip()


def fetch_repo(ref: RepoRef, root: Path | None = None) -> tuple[Path, str]:
    """Fetch the repository into the cache. Returns (checkout folder, commit)."""
    dest = (root or cache_root()) / f"{ref.owner}-{ref.name}-{ref.cache_key}"
    try:
        return _fetch_with_git(ref, dest)
    except FileNotFoundError:
        if ref.host != "github.com":
            raise TargetError("git is not installed, and only GitHub links can be fetched without it") from None
        log.warning("git is not installed, downloading a zip archive instead")
        return _fetch_zip(ref, dest)
    except subprocess.TimeoutExpired as exc:
        raise TargetError(f"Fetching {ref.url} took longer than {FETCH_TIMEOUT}s") from exc


def _fetch_with_git(ref: RepoRef, dest: Path) -> tuple[Path, str]:
    if not (dest / ".git").is_dir():
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        _git(["init", "-q"], cwd=dest)
        _git(["remote", "add", "origin", ref.clone_url], cwd=dest)
    target = ref.ref or "HEAD"
    try:
        _git(["fetch", "-q", "--depth", "1", "--no-tags", "origin", target], cwd=dest)
    except TargetError as exc:
        raise TargetError(f"Could not fetch {ref.url} ({target}): {exc}") from exc
    _git(["checkout", "-q", "--force", "--detach", "FETCH_HEAD"], cwd=dest)
    _git(["clean", "-q", "-ffdx"], cwd=dest)  # remove anything left from an earlier run
    return dest, _git(["rev-parse", "HEAD"], cwd=dest)


def _fetch_zip(ref: RepoRef, dest: Path) -> tuple[Path, str]:
    url = f"https://codeload.github.com/{ref.owner}/{ref.name}/zip/{ref.ref or 'HEAD'}"
    with httpx.Client(follow_redirects=True, timeout=60) as client:
        response = client.get(url)
    if response.status_code != 200:
        raise TargetError(f"Could not download {ref.url} (HTTP {response.status_code})")
    if len(response.content) > MAX_ZIP_BYTES:
        raise TargetError("The repository archive is larger than 300 MB")
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        for info in archive.infolist():
            if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:  # skip folders and symlinks
                continue
            inner = PurePosixPath(*PurePosixPath(info.filename).parts[1:])  # drop "repo-sha/"
            if not inner.parts or ".." in inner.parts or inner.is_absolute():
                continue
            target = dest.joinpath(*inner.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    commit = response.headers.get("etag", "").strip('"W/') or (ref.ref or "HEAD")
    return dest, commit


# ---- how is the server started? ---------------------------------------------------


@dataclass
class Launch:
    entry: str  # file path inside the repository, posix style
    kind: str  # "python" or "node"
    found_by: str  # "readme", "pyproject", "package.json", or "entry file"
    args: list[str] = field(default_factory=list)  # extra arguments after the entry file
    hint: str = ""  # the launch command as written in the repository
    program: str | None = None  # the installed program name (pyproject script or npm bin), if any
    # For an entry that only exists after a build (build/index.js): the source file it is
    # compiled from (src/index.ts). Code checks read this file. --run builds and starts the entry.
    source: str | None = None


def find_launches(repo_dir: Path, subdir: str | None = None) -> list[Launch]:
    """Every server entry point we can find, best guesses first, one per file."""
    base = repo_dir / subdir if subdir else repo_dir
    if base.is_file():
        kind = "python" if base.suffix in PYTHON_EXT else "node"
        return [Launch(base.relative_to(repo_dir).as_posix(), kind, "link")]
    found: list[Launch] = _from_readme(repo_dir, base)
    if found:
        # The README says how to start the servers. That beats guessing, and it skips helper
        # scripts like npm installers that are not MCP servers themselves.
        return list({launch.entry: launch for launch in found}.values())[:5]
    found += _from_pyproject(repo_dir, base)
    found += _from_package_json(repo_dir, base)
    built = any(launch.source for launch in found)
    for launch in _from_entry_files(repo_dir, base):
        # When the project compiles its TypeScript, a raw .ts file is not what it runs.
        if not (built and Path(launch.entry).suffix in TS_SOURCE_EXT):
            found.append(launch)
    unique: dict[str, Launch] = {}
    for launch in found:
        unique.setdefault(launch.entry, launch)
    candidates = list(unique.values())
    # Helper programs (a background daemon, an installer) are not MCP servers. Keep entries
    # whose code builds an MCP server, unless that would leave nothing to scan.
    servers = [launch for launch in candidates if has_mcp_code(repo_dir, launch.source or launch.entry)]
    return (servers or candidates)[:5]


def _rel(repo_dir: Path, path: Path) -> str | None:
    try:
        resolved = path.resolve()
        if resolved.is_file() and resolved.is_relative_to(repo_dir.resolve()):
            return resolved.relative_to(repo_dir.resolve()).as_posix()
    except (OSError, ValueError):
        return None
    return None


_PLACEHOLDER_PREFIX = re.compile(
    r"^(?:<[^>]+>|\$\{[^}]+\}|%[^%]+%|~?/?(?:absolute/)?(?:path/to|your/path|full/path/to)/[^/\\]+|[A-Z]:\\path\\to\\[^\\]+)[/\\]",
    re.IGNORECASE,
)


def _from_readme(repo_dir: Path, base: Path) -> list[Launch]:
    launches: list[Launch] = []
    for readme in [*sorted(base.glob("README*.md")), *sorted((repo_dir / "docs").glob("install*.md"))][:4]:
        text = readme.read_text(encoding="utf-8", errors="replace")
        for lang, block in code_blocks(text):
            if lang not in ("", "json", "jsonc", "json5") or '"command"' not in block:
                continue
            try:
                doc = jsonc.loads(block)
            except ValueError:
                continue
            for entry in _server_entries(doc):
                launch = _launch_from_entry(repo_dir, entry)
                if launch:
                    launches.append(launch)
    return launches


def code_blocks(markdown: str) -> list[tuple[str, str]]:
    """Fenced code blocks as (language, body), read line by line so fences always pair up."""
    blocks: list[tuple[str, str]] = []
    lang: str | None = None
    fence = ""
    lines: list[str] = []
    for line in markdown.splitlines():
        stripped = line.strip()
        if lang is None:
            match = re.match(r"^(`{3,}|~{3,})\s*([\w+-]*)", stripped)
            if match:
                fence, lang, lines = match.group(1), match.group(2).lower(), []
        elif stripped.startswith(fence) and stripped.strip("`~") == "":
            blocks.append((lang, "\n".join(lines)))
            lang = None
        else:
            lines.append(line)
    return blocks


def _server_entries(doc: object) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    for key in ("mcpServers", "servers", "context_servers"):
        if isinstance(doc.get(key), dict):
            return [v for v in doc[key].values() if isinstance(v, dict)]
    return [doc] if "command" in doc else []


def _launch_from_entry(repo_dir: Path, entry: dict) -> Launch | None:
    command = str(entry.get("command", ""))
    args = [str(a) for a in entry.get("args", []) if isinstance(a, str | int | float)]
    hint = " ".join([command, *args])
    for i, arg in enumerate(args):
        local = _PLACEHOLDER_PREFIX.sub("", arg.replace("\\", "/"))
        if Path(local).suffix not in (*PYTHON_EXT, *JS_EXT):
            continue
        rel = _rel(repo_dir, repo_dir / local)
        if rel:
            kind = "python" if Path(rel).suffix in PYTHON_EXT else "node"
            return Launch(rel, kind, "readme", args[i + 1 :], hint)
    return None


def _from_pyproject(repo_dir: Path, base: Path) -> list[Launch]:
    path = base / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return []
    launches = []
    for script, target in (doc.get("project", {}).get("scripts") or {}).items():
        module = str(target).split(":")[0]
        for folder in (base, base / "src"):
            for candidate in (
                folder / Path(*module.split(".")).with_suffix(".py"),
                folder / Path(*module.split(".")) / "__main__.py",
            ):
                rel = _rel(repo_dir, candidate)
                if rel:
                    launches.append(Launch(rel, "python", "pyproject", hint=f"{script} ({target})", program=script))
    return launches


def _from_package_json(repo_dir: Path, base: Path) -> list[Launch]:
    path = base / "package.json"
    if not path.is_file():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    targets: list[tuple[str, str]] = []
    bins = doc.get("bin")
    if isinstance(bins, str):
        targets.append((str(doc.get("name", "bin")), bins))
    elif isinstance(bins, dict):
        targets += [(str(k), str(v)) for k, v in bins.items()]
        default = str(doc.get("name", "")).split("/")[-1]
        if len(bins) > 1 and default in bins and (doc.get("mcpName") or (base / "server.json").is_file()):
            # The package is listed as an MCP server, and `npx <package>` runs the program named
            # after it. The other programs are helpers (a CLI, a daemon).
            targets = [(default, str(bins[default]))]
    if isinstance(doc.get("main"), str) and not targets:
        # "main" is the library entry. With programs in "bin", those are the servers.
        targets.append(("main", doc["main"]))
    launches = []
    for label, target in targets:
        program = None if label == "main" else label
        rel = _rel(repo_dir, base / target)
        if rel:
            launches.append(Launch(rel, "node", "package.json", hint=label, program=program))
            continue
        # Not built yet. Find the source file it is compiled from, so the code can still be read.
        planned, source = _built_entry(repo_dir, base, target)
        if planned and not source and _has_script(doc, "build"):
            # Made by a bundler (esbuild, rollup) from a file whose name does not match the output.
            source = _bundled_source(repo_dir, base, doc)
        if planned and source:
            launches.append(Launch(planned, "node", "package.json", hint=label, program=program, source=source))
    return launches


TS_SOURCE_EXT = (".ts", ".mts", ".cts", ".tsx")
BUILD_DIRS = ("build", "dist", "lib", "out")
_COMPILED_TO_SOURCE = {".js": (".ts", ".tsx", ".js"), ".mjs": (".mts", ".mjs"), ".cjs": (".cts", ".cjs")}


def _built_entry(repo_dir: Path, base: Path, target: str) -> tuple[str | None, str | None]:
    """For a build output that does not exist yet: (its path in the repository, its source file)."""
    try:
        planned = (base / target).resolve()
        root = repo_dir.resolve()
        if not planned.is_relative_to(root):
            return None, None
        rel = planned.relative_to(base.resolve()).as_posix()
    except (OSError, ValueError):
        return None, None
    out_dir, root_dir = _ts_dirs(base)
    stems: list[str] = []
    for prefix in [d for d in (out_dir, *BUILD_DIRS) if d]:
        if rel.startswith(prefix + "/"):
            rest = rel[len(prefix) + 1 :]
            stems += [f"{root_dir}/{rest}" if root_dir else rest, rest, f"src/{rest}"]
    suffix = PurePosixPath(rel).suffix
    for stem in stems:
        base_name = stem[: -len(suffix)] if suffix else stem
        for ext in _COMPILED_TO_SOURCE.get(suffix, (suffix,)):
            source = _rel(repo_dir, base / f"{base_name}{ext}")
            if source:
                return planned.relative_to(root).as_posix(), source
    return planned.relative_to(root).as_posix(), None


def _has_script(doc: dict, name: str) -> bool:
    scripts = doc.get("scripts")
    return isinstance(scripts, dict) and isinstance(scripts.get(name), str)


# The entry file in a bundler config: esbuild `entryPoints: [...]`, rollup `input: ...`.
_BUNDLER_ENTRY = re.compile(r"\b(?:entryPoints|entry|input)\s*:\s*\[?([^\]\n}]+)")
_STRING = re.compile(r"""['"]([^'"]+\.(?:[cm]?[jt]sx?))['"]""")
# Scripts that start the server from its source while developing.
_DEV_SCRIPTS = ("dev", "start", "start:dev", "serve", "watch")


def _bundled_source(repo_dir: Path, base: Path, doc: dict) -> str | None:
    """The source file a bundler turns into the program, from the build script's config or the dev script."""
    scripts = doc.get("scripts") or {}
    for word in str(scripts.get("build", "")).split():
        config = base / word
        if config.suffix not in (".js", ".mjs", ".cjs", ".ts", ".mts") or not config.is_file():
            continue
        try:
            text = config.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        for match in _BUNDLER_ENTRY.finditer(text):
            for name in _STRING.findall(match.group(1)):
                # Paths are relative to the config file (join(__dirname, ...)) or to the package.
                for folder in (config.parent, base):
                    source = _rel(repo_dir, folder / name)
                    if source:
                        return source
    for key in _DEV_SCRIPTS:
        for word in str(scripts.get(key, "")).split():
            if Path(word).suffix in (*TS_SOURCE_EXT, ".js", ".mjs"):
                source = _rel(repo_dir, base / word)
                if source:
                    return source
    return None


def _ts_dirs(base: Path) -> tuple[str, str]:
    """The compilerOptions outDir and rootDir from tsconfig.json, as clean relative paths."""
    try:
        doc = jsonc.loads((base / "tsconfig.json").read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return "", ""
    options = doc.get("compilerOptions") if isinstance(doc, dict) else None
    if not isinstance(options, dict):
        return "", ""

    def clean(value: object) -> str:
        text = str(value or "").replace("\\", "/").strip().removeprefix("./").strip("/")
        return "" if text in (".", "") else text

    return clean(options.get("outDir")), clean(options.get("rootDir"))


def has_mcp_code(repo_dir: Path, entry: str) -> bool:
    """Does the entry file, or a local file it imports, build an MCP server?"""
    for path in entry_with_local_imports(repo_dir / entry, limit=40, project_root=repo_dir):
        try:
            if MCP_CODE.search(path.read_text(encoding="utf-8", errors="replace")[:300_000]):
                return True
        except OSError:
            continue
    return False


def _from_entry_files(repo_dir: Path, base: Path) -> list[Launch]:
    launches = []
    candidates = [base / name for name in ENTRY_CANDIDATES]
    candidates += sorted(base.glob("src/*/server.py")) + sorted(base.glob("src/*/__main__.py"))
    for path in candidates:
        rel = _rel(repo_dir, path)
        if not rel or any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        if MCP_CODE.search(text):
            launches.append(Launch(rel, "python" if path.suffix in PYTHON_EXT else "node", "entry file"))
    return launches
