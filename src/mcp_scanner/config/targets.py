# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Turn what the user typed into a list of servers to scan."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from mcp_scanner.analyzers.source import source_files
from mcp_scanner.analyzers.source.inventory import extract_inventory
from mcp_scanner.analyzers.source.other_languages import extract_other_languages
from mcp_scanner.analyzers.source.walker import JS_EXT, PYTHON_EXT, SKIP_DIRS, walk_folder
from mcp_scanner.config.discovery import existing_configs
from mcp_scanner.config.mcp_config import parse_client_config, parse_server_entry
from mcp_scanner.config.repository import Launch, cache_root, fetch_repo, find_launches, parse_repo_url
from mcp_scanner.config.settings import Settings
from mcp_scanner.core.errors import TargetError
from mcp_scanner.models.mcp import ToolInfo
from mcp_scanner.models.server import RepoInfo, ServerSpec, TransportType
from mcp_scanner.utils import jsonc
from mcp_scanner.utils.secrets import mask_args

log = logging.getLogger(__name__)
# Code that builds an MCP server object.
SERVER_CONSTRUCTOR = re.compile(r"\b(?:new\s+(?:McpServer|Server)\s*\(|(?:FastMCP|MCPServer)\s*\()")


@dataclass
class TargetRequest:
    """The raw target options from the CLI or a skill."""

    target: str | None = None
    discover: bool = False
    server_names: list[str] = field(default_factory=list)
    transport: str | None = None  # force "http" or "sse" for URLs
    extra_env: dict[str, str] = field(default_factory=dict)
    extra_headers: dict[str, str] = field(default_factory=dict)
    source_path: str | None = None
    name: str | None = None
    # For repository links and local folders: start the server (inside Docker) instead of
    # only reading its code.
    run: bool = False
    # Set by the engine when the AI setup planner can work out a start command that
    # automatic setup could not find.
    ai_setup: bool = False


def resolve_targets(request: TargetRequest, settings: Settings) -> list[ServerSpec]:
    """Find every server to scan. Raises TargetError when nothing usable is found."""
    specs = _collect(request, settings)
    if request.server_names:
        wanted = set(request.server_names)
        specs = [s for s in specs if s.name in wanted or s.name.split("/")[-1] in wanted]
        if not specs:
            raise TargetError(f"No server named {', '.join(sorted(wanted))} was found")
    if not specs:
        raise TargetError("Nothing to scan. Give a command, URL, config file, or tools file.")
    source = request.source_path or settings.scan.source_path
    return [_apply_overrides(s, request, source) for s in specs]


def _collect(request: TargetRequest, settings: Settings) -> list[ServerSpec]:
    if request.discover:
        return _discover_all()
    if request.target:
        return _from_target(request.target, request)
    if settings.servers:
        return _from_settings(settings)
    return []


def _discover_all() -> list[ServerSpec]:
    specs: list[ServerSpec] = []
    for known in existing_configs():
        try:
            for spec in parse_client_config(known.path):
                spec.name = f"{known.client}:{spec.name}"
                specs.append(spec)
        except TargetError as exc:
            log.warning("Skipping %s: %s", known.path, exc)
    return specs


def _from_settings(settings: Settings) -> list[ServerSpec]:
    specs = []
    for name, entry in settings.servers.items():
        spec = parse_server_entry(name, entry, origin="scanner config")
        if spec:
            specs.append(spec)
    return specs


def _from_target(target: str, request: TargetRequest) -> list[ServerSpec]:
    text = target.strip()
    repo = parse_repo_url(text)
    if repo is not None:
        repo_dir, commit = fetch_repo(repo)
        return repository_specs(repo_dir, commit, repo.url, repo.clone_url, repo.subdir, request)
    if text.lower().startswith(("http://", "https://")):
        return [_url_spec(text, request)]
    path = Path(text).expanduser()
    if path.is_file():
        return _from_file(path)
    if path.is_dir():
        # A local folder, for example a repository you already cloned.
        return repository_specs(path.resolve(), "", str(path.resolve()), str(path.resolve()), None, request)
    return [_command_spec(text, request)]


def repository_specs(
    repo_dir: Path, commit: str, url: str, clone_url: str, subdir: str | None, request: TargetRequest
) -> list[ServerSpec]:
    """One spec per server found in the repository.

    Without `run`, the server is read, not started: its tools come straight from the
    source code. With `run`, it is installed and started inside the Docker sandbox.
    """
    launches = find_launches(repo_dir, subdir)
    folder = repo_dir / subdir if subdir else repo_dir
    if not launches:
        if request.run and request.ai_setup:
            # The AI setup planner works out how to start it, before the server is launched.
            launches = [Launch(entry="", kind="", found_by="ai-setup")]
        elif request.run:
            raise TargetError(
                f"Could not find how to start the server in {url}. Scan it without --run, "
                "or give the start command yourself."
            )
        launches = [Launch(entry="", kind="", found_by="none")]
    repo_name = Path(clone_url.rstrip("/")).name.removesuffix(".git") or repo_dir.name
    specs = []
    for launch in launches:
        # Code checks read the source file. A build output (build/index.js) may not exist yet.
        code = launch.source or launch.entry
        entry = repo_dir / code if code else folder
        label = request.name or repo_name
        if len(launches) > 1:
            label = f"{label}:{Path(launch.entry).stem}"
        info = RepoInfo(
            url=url,
            clone_url=clone_url,
            commit=commit,
            local_dir=str(repo_dir),
            entry=launch.entry or None,
            kind=launch.kind or None,
            launch_hint=launch.hint or None,
            program=launch.program,
        )
        common: dict[str, Any] = {
            "name": label,
            "source_path": str(entry),
            "repo": info,
            "origin": url,
            "origin_kind": "repository",
        }
        if request.run:
            # The command picks the sandbox image. The real start command comes from the install step.
            command = "python" if launch.kind == "python" else "node"
            specs.append(
                ServerSpec(
                    transport=TransportType.STDIO,
                    command=command,
                    args=[launch.entry, *launch.args] if launch.entry else [],
                    cwd=str(repo_dir),
                    **common,
                )
            )
        else:
            tools_file, used, _ = write_static_inventory(entry, repo_dir)
            common["source_path"] = str(used)
            specs.append(ServerSpec(transport=TransportType.OFFLINE, tools_file=str(tools_file), **common))
    return specs


def server_files(entry: Path, repo_dir: Path) -> list[Path]:
    """Files that create an MCP server, in the same language as the entry.

    Launcher scripts often load the real server through a computed path, which import
    following cannot see. Then we look for the files that build the server.
    """
    exts = PYTHON_EXT if entry.suffix in PYTHON_EXT else JS_EXT
    found = []
    for path in walk_folder(repo_dir):
        if path.suffix not in exts:
            continue
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:300_000]
        except OSError:
            continue
        if SERVER_CONSTRUCTOR.search(head):
            found.append(path)
    return found[:5]


# Tool manifests some repositories ship, checked in this order before searching every JSON file.
MANIFEST_PATHS = (
    "tools.json",
    "mcp.json",
    "server.json",
    "testdata/tools.json",
    ".mcp/tools.json",
    "src/tools.json",
    "src/mcp.json",
    "test/tools.json",
    "tools/tools.json",
)
MANIFEST_SKIP = ("package.json", "package-lock.json", "tsconfig")
MAX_MANIFEST_FILES = 3000
MAX_MANIFEST_BYTES = 2_000_000


def manifest_tools(repo_dir: Path) -> tuple[Path, list[dict[str, Any]]] | None:
    """A tools list shipped as JSON in the repository: known manifest names first, then any JSON file."""
    candidates = [repo_dir / rel for rel in MANIFEST_PATHS]
    others: list[Path] = []
    for path in sorted(repo_dir.rglob("*.json")):
        if len(others) >= MAX_MANIFEST_FILES:
            break
        rel = path.relative_to(repo_dir)
        if any(part in SKIP_DIRS for part in rel.parts) or path.name.startswith(MANIFEST_SKIP):
            continue
        others.append(path)
    for path in [*candidates, *others]:
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_MANIFEST_BYTES:
                continue
            doc = jsonc.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        inner = doc.get("result", doc) if isinstance(doc, dict) else None
        tools = inner.get("tools") if isinstance(inner, dict) else None
        if (
            isinstance(tools, list)
            and tools
            and all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in tools)
        ):
            return path, tools
    return None


def write_static_inventory(entry: Path, repo_dir: Path) -> tuple[Path, Path, str]:
    """Read tools without running anything, and save them as a tools file the offline scan can load.

    In order: the source code (Python and JavaScript), a tools manifest the repository ships
    (tools.json and similar), then Go and Rust code. Returns (tools file, where the tools came
    from, how they were found).
    """
    files, _ = source_files(entry, repo_dir)
    inventory = extract_inventory(files)
    found_by = "source code"
    if not inventory.tools and entry.is_file():
        for candidate in server_files(entry, repo_dir):
            more, _ = source_files(candidate, repo_dir)
            found = extract_inventory(more)
            if found.tools:
                inventory, entry = found, candidate
                break
    if not inventory.tools:
        manifest = manifest_tools(repo_dir)
        if manifest is not None:
            path, tools = manifest
            inventory.tools = [ToolInfo.from_wire(t) for t in tools]
            entry, found_by = path, f"the tools file {path.relative_to(repo_dir).as_posix()}"
    if not inventory.tools:
        inventory.tools = extract_other_languages(repo_dir)
        if inventory.tools:
            found_by = "Go or Rust source code"
    key = hashlib.sha256(str(entry.resolve()).encode()).hexdigest()[:16]
    out = cache_root() / "inventories" / f"{key}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "serverInfo": {"name": inventory.server_name or entry.stem},
        "instructions": inventory.instructions,
        "tools": [
            t.raw or {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
            for t in inventory.tools
        ],
        "prompts": [p.model_dump(exclude={"rendered_text"}) for p in inventory.prompts],
        "resources": [{"uri": r.uri, "name": r.name, "description": r.description} for r in inventory.resources],
    }
    out.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return out, entry, found_by


def _url_spec(url: str, request: TargetRequest) -> ServerSpec:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise TargetError(f"Invalid URL: {url}")
    if request.transport == "sse" or (request.transport is None and parsed.path.rstrip("/").endswith("/sse")):
        transport = TransportType.SSE
    else:
        transport = TransportType.HTTP
    return ServerSpec(name=request.name or parsed.hostname, transport=transport, url=url)


def _from_file(path: Path) -> list[ServerSpec]:
    """A file can be an offline tools list or an MCP client config."""
    doc = _read_any(path)
    if looks_like_tools_file(doc):
        return [ServerSpec(name=path.stem, transport=TransportType.OFFLINE, tools_file=str(path))]
    specs = parse_client_config(path)
    if not specs:
        raise TargetError(f"{path} has no MCP servers and no tools list")
    return specs


def _read_any(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(text)
        if path.suffix.lower() == ".toml":
            return None
        return jsonc.loads(text)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None


def looks_like_tools_file(doc: Any) -> bool:
    if isinstance(doc, list):
        return all(isinstance(t, dict) and "name" in t for t in doc) and bool(doc)
    if isinstance(doc, dict):
        inner = doc.get("result", doc)
        return isinstance(inner, dict) and isinstance(inner.get("tools"), list)
    return False


def split_command(command: str) -> list[str]:
    """Split a command line into parts. Windows paths keep their backslashes."""
    if os.name == "nt":
        parts = shlex.split(command, posix=False)
        return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]
    return shlex.split(command)


def _command_spec(command: str, request: TargetRequest) -> ServerSpec:
    try:
        parts = split_command(command)
    except ValueError as exc:
        raise TargetError(f"Could not read the command: {exc}") from exc
    if not parts:
        raise TargetError("The command is empty")
    name = request.name or _guess_name(parts)
    return ServerSpec(name=name, transport=TransportType.STDIO, command=parts[0], args=parts[1:])


def _guess_name(parts: list[str]) -> str:
    """Pick a friendly name, for example the npm package or script name."""
    shown = mask_args(parts)
    for part, safe in zip(reversed(parts), reversed(shown), strict=True):
        if part.startswith("-") or part != safe:
            continue  # a flag, or a key that must not become the name
        base = Path(part).name
        if base and base.lower() not in ("npx", "uvx", "node", "python", "python3", "uv", "run"):
            return re.split(r"[=<>!~@]", base)[0] or base
    return Path(parts[0]).name


def _apply_overrides(spec: ServerSpec, request: TargetRequest, source: str | None) -> ServerSpec:
    updates: dict[str, Any] = {}
    if request.extra_env:
        updates["env"] = {**spec.env, **request.extra_env}
    if request.extra_headers:
        updates["headers"] = {**spec.headers, **request.extra_headers}
    if source and not spec.source_path:
        updates["source_path"] = source
    return spec.model_copy(update=updates) if updates else spec
