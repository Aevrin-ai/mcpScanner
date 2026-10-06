# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Read MCP server lists from the config files of MCP clients.

Different clients use different shapes. We support the common ones:

    {"mcpServers": {...}}                 most desktop clients
    {"servers": {...}}                    VS Code mcp.json
    {"mcp": {"servers": {...}}}           VS Code settings.json
    {"context_servers": {...}}            Zed
    {"projects": {path: {"mcpServers"}}}  per-project lists
    [mcp_servers.name] in TOML            some command line agents

A broken entry is skipped with a warning. One bad server should not hide the others.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from mcp_scanner.core.errors import TargetError
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.utils import jsonc

log = logging.getLogger(__name__)

_SERVER_KEYS = ("mcpServers", "servers", "context_servers", "mcp_servers")
_URL_KEYS = ("url", "serverUrl", "serverURL", "httpUrl", "uri", "endpoint")


def load_config_document(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            return tomllib.loads(text)
        if suffix in (".yaml", ".yml"):
            return yaml.safe_load(text)
        return jsonc.loads(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise TargetError(f"Could not parse MCP config file {path}: {exc}") from exc


def find_server_tables(doc: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Return (name prefix, server table) pairs found anywhere we know to look."""
    tables: list[tuple[str, Any]] = []
    if not isinstance(doc, dict):
        return tables
    for key in _SERVER_KEYS:
        if key in doc:
            tables.append((prefix, doc[key]))
    nested = doc.get("mcp")
    if isinstance(nested, dict):
        tables.extend(find_server_tables(nested, prefix))
    projects = doc.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            label = f"{Path(str(project_path)).name or project_path}/"
            tables.extend(find_server_tables(project, prefix + label))
    return tables


def parse_client_config(path: str | Path) -> list[ServerSpec]:
    """Read every MCP server from one client config file."""
    file_path = Path(path).expanduser()
    doc = load_config_document(file_path)
    specs: list[ServerSpec] = []
    seen: set[str] = set()
    for prefix, table in find_server_tables(doc):
        for name, entry in _iter_entries(table):
            full_name = f"{prefix}{name}"
            if full_name in seen:
                continue
            spec = parse_server_entry(full_name, entry, origin=str(file_path))
            if spec is not None:
                seen.add(full_name)
                specs.append(spec)
    return specs


def _iter_entries(table: Any) -> list[tuple[str, Any]]:
    if isinstance(table, dict):
        return [(str(k), v) for k, v in table.items()]
    if isinstance(table, list):  # some clients use a list with a "name" field
        return [(str(item.get("name", f"server-{i}")), item) for i, item in enumerate(table) if isinstance(item, dict)]
    return []


def parse_server_entry(name: str, entry: Any, *, origin: str | None = None) -> ServerSpec | None:
    """Turn one config entry into a ServerSpec. Returns None when the entry is unusable."""
    if not isinstance(entry, dict):
        log.warning("Skipping MCP server %r in %s: entry is not an object", name, origin)
        return None
    url = next((str(entry[k]) for k in _URL_KEYS if isinstance(entry.get(k), str)), None)
    command, args = _command_and_args(entry)
    env = _string_map(entry.get("env"))
    headers = _string_map(entry.get("headers"))
    common: dict[str, Any] = {"name": name, "env": env, "origin": origin, "origin_kind": "config"}
    if url:
        transport = _remote_transport(entry, url)
        return ServerSpec(transport=transport, url=url, headers=headers, **common)
    if command:
        cwd = entry.get("cwd") if isinstance(entry.get("cwd"), str) else None
        return ServerSpec(transport=TransportType.STDIO, command=command, args=args, cwd=cwd, **common)
    log.warning("Skipping MCP server %r in %s: no command or url", name, origin)
    return None


def _command_and_args(entry: dict[str, Any]) -> tuple[str | None, list[str]]:
    command = entry.get("command")
    args = entry.get("args")
    if isinstance(command, dict):  # Zed style: {"command": {"path": ..., "args": [...]}}
        args = command.get("args", args)
        command = command.get("path")
    if not isinstance(command, str) or not command.strip():
        return None, []
    arg_list = [str(a) for a in args] if isinstance(args, list) else []
    return command.strip(), arg_list


def _remote_transport(entry: dict[str, Any], url: str) -> TransportType:
    declared = str(entry.get("type") or entry.get("transport") or "").lower()
    if declared == "sse":
        return TransportType.SSE
    if declared in ("http", "streamable-http", "streamablehttp", "streamable_http"):
        return TransportType.HTTP
    return TransportType.SSE if urlparse(url).path.rstrip("/").endswith("/sse") else TransportType.HTTP


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in value.items()}
