# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Check a ServerSpec before anything runs, so problems get a clear message."""

from __future__ import annotations

import shutil
from pathlib import Path
from urllib.parse import urlparse

from mcp_scanner.config.settings import Settings
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.sandbox import docker


def validate_spec(spec: ServerSpec, settings: Settings) -> list[str]:
    """Return a list of problems. An empty list means the spec looks usable."""
    if spec.transport == TransportType.OFFLINE:
        if not spec.tools_file or not Path(spec.tools_file).is_file():
            return [f"Tools file not found: {spec.tools_file}"]
        return []
    if spec.is_remote:
        return _check_url(spec.url or "")
    return _check_command(spec, settings)


def _check_url(url: str) -> list[str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return [f"URL must start with http:// or https:// (got '{url}')"]
    if not parsed.hostname:
        return [f"URL has no host name: '{url}'"]
    return []


def _check_command(spec: ServerSpec, settings: Settings) -> list[str]:
    problems = []
    if not spec.command:
        return [f"Server '{spec.name}' has no command"]
    if spec.cwd and not Path(spec.cwd).expanduser().is_dir():
        problems.append(f"Working folder not found: {spec.cwd}")
    uses_docker = settings.sandbox.mode == "docker" or (
        settings.sandbox.mode == "auto"
        and docker.supports_command(spec.command, settings.sandbox)
        and docker.docker_available()
    )
    if not uses_docker and shutil.which(spec.command) is None and not Path(spec.command).is_file():
        problems.append(f"Command not found: '{spec.command}'. Is it installed and on PATH?")
    return problems
