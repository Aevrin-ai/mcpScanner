# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Build a clean environment for a server process.

The server must not see the scanner's own environment. That environment may
hold API keys, cloud tokens, or SSH agent sockets. So we start from an empty
dict and only copy a short list of harmless variables that programs need to run.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from mcp_scanner.config.expand import expand_mapping
from mcp_scanner.config.settings import SandboxSettings
from mcp_scanner.sandbox.canary import CANARY_ENV_NAME, CanarySet
from mcp_scanner.sandbox.workspace import Workspace

# Harmless variables that most programs need to start.
_BASE_ALLOWLIST = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    # Windows needs these to start almost anything.
    "SYSTEMROOT",
    "SystemRoot",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "ProgramData",
    "CommonProgramFiles",
)

# Variables that hold a home or temp folder. With home isolation they point into the workspace.
_HOME_VARS = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME")
_TEMP_VARS = ("TMP", "TEMP", "TMPDIR")


def scanner_cache_dir() -> Path:
    """A shared package cache, so npx and uvx do not download everything on every scan."""
    path = Path.home() / ".aevrin-mcp-scanner" / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_server_env(
    server_env: Mapping[str, str],
    settings: SandboxSettings,
    workspace: Workspace | None,
    canary: CanarySet | None,
    host_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the full environment for the server process."""
    source = os.environ if host_env is None else host_env
    env = {key: source[key] for key in _BASE_ALLOWLIST if key in source}
    if workspace is not None and settings.isolate_home:
        env.update(_isolated_dirs(workspace))
    else:
        env.update({key: source[key] for key in _HOME_VARS + _TEMP_VARS if key in source})
    for name in settings.env_passthrough:
        if name in source:
            env[name] = source[name]
    if canary is not None:
        env[CANARY_ENV_NAME] = canary.env_value
    # The server's own config wins. ${VAR} placeholders are filled from the host env.
    env.update(expand_mapping(server_env, source))
    return env


def _isolated_dirs(workspace: Workspace) -> dict[str, str]:
    home = str(workspace.home)
    tmp = str(workspace.tmp)
    cache = scanner_cache_dir()
    values = {
        "HOME": home,
        "USERPROFILE": home,
        "XDG_CONFIG_HOME": str(workspace.home / ".config"),
        "XDG_CACHE_HOME": str(workspace.home / ".cache"),
        "XDG_DATA_HOME": str(workspace.home / ".local" / "share"),
        "TMP": tmp,
        "TEMP": tmp,
        "TMPDIR": tmp,
        "npm_config_cache": str(cache / "npm"),
        "UV_CACHE_DIR": str(cache / "uv"),
        "PIP_CACHE_DIR": str(cache / "pip"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if sys.platform == "win32":
        values["APPDATA"] = str(workspace.home / "AppData" / "Roaming")
        values["LOCALAPPDATA"] = str(workspace.home / "AppData" / "Local")
        Path(values["APPDATA"]).mkdir(parents=True, exist_ok=True)
        Path(values["LOCALAPPDATA"]).mkdir(parents=True, exist_ok=True)
    return values
