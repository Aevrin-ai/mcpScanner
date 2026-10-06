# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Load settings from a YAML file and environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_scanner.config.settings import Settings
from mcp_scanner.core.errors import ConfigError

DEFAULT_CONFIG_NAMES = ("mcp-scanner.yaml", "mcp-scanner.yml", ".mcp-scanner.yaml")

# Environment variable -> (section, key). Only simple, non-secret settings.
_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "AEVRIN_AI_ENABLED": ("ai", "enabled"),
    "AEVRIN_AI_PROVIDER": ("ai", "provider"),
    "AEVRIN_AI_MODEL": ("ai", "model"),
    "AEVRIN_AI_SETUP": ("ai", "setup"),
    "AEVRIN_SANDBOX_MODE": ("sandbox", "mode"),
    "AEVRIN_SANDBOX_ALLOW_HOST": ("sandbox", "allow_host"),
    "AEVRIN_SANDBOX_NETWORK": ("sandbox", "network"),
    "AEVRIN_LOG_LEVEL": ("logging", "level"),
    "AEVRIN_OUTPUT_DIR": ("output", "directory"),
    "AEVRIN_PINS_FILE": ("scan", "pins_file"),
}


def find_default_config(cwd: Path | None = None) -> Path | None:
    """Look for a config file next to where the user runs the scanner."""
    env_path = os.environ.get("AEVRIN_CONFIG")
    if env_path:
        return Path(env_path)
    base = cwd or Path.cwd()
    for name in DEFAULT_CONFIG_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a mapping at the top level")
    return data


def apply_env_overrides(data: dict[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    for var, (section, key) in _ENV_OVERRIDES.items():
        value = env.get(var)
        if value is None or value.strip() == "":
            continue
        data.setdefault(section, {})
        data[section][key] = value.strip()
    return data


def load_settings(
    path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    use_default_file: bool = True,
) -> Settings:
    """Build Settings. Order: defaults, then the file, then environment variables."""
    source_env = os.environ if env is None else env
    config_path = Path(path) if path else (find_default_config() if use_default_file else None)
    data = read_yaml(config_path) if config_path else {}
    data = apply_env_overrides(data, source_env)
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        where = f" in {config_path}" if config_path else ""
        raise ConfigError(f"Invalid settings{where}:\n{_short_errors(exc)}") from exc


def _short_errors(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)
