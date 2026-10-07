# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Find MCP client config files on this computer.

We only read these files. We never change them.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KnownConfig:
    client: str
    path: Path

    @property
    def exists(self) -> bool:
        return self.path.is_file()


def _app_data_dir() -> Path:
    """The folder where desktop apps keep user settings on this OS."""
    home = Path.home()
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    if sys.platform == "darwin":
        return home / "Library" / "Application Support"
    return Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))


def known_config_paths(project_dir: Path | None = None) -> list[KnownConfig]:
    """All places where popular MCP clients keep their server lists."""
    home = Path.home()
    app = _app_data_dir()
    project = project_dir or Path.cwd()
    vscode_user = [app / "Code" / "User", app / "Code - Insiders" / "User"]
    entries: list[tuple[str, Path]] = [
        ("Claude Desktop", app / "Claude" / "claude_desktop_config.json"),
        ("Claude Code", home / ".claude.json"),
        ("Claude Code (project)", project / ".mcp.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("Cursor (project)", project / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Gemini CLI", home / ".gemini" / "settings.json"),
        ("Gemini CLI (project)", project / ".gemini" / "settings.json"),
        ("Codex CLI", home / ".codex" / "config.toml"),
        (
            "Zed",
            app / "Zed" / "settings.json" if sys.platform == "win32" else home / ".config" / "zed" / "settings.json",
        ),
        ("LM Studio", home / ".lmstudio" / "mcp.json"),
        ("Kiro", home / ".kiro" / "settings" / "mcp.json"),
        ("Amazon Q", home / ".aws" / "amazonq" / "mcp.json"),
        ("VS Code (project)", project / ".vscode" / "mcp.json"),
    ]
    for user_dir in vscode_user:
        label = "VS Code Insiders" if "Insiders" in str(user_dir) else "VS Code"
        entries.append((label, user_dir / "mcp.json"))
        entries.append((label, user_dir / "settings.json"))
        cline = user_dir / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"
        entries.append(("Cline", cline))
    seen: set[Path] = set()
    result = []
    for client, path in entries:
        if path not in seen:
            seen.add(path)
            result.append(KnownConfig(client, path))
    return result


def existing_configs(project_dir: Path | None = None) -> list[KnownConfig]:
    return [c for c in known_config_paths(project_dir) if c.exists]
