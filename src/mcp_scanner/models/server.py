# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Models that describe which MCP server to scan."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from mcp_scanner.utils.secrets import mask_args


class TransportType(str, Enum):
    """How we talk to the server."""

    STDIO = "stdio"
    HTTP = "http"  # streamable HTTP
    SSE = "sse"  # older HTTP + server-sent events
    OFFLINE = "offline"  # a tools file, nothing is started


class SetupPlan(BaseModel):
    """How to install and start a repository server, worked out by the AI setup planner.

    Install commands run in the install container (network on, no secrets). The server
    then runs in the locked container, with network only when `needs_network` allows it.
    """

    kind: str  # "python" or "node": picks the sandbox image
    install: list[str] = Field(default_factory=list)  # shell commands, run in /opt/deps/app
    command: str  # the program that starts the server over stdio
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)  # harmless settings only, never secrets
    required_env: list[str] = Field(default_factory=list)  # names of keys the server expects
    needs_network: bool = False  # the tools call an online service
    notes: str = ""
    source: str = "ai"  # "ai", or "cache" when reused from an earlier scan of the same commit


class RepoInfo(BaseModel):
    """A server that comes from a git repository (for example a GitHub link)."""

    url: str  # the link the user gave, for reports
    clone_url: str
    commit: str = ""
    local_dir: str = ""  # where the checkout lives on this machine
    entry: str | None = None  # the server file inside the repository, if found
    kind: str | None = None  # "python" or "node"
    launch_hint: str | None = None  # how the README or manifest says to start it
    program: str | None = None  # the installed program name (pyproject script or npm bin)
    setup: SetupPlan | None = None  # set when the AI setup planner chose how to start it

    def short(self) -> str:
        where = f"{self.url}@{self.commit[:12]}" if self.commit else self.url
        return f"{where} ({self.entry})" if self.entry else where


class ServerSpec(BaseModel):
    """Everything needed to find, start, or connect to one MCP server."""

    name: str
    transport: TransportType
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    tools_file: str | None = None
    source_path: str | None = None
    # Where this server came from, for example a client config file.
    origin: str | None = None
    # "cli" when typed by the user, "config" when read from a config file,
    # "repository" when it came from a git repository link.
    origin_kind: str = "cli"
    # Set for servers that come from a git repository.
    repo: RepoInfo | None = None

    @property
    def is_local_process(self) -> bool:
        return self.transport == TransportType.STDIO

    @property
    def is_remote(self) -> bool:
        return self.transport in (TransportType.HTTP, TransportType.SSE)

    def display_target(self) -> str:
        """A short text that shows what was scanned. It never shows env values."""
        if self.repo is not None:
            return self.repo.short()
        if self.transport == TransportType.STDIO:
            # Keys passed on the command line (--api-key VALUE) are masked.
            return " ".join([self.command or "", *mask_args(self.args)]).strip()
        if self.transport == TransportType.OFFLINE:
            return self.tools_file or "offline"
        return self.url or ""

    def public_summary(self) -> dict[str, object]:
        """Data for reports. Env and header values are hidden on purpose."""
        return {
            "name": self.name,
            "transport": self.transport.value,
            "target": self.display_target(),
            "env_keys": sorted(self.env),
            "header_keys": sorted(self.headers),
            "origin": self.origin,
            "source_path": self.source_path,
            "repository": self.repo.model_dump(exclude={"local_dir"}) if self.repo else None,
        }
