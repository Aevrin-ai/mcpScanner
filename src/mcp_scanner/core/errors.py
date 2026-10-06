# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Exceptions used across the scanner.

Messages in these errors are shown to users. Never put secrets in them.
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for all scanner errors."""


class ConfigError(ScannerError):
    """The settings or a config file is wrong."""


class TargetError(ScannerError):
    """We could not understand what the user wants to scan."""


class SandboxError(ScannerError):
    """The sandbox could not start or control the server."""

    # Output of a failed install step, for the AI setup retry. Never shown in full in reports.
    log: str = ""


class HostExecutionNotAllowed(SandboxError):
    """The user did not allow running the server on this machine."""


class MCPError(ScannerError):
    """Base class for MCP protocol problems."""


class MCPConnectionError(MCPError):
    """We could not connect to the server, or the connection broke."""


class MCPTimeoutError(MCPError):
    """The server did not answer in time."""


class MCPProtocolError(MCPError):
    """The server sent something that breaks the MCP rules."""


class MCPRemoteError(MCPError):
    """The server answered with a JSON-RPC error."""

    def __init__(self, code: int, message: str, method: str | None = None) -> None:
        self.code = code
        self.remote_message = message
        self.method = method
        super().__init__(f"Server error {code} for {method or 'request'}: {message[:200]}")

    @property
    def is_method_not_found(self) -> bool:
        return self.code == -32601


class MCPAuthError(MCPConnectionError):
    """The server said we are not allowed in (HTTP 401 or 403)."""


class AIProviderError(ScannerError):
    """An AI provider call failed."""


class SkillError(ScannerError):
    """A skill is invalid or could not run."""
