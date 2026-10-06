# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Facts that source code analysis produces."""

from __future__ import annotations

from dataclasses import dataclass, field

# Hit categories. Rules look these up by name.
COMMAND = "command"
CODE_EVAL = "code-eval"
OBFUSCATED_EXEC = "obfuscated-exec"
DESERIALIZATION = "deserialization"
FILE_READ = "file-read"
FILE_WRITE = "file-write"
NETWORK = "network"
SQL = "sql"
TEMPLATE = "template"
SENSITIVE_PATH = "sensitive-path"
ENV_DUMP = "env-dump"
EXFIL_ENDPOINT = "exfil-endpoint"
REVERSE_SHELL = "reverse-shell"
PERSISTENCE = "persistence"
SECRET = "secret"


@dataclass
class ToolFunction:
    """A function that the MCP server exposes as a tool, prompt, or resource."""

    name: str  # the name the agent sees
    function: str  # the code name
    file: str
    line: int
    kind: str = "tool"


@dataclass
class CodeHit:
    category: str
    file: str
    line: int
    snippet: str
    language: str
    function: str | None = None
    tool: str | None = None  # the MCP tool this code runs for, when known
    tainted: bool = False  # tool input reaches this call
    tainted_params: list[str] = field(default_factory=list)
    detail: str = ""
    sanitized: bool = False
    # A short fact about the hit that rules may use, for example "marked public" for a key
    # that a comment says is public on purpose.
    note: str = ""

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class SourceFacts:
    root: str
    files_scanned: list[str] = field(default_factory=list)
    tool_functions: list[ToolFunction] = field(default_factory=list)
    hits: list[CodeHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    mcp_detected: bool = False
    # Minified or bundled files: only checked for secrets, not for code patterns.
    minified_files: list[str] = field(default_factory=list)
    # Environment variables the code reads by name (process.env.X, os.getenv("X")), in order of first use.
    env_reads: list[str] = field(default_factory=list)

    def hits_for(self, *categories: str) -> list[CodeHit]:
        wanted = set(categories)
        return [h for h in self.hits if h.category in wanted]

    def tool_hits(self, tool: str) -> list[CodeHit]:
        return [h for h in self.hits if h.tool == tool]

    def same_function(self, hit: CodeHit, category: str) -> bool:
        """True when the same function also has a hit of another category."""
        return any(
            h.category == category and h.file == hit.file and h.function == hit.function and h.function
            for h in self.hits
        )
