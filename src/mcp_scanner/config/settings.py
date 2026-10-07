# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Scanner settings. Loaded from YAML, then environment variables, then CLI flags.

API keys are never stored here. They only come from environment variables.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mcp_scanner.models.severity import Severity


class _Strict(BaseModel):
    # Unknown keys are an error. This catches typos like "timout" early.
    model_config = ConfigDict(extra="forbid")


class TimeoutSettings(_Strict):
    startup: float = Field(60.0, gt=0, description="Seconds to wait for the server to start and answer initialize.")
    request: float = Field(30.0, gt=0, description="Seconds to wait for one MCP request.")
    tool_call: float = Field(20.0, gt=0, description="Seconds to wait for one dynamic tool call.")
    server_total: float = Field(1200.0, gt=0, description="Hard limit for one server scan.")
    install: float = Field(
        600.0, gt=0, description="Seconds to install a server before it starts (Docker sandbox, npx, uvx, --run)."
    )


class SandboxSettings(_Strict):
    mode: Literal["auto", "docker", "process"] = "auto"
    allow_host: bool = False
    # "auto": network only when the server needs an online service (see docs/sandboxing.md).
    network: Literal["none", "allow", "auto"] = "none"
    memory_mb: int = Field(1024, ge=64)
    # The install step builds code (npm, tsc, pip). It holds no secrets, so it may use more memory.
    install_memory_mb: int = Field(4096, ge=256)
    max_processes: int = Field(32, ge=1)
    cpu_seconds: int = Field(300, ge=1)
    max_message_mb: int = Field(16, ge=1)
    isolate_home: bool = True
    env_passthrough: list[str] = Field(default_factory=list)
    docker_image: str | None = None
    docker_image_node: str = "node:22-slim"
    docker_image_python: str = "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"
    # Images for the install step of repositories (--run). They match the images above (same Debian and
    # runtime), plus git and compilers, which builds often need (git submodules, native modules).
    docker_install_image_node: str = "node:22"
    docker_install_image_python: str = "ghcr.io/astral-sh/uv:python3.12-bookworm"
    keep_workspace: bool = False


class DynamicSettings(_Strict):
    enabled: bool = False
    call_tools: bool = True
    call_dangerous_tools: bool = False
    max_tool_calls: int = Field(25, ge=0)
    read_prompts: bool = True
    read_resources: bool = True
    max_content_chars: int = Field(100_000, ge=1000)


class RuleSettings(_Strict):
    enabled: list[str] = Field(default_factory=list, description="Empty means all rules.")
    disabled: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    rules_dirs: list[str] = Field(default_factory=list)


class ScanSettings(_Strict):
    min_severity: Severity = Severity.INFO
    fail_on: Severity | None = Severity.HIGH
    source_path: str | None = None
    pins_file: str = "~/.aevrin-mcp-scanner/pins.json"
    # False: never start or contact servers. Only config, source, and dependency checks run.
    connect: bool = True
    online_checks: bool = False
    # When a scan cannot finish or finds no tools, look for a public report from an earlier scan of
    # the same repository or npm package. It is shown apart from this scan's result, never mixed in.
    prescanned_fallback: bool = True
    prescanned_url: str = "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-directory/main/data/reports"

    @field_validator("fail_on", mode="before")
    @classmethod
    def _none_word(cls, value: Any) -> Any:
        return None if isinstance(value, str) and value.lower() in ("none", "never", "off") else value


class AIPricing(_Strict):
    input_per_million: float = Field(ge=0)
    output_per_million: float = Field(ge=0)


class AISettings(_Strict):
    enabled: bool = False
    provider: Literal["openai", "anthropic", "xai", "openrouter", "groq"] | None = None
    model: str | None = None
    timeout: float = Field(60.0, gt=0)
    max_retries: int = Field(2, ge=0)
    max_calls: int = Field(20, ge=0)
    max_input_chars: int = Field(24_000, ge=1000)
    max_output_tokens: int = Field(2000, ge=100)
    review_findings: bool = True
    review_tools: bool = True
    # Let the AI work out how to install and start a repository server (--run):
    # "auto" when automatic setup finds nothing or fails, "always" for every repository, "never" to turn it off.
    setup: Literal["auto", "always", "never"] = "auto"
    pricing: AIPricing | None = None


ReportFormat = Literal["console", "json", "markdown", "sarif"]


def _default_formats() -> list[ReportFormat]:
    return ["console"]


class OutputSettings(_Strict):
    formats: list[ReportFormat] = Field(default_factory=_default_formats)
    directory: str | None = None
    show_evidence: bool = True


class LoggingSettings(_Strict):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "WARNING"
    json_format: bool = False
    file: str | None = None


class EvalSettings(_Strict):
    root: str = "src/evals"
    reports_dir: str = "src/evals/reports"


class Suppression(_Strict):
    """Tell the scanner to ignore one known finding. A reason is required."""

    rule_id: str
    reason: str = Field(min_length=3)
    server: str = "*"
    target: str = "*"
    expires: date | None = None


class Settings(_Strict):
    servers: dict[str, dict[str, Any]] = Field(default_factory=dict)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    rules: RuleSettings = Field(default_factory=RuleSettings)
    timeouts: TimeoutSettings = Field(default_factory=TimeoutSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    dynamic: DynamicSettings = Field(default_factory=DynamicSettings)
    ai: AISettings = Field(default_factory=AISettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    evals: EvalSettings = Field(default_factory=EvalSettings)
    suppressions: list[Suppression] = Field(default_factory=list)
