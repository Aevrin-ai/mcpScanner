# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Scan options shared by the CLI and skills, and helpers to apply them.

Settings come from the config file. Options are the per-run changes on top
(for example --dynamic). Applying options never changes the original Settings.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from mcp_scanner.config.settings import Settings
from mcp_scanner.models.result import ScanReport
from mcp_scanner.models.severity import Severity
from mcp_scanner.reports import REPORTERS, get_reporter
from mcp_scanner.scanner.engine import report_path


@dataclass
class ScanOptions:
    dynamic: bool | None = None
    call_dangerous_tools: bool | None = None
    ai: bool | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_setup: str | None = None
    min_severity: str | None = None
    fail_on: str | None = None
    formats: list[str] = field(default_factory=list)
    output_dir: str | None = None
    sandbox_mode: str | None = None
    allow_host: bool | None = None
    network: str | None = None
    rules_enabled: list[str] = field(default_factory=list)
    rules_disabled: list[str] = field(default_factory=list)
    source: str | None = None
    pins_file: str | None = None
    timeout: float | None = None
    startup_timeout: float | None = None
    connect: bool | None = None


def apply_options(settings: Settings, options: ScanOptions) -> Settings:
    s = settings.model_copy(deep=True)
    if options.dynamic is not None:
        s.dynamic.enabled = options.dynamic
    if options.call_dangerous_tools is not None:
        s.dynamic.call_dangerous_tools = options.call_dangerous_tools
    if options.ai is not None:
        s.ai.enabled = options.ai
    if options.ai_provider:
        s.ai.provider = options.ai_provider  # type: ignore[assignment]
        s.ai.enabled = True if options.ai is None else options.ai
    if options.ai_model:
        s.ai.model = options.ai_model
    if options.ai_setup:
        if options.ai_setup not in ("auto", "always", "never"):
            raise ValueError(f"Unknown --ai-setup '{options.ai_setup}'. Use auto, always, or never.")
        s.ai.setup = options.ai_setup  # type: ignore[assignment]
    if options.min_severity:
        s.scan.min_severity = Severity.parse(options.min_severity)
    if options.fail_on:
        s.scan.fail_on = (
            None if options.fail_on.lower() in ("none", "never", "off") else Severity.parse(options.fail_on)
        )
    if options.formats:
        unknown = [f for f in options.formats if f not in REPORTERS]
        if unknown:
            raise ValueError(f"Unknown format(s): {', '.join(unknown)}. Use: {', '.join(REPORTERS)}")
        s.output.formats = options.formats  # type: ignore[assignment]
    if options.output_dir:
        s.output.directory = options.output_dir
    if options.sandbox_mode:
        s.sandbox.mode = options.sandbox_mode  # type: ignore[assignment]
    if options.allow_host is not None:
        s.sandbox.allow_host = options.allow_host
    if options.network:
        if options.network not in ("none", "allow", "auto"):
            raise ValueError(f"Unknown --network '{options.network}'. Use none, allow, or auto.")
        s.sandbox.network = options.network  # type: ignore[assignment]
    if options.rules_enabled:
        s.rules.enabled = options.rules_enabled
    if options.rules_disabled:
        s.rules.disabled = [*s.rules.disabled, *options.rules_disabled]
    if options.source:
        s.scan.source_path = options.source
    if options.pins_file:
        s.scan.pins_file = options.pins_file
    if options.connect is not None:
        s.scan.connect = options.connect
    if options.startup_timeout:
        s.timeouts.startup = options.startup_timeout
    if options.timeout:
        s.timeouts.server_total = options.timeout
    return s


def write_reports(report: ScanReport, formats: Sequence[str], directory: str | None) -> list[Path]:
    """Write one file per non-console format. Returns the paths written."""
    written = []
    for name in formats:
        if name == "console":
            continue
        reporter = get_reporter(name)
        path = report_path(directory, report.scan_id, reporter.extension)
        path.write_text(reporter.render(report), encoding="utf-8")
        written.append(path)
    return written
