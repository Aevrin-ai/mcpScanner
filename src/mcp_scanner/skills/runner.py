# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Run a skill's workflow through the normal scan engine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_scanner.config.discovery import existing_configs
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.core.errors import SkillError
from mcp_scanner.models.result import ScanReport
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest, exit_code
from mcp_scanner.scanner.options import ScanOptions, apply_options, write_reports
from mcp_scanner.skills.loader import Skill, interpolate, resolve_inputs

# Called with (step label, text) so the caller decides how to show progress.
Output = Callable[[str, str], None]
# Builds an engine for the given settings. The CLI passes one that adds AI review.
EngineFactory = Callable[[Settings], ScanEngine]


@dataclass
class SkillRunResult:
    reports: list[ScanReport] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    exit_code: int = 0


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v) for v in value]


def _as_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class SkillRunner:
    def __init__(
        self,
        settings: Settings,
        engine_factory: EngineFactory,
        output: Output,
        base_request: ScanRequest | None = None,
    ) -> None:
        self.settings = settings
        self.engine_factory = engine_factory
        self.output = output
        self.base_request = base_request or ScanRequest()

    def run(self, skill: Skill, given: dict[str, str]) -> SkillRunResult:
        if skill.problems:
            raise SkillError(f"Skill '{skill.name}' is not valid: " + "; ".join(skill.problems))
        inputs = resolve_inputs(skill, given)
        result = SkillRunResult()
        for index, step in enumerate(skill.meta.workflow, start=1):
            options = interpolate(step.with_, inputs)
            label = step.name or f"step {index}: {step.action}"
            self.output(label, "")
            handler = getattr(self, f"_{step.action}")
            handler(options, result, label)
        return result

    # ---- actions ------------------------------------------------------------

    def _scan(self, options: dict[str, Any], result: SkillRunResult, label: str, *, inspect: bool = False) -> None:
        scan_options = ScanOptions(
            dynamic=False if inspect else _as_bool(options.get("dynamic")),
            ai=False if inspect else _as_bool(options.get("ai")),
            ai_provider=options.get("ai_provider") or None,
            ai_model=options.get("ai_model") or None,
            min_severity=options.get("min_severity") or None,
            fail_on=options.get("fail_on") or None,
            formats=_as_list(options.get("formats")),
            output_dir=options.get("output") or None,
            rules_enabled=[] if inspect else _as_list(options.get("rules")),
            rules_disabled=_as_list(options.get("disable_rules")),
            source=options.get("source") or None,
        )
        settings = apply_options(self.settings, scan_options)
        if inspect:
            settings.rules.enabled = []
            settings.rules.disabled = ["*"]
        target = TargetRequest(
            target=options.get("target") or None,
            discover=bool(_as_bool(options.get("discover"))),
            server_names=_as_list(options.get("server")),
            transport=options.get("transport") or None,
        )
        request = ScanRequest(
            target=target,
            rules_dirs=self.base_request.rules_dirs,
            host_confirm=self.base_request.host_confirm,
            use_pins=self.base_request.use_pins and not inspect,
            progress=lambda message: self.output(label, message),
        )
        report = self.engine_factory(settings).run(request)
        result.reports.append(report)
        if not inspect:
            result.files += write_reports(report, settings.output.formats, settings.output.directory)
            result.exit_code = max(result.exit_code, exit_code(report, settings.scan.fail_on))

    def _inspect(self, options: dict[str, Any], result: SkillRunResult, label: str) -> None:
        self._scan(options, result, label, inspect=True)

    def _discover(self, options: dict[str, Any], result: SkillRunResult, label: str) -> None:
        configs = existing_configs()
        if not configs:
            self.output(label, "No MCP client config files found.")
        for known in configs:
            self.output(label, f"{known.client}: {known.path}")

    def _report(self, options: dict[str, Any], result: SkillRunResult, label: str) -> None:
        if not result.reports:
            raise SkillError("The report step needs a scan step before it")
        formats = _as_list(options.get("formats")) or ["markdown"]
        for report in result.reports:
            result.files += write_reports(report, formats, options.get("output") or self.settings.output.directory)
