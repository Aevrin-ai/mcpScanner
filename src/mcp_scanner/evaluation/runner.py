# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Run eval cases through the real scan engine and score the results."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.core.errors import ScannerError
from mcp_scanner.evaluation.cases import GRADE_ORDER, EvalCase
from mcp_scanner.models.ai import AIUsage
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.severity import Confidence, Severity
from mcp_scanner.rules.registry import id_matches
from mcp_scanner.sandbox.launcher import HostConfirm
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest

CONFIDENCE_VALUE = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.3}


@dataclass
class CaseResult:
    name: str
    malicious: bool
    passed: bool = False
    grade: str = "?"
    score: float = 0.0
    found_rules: list[str] = field(default_factory=list)
    true_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    flagged: bool = False
    confidences: list[float] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    status: str = "failed"
    duration_seconds: float = 0.0
    ai_usage: AIUsage = field(default_factory=AIUsage)


def is_flagged(findings: list[Finding], grade: str) -> bool:
    """Would a user see this server as dangerous?"""
    strong = [f for f in findings if f.severity.at_least(Severity.HIGH) and f.confidence != Confidence.LOW]
    return grade in ("D", "F") or bool(strong)


def judge(case: EvalCase, findings: list[Finding], grade: str) -> CaseResult:
    result = CaseResult(name=case.name, malicious=case.malicious, grade=grade)
    active = [f for f in findings if f.counts_for_risk]
    result.found_rules = sorted({f.rule_id for f in active})
    expect = case.expect
    for wanted in expect.must_find:
        hits = [f for f in active if id_matches(f.rule_id, [wanted])]
        if hits:
            result.true_positives.append(wanted)
            result.confidences.append(max(CONFIDENCE_VALUE[f.confidence] for f in hits))
        else:
            result.false_negatives.append(wanted)
    for unwanted in expect.must_not_find:
        result.false_positives += [
            f"{f.rule_id} on {f.target_name}" for f in active if id_matches(f.rule_id, [unwanted])
        ]
    if not case.malicious:
        for f in active:
            serious = f.severity.at_least(Severity.MEDIUM) and f.confidence != Confidence.LOW
            allowed = id_matches(f.rule_id, expect.allow) or id_matches(f.rule_id, expect.must_find)
            label = f"{f.rule_id} on {f.target_name}"
            if serious and not allowed and label not in result.false_positives:
                result.false_positives.append(label)
    rank = GRADE_ORDER.get(grade)
    if expect.min_grade and (rank is None or rank < GRADE_ORDER[expect.min_grade]):
        result.problems.append(f"grade {grade} is better than the expected minimum {expect.min_grade}")
    if expect.max_grade and (rank is None or rank > GRADE_ORDER[expect.max_grade]):
        result.problems.append(f"grade {grade} is worse than the expected maximum {expect.max_grade}")
    result.flagged = is_flagged(active, grade)
    result.passed = not (result.false_negatives or result.false_positives or result.problems)
    return result


class EvalRunner:
    def __init__(
        self,
        settings: Settings,
        engine_factory: Callable[[Settings], ScanEngine],
        host_confirm: HostConfirm | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.engine_factory = engine_factory
        self.host_confirm = host_confirm
        self.progress = progress

    def run_case(self, case: EvalCase) -> CaseResult:
        settings = self.settings.model_copy(deep=True)
        settings.dynamic.enabled = case.dynamic
        settings.scan.connect = case.connect
        settings.scan.min_severity = Severity.INFO
        settings.scan.source_path = case.source
        start = time.perf_counter()
        if self.progress:
            self.progress(f"eval case {case.name}")
        request = ScanRequest(
            target=TargetRequest(target=case.target, source_path=case.source, name=case.name),
            host_confirm=self.host_confirm,
            use_pins=False,
        )
        try:
            report = self.engine_factory(settings).run(request)
        except ScannerError as exc:
            failed = CaseResult(name=case.name, malicious=case.malicious, errors=[str(exc)])
            failed.false_negatives = list(case.expect.must_find)
            failed.duration_seconds = round(time.perf_counter() - start, 3)
            return failed
        # A config file case can hold many servers. Judge them together, with the worst grade.
        findings = [f for server in report.servers for f in server.findings]
        worst = max(report.servers, key=lambda s: (GRADE_ORDER.get(s.risk.grade, -1), s.risk.score))
        result = judge(case, findings, worst.risk.grade)
        result.score = worst.risk.score
        result.status = report.status.value
        result.errors = [f"{e.stage}: {e.message}" for s in report.servers for e in s.errors if e.stage != "source"]
        result.ai_usage = report.ai_usage
        if report.status.value == "failed":
            result.passed = False
        result.duration_seconds = round(time.perf_counter() - start, 3)
        return result

    def run(self, cases: list[EvalCase]) -> list[CaseResult]:
        return [self.run_case(case) for case in cases]
