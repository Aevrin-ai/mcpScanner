# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Turn case results into quality numbers.

Two levels:
  - rule level: did each expected rule fire (true positive) or not (false
    negative), and did unexpected serious findings appear (false positive)?
  - server level: was each malicious server flagged as dangerous (detection
    rate), and was any safe server flagged (false positive rate)?
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_scanner.evaluation.runner import CaseResult
from mcp_scanner.models.ai import AIUsage


def _ratio(top: float, bottom: float) -> float | None:
    return round(top / bottom, 4) if bottom else None


@dataclass
class EvalSummary:
    cases: int = 0
    passed: int = 0
    malicious_cases: int = 0
    benign_cases: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    detection_rate: float | None = None
    precision: float | None = None
    recall: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None
    average_confidence: float | None = None
    total_seconds: float = 0.0
    average_seconds: float | None = None
    ai_usage: dict[str, Any] = field(default_factory=dict)


def summarize(results: list[CaseResult]) -> EvalSummary:
    s = EvalSummary(cases=len(results), passed=sum(r.passed for r in results))
    malicious = [r for r in results if r.malicious]
    benign = [r for r in results if not r.malicious]
    s.malicious_cases, s.benign_cases = len(malicious), len(benign)
    s.true_positives = sum(len(r.true_positives) for r in results)
    s.false_positives = sum(len(r.false_positives) for r in results)
    s.false_negatives = sum(len(r.false_negatives) for r in results)
    s.precision = _ratio(s.true_positives, s.true_positives + s.false_positives)
    s.recall = _ratio(s.true_positives, s.true_positives + s.false_negatives)
    s.detection_rate = _ratio(sum(r.flagged for r in malicious), len(malicious))
    s.false_negative_rate = round(1 - s.detection_rate, 4) if s.detection_rate is not None else None
    s.false_positive_rate = _ratio(sum(r.flagged for r in benign), len(benign))
    confidences = [c for r in results for c in r.confidences]
    s.average_confidence = round(sum(confidences) / len(confidences), 3) if confidences else None
    s.total_seconds = round(sum(r.duration_seconds for r in results), 2)
    s.average_seconds = round(s.total_seconds / len(results), 2) if results else None
    usage = AIUsage()
    for r in results:
        usage.add(r.ai_usage)
        usage.provider = usage.provider or r.ai_usage.provider
        usage.model = usage.model or r.ai_usage.model
    s.ai_usage = usage.model_dump()
    return s


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_markdown(summary: EvalSummary, results: list[CaseResult]) -> str:
    lines = [
        "# Aevrin MCP Scanner eval report",
        "",
        f"- Date: {datetime.now(UTC).isoformat(timespec='seconds')}",
        f"- Cases: {summary.cases} ({summary.malicious_cases} malicious, {summary.benign_cases} benign), passed {summary.passed}",
        f"- Detection rate: {_pct(summary.detection_rate)}",
        f"- Precision: {_pct(summary.precision)}",
        f"- Recall: {_pct(summary.recall)}",
        f"- False positive rate: {_pct(summary.false_positive_rate)}",
        f"- False negative rate: {_pct(summary.false_negative_rate)}",
        f"- Average confidence of true positives: {summary.average_confidence if summary.average_confidence is not None else 'n/a'}",
        f"- Run time: {summary.total_seconds}s total, {summary.average_seconds}s per case",
    ]
    usage = summary.ai_usage
    if usage.get("calls"):
        cost = usage.get("estimated_cost_usd")
        lines.append(
            f"- AI: {usage['calls']} calls, {usage['input_tokens']} in / {usage['output_tokens']} out tokens"
            + (f", about ${cost:.4f}" if cost is not None else "")
        )
    lines += [
        "",
        "| Case | Kind | Result | Grade | Missed | False positives | Seconds |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r.name} | {'malicious' if r.malicious else 'benign'} | {'pass' if r.passed else 'FAIL'} | {r.grade} | "
            f"{', '.join(r.false_negatives) or '-'} | {', '.join(r.false_positives) or '-'} | {r.duration_seconds} |"
        )
    failed = [r for r in results if r.problems or r.errors]
    if failed:
        lines += ["", "## Notes", ""]
        for r in failed:
            for text in [*r.problems, *r.errors]:
                lines.append(f"- {r.name}: {text}")
    return "\n".join(lines) + "\n"


def write_eval_report(summary: EvalSummary, results: list[CaseResult], folder: Path) -> tuple[Path, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    json_path = folder / f"eval-{stamp}.json"
    md_path = folder / f"eval-{stamp}.md"
    data: dict[str, Any] = {"summary": asdict(summary), "cases": [asdict(r) for r in results]}
    for case in data["cases"]:
        case["ai_usage"] = (
            case["ai_usage"].model_dump() if hasattr(case["ai_usage"], "model_dump") else case["ai_usage"]
        )
    json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    md_path.write_text(render_markdown(summary, results), encoding="utf-8")
    return json_path, md_path
