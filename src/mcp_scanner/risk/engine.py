# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Give each finding risk points and each server a score and a grade.

    points = severity points x confidence factor

The first finding of a rule counts in full. Repeats of the same rule count a quarter,
and all findings of one rule together add at most 1.5 times the top one, so one rule
firing on 30 file tools does not drown out everything else.
The server score is the sum, capped at 100.

"Possible" findings (low confidence) score 0. They are shown, but they do not move the grade.
Grade F needs strong evidence: at least one validated or confirmed high or critical
finding. Heuristic findings alone stop at D.
A confirmed malicious finding forces grade F.

The score is a sorting aid, not a scientific measure. Every point is listed in the report.
"""

from __future__ import annotations

from mcp_scanner.models.finding import Finding
from mcp_scanner.models.result import ScanStatus
from mcp_scanner.models.risk import RiskFactor, RiskScore
from mcp_scanner.models.severity import Confidence, Severity, ValidationStatus

SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}
CONFIDENCE_FACTOR: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.0,
}
REPEAT_FACTOR = 0.25
# All findings of one rule together add at most this times its top finding.
RULE_CAP = 1.5
# Grade F starts here, see GRADES.
F_THRESHOLD = 60.0
MAX_SCORE = 100.0
# (score below this, grade, label). Checked in order.
GRADES: tuple[tuple[float, str, str], ...] = (
    (0.001, "A", "No known risk"),
    (15.0, "B", "Low risk"),
    (35.0, "C", "Moderate risk"),
    (60.0, "D", "High risk"),
    (float("inf"), "F", "Critical risk"),
)


def grade_for(score: float) -> tuple[str, str]:
    for limit, grade, label in GRADES:
        if score < limit:
            return grade, label
    return "F", "Critical risk"


def finding_points(finding: Finding, repeat: bool) -> tuple[float, str]:
    if not finding.counts_for_risk:
        return 0.0, f"{finding.validation_status.value}, not counted"
    base = SEVERITY_POINTS[finding.severity]
    factor = 1.0 if finding.validation_status == ValidationStatus.CONFIRMED else CONFIDENCE_FACTOR[finding.confidence]
    reason = f"{finding.severity.value} ({base:g}) x {finding.confidence.value} confidence ({factor:g})"
    if finding.validation_status == ValidationStatus.CONFIRMED:
        reason = f"{finding.severity.value} ({base:g}) x confirmed (1)"
    points = base * factor
    if repeat and points:
        points *= REPEAT_FACTOR
        reason += f" x repeat of the same rule ({REPEAT_FACTOR:g})"
    return round(points, 2), reason


def score_findings(findings: list[Finding], status: ScanStatus = ScanStatus.COMPLETED) -> RiskScore:
    """Set risk_points on each finding and return the server score."""
    first_points: dict[str, float] = {}
    rule_totals: dict[str, float] = {}
    factors: list[RiskFactor] = []
    total = 0.0
    for finding in sorted(findings, key=lambda f: (-f.severity.rank, -f.confidence.rank)):
        repeat = finding.rule_id in first_points
        points, reason = finding_points(finding, repeat)
        if finding.counts_for_risk and not repeat:
            first_points[finding.rule_id] = points
        if repeat and points:
            # One kind of problem in many places is worse than in one place, but not many times worse.
            room = max(0.0, first_points[finding.rule_id] * RULE_CAP - rule_totals.get(finding.rule_id, 0.0))
            if points > room:
                points = round(room, 2)
                reason += f", capped at {RULE_CAP:g}x the rule's top finding"
        finding.risk_points = points
        rule_totals[finding.rule_id] = rule_totals.get(finding.rule_id, 0.0) + points
        if points > 0:
            total += points
            factors.append(
                RiskFactor(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    target=f"{finding.target_kind.value} {finding.target_name}",
                    severity=finding.severity.value,
                    confidence=finding.confidence.value,
                    points=points,
                    reason=reason,
                )
            )
    score = min(MAX_SCORE, round(total, 1))
    notes: list[str] = []
    strong = [
        f
        for f in findings
        if f.counts_for_risk
        and f.severity.at_least(Severity.HIGH)
        and f.validation_status in (ValidationStatus.CONFIRMED, ValidationStatus.VALIDATED)
    ]
    if score >= F_THRESHOLD and not strong:
        # Many medium-confidence matches add up, but they are still guesses. F means "strong evidence
        # of serious risk", so without a validated or confirmed high finding the grade stops at D.
        score = F_THRESHOLD - 1
        notes.append(
            f"Score capped at {score:g}: the findings are heuristic. Grade F needs at least one high or "
            "critical finding with strong evidence."
        )
    grade, label = grade_for(score)
    confirmed_bad = [f for f in findings if f.malicious and f.validation_status == ValidationStatus.CONFIRMED]
    if confirmed_bad:
        score, grade, label = MAX_SCORE, "F", "Confirmed malicious"
        notes.append(f"Grade forced to F: {confirmed_bad[0].rule_id} is confirmed malicious behavior.")
    possible = sum(1 for f in findings if f.counts_for_risk and f.confidence == Confidence.LOW)
    if possible:
        notes.append(f"{possible} possible finding(s) with weak evidence are listed but add no points.")
    if status != ScanStatus.COMPLETED:
        notes.append("The scan was not complete, so the real risk may be higher than this score.")
        if grade in ("A", "B"):
            # An incomplete scan must never look clean or low risk: its score is only a lower bound.
            grade, label = "?", "Unknown, the scan was not complete"
        elif grade != "F":
            label = f"{label} or worse (the scan was not complete)"
    return RiskScore(score=score, grade=grade, label=label, factors=factors, notes=notes)
