from datetime import date

from mcp_scanner.config.settings import Suppression
from mcp_scanner.models.finding import AnalysisKind, Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.result import ScanStatus
from mcp_scanner.models.severity import Category, Confidence, Severity, ValidationStatus
from mcp_scanner.risk.engine import grade_for, score_findings
from mcp_scanner.validators.finding_validator import FindingValidator


def cand(
    rule: str = "MCP-TEST-001",
    target: str = "t",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    kind: str = "text-match",
    location: str = "tool t > description",
    category: Category = Category.TOOL_POISONING,
    description: str = "desc",
    **extra: object,
) -> FindingCandidate:
    return FindingCandidate(
        rule_id=rule,
        title="Test",
        severity=severity,
        confidence=confidence,
        category=category,
        description=description,
        evidence=[Evidence.make(kind, location, "snippet")],
        target_kind=TargetKind.TOOL,
        target_name=target,
        **extra,  # type: ignore[arg-type]
    )


def test_drops_candidates_without_evidence() -> None:
    c = cand()
    c.evidence = []
    assert FindingValidator().validate("s", [c]) == []


def test_merges_duplicates_and_keeps_worst() -> None:
    a = cand(severity=Severity.MEDIUM, confidence=Confidence.LOW)
    b = cand(severity=Severity.HIGH, confidence=Confidence.HIGH, location="other place")
    found = FindingValidator().validate("s", [a, b])
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH and found[0].confidence == Confidence.HIGH
    assert len(found[0].evidence) == 2


def test_negation_in_same_sentence_marks_false_positive() -> None:
    found = FindingValidator().validate("s", [cand(context_text="This tool does not ")])
    assert found[0].validation_status == ValidationStatus.LIKELY_FALSE_POSITIVE
    assert not found[0].counts_for_risk


def test_negation_in_earlier_sentence_is_ignored() -> None:
    found = FindingValidator().validate("s", [cand(context_text="otherwise the tool will not work. ")])
    assert found[0].validation_status == ValidationStatus.VALIDATED


def test_corroboration_raises_confidence() -> None:
    meta = cand(rule="MCP-A-001", confidence=Confidence.MEDIUM, category=Category.COMMAND_EXECUTION)
    code = cand(
        rule="MCP-B-001",
        confidence=Confidence.MEDIUM,
        kind="source-code",
        location="server.py:4",
        category=Category.CODE_EXECUTION,
    )
    found = {f.rule_id: f for f in FindingValidator().validate("s", [meta, code])}
    assert found["MCP-A-001"].confidence == Confidence.HIGH
    assert "Backed up by MCP-B-001" in found["MCP-A-001"].validation_notes[0]


def test_same_kind_of_evidence_does_not_corroborate() -> None:
    a = cand(rule="MCP-A-001", confidence=Confidence.MEDIUM)
    b = cand(rule="MCP-B-001", confidence=Confidence.MEDIUM)
    assert all(f.confidence == Confidence.MEDIUM for f in FindingValidator().validate("s", [a, b]))


def test_status_levels() -> None:
    found = FindingValidator().validate(
        "s",
        [
            cand(rule="MCP-A-001", confirmed=True, confidence=Confidence.MEDIUM, analysis=AnalysisKind.DYNAMIC),
            cand(rule="MCP-B-001", confidence=Confidence.HIGH),
            cand(rule="MCP-C-001", confidence=Confidence.LOW),
        ],
    )
    status = {f.rule_id: f.validation_status for f in found}
    assert status == {
        "MCP-A-001": ValidationStatus.CONFIRMED,
        "MCP-B-001": ValidationStatus.VALIDATED,
        "MCP-C-001": ValidationStatus.UNVERIFIED,
    }


def test_suppression_and_expiry() -> None:
    rules = [
        Suppression(rule_id="MCP-A-*", reason="known and accepted", server="s", target="t"),
        Suppression(rule_id="MCP-B-001", reason="old exception", expires=date(2020, 1, 1)),
    ]
    found = {
        f.rule_id: f
        for f in FindingValidator(rules, today=date(2026, 1, 1)).validate(
            "s", [cand(rule="MCP-A-001"), cand(rule="MCP-B-001")]
        )
    }
    assert found["MCP-A-001"].validation_status == ValidationStatus.SUPPRESSED
    assert found["MCP-B-001"].validation_status == ValidationStatus.VALIDATED
    assert "expired" in found["MCP-B-001"].validation_notes[0]


def test_finding_ids_are_stable() -> None:
    first = FindingValidator().validate("s", [cand()])[0].id
    second = FindingValidator().validate("s", [cand()])[0].id
    assert first == second and first.startswith("F-")


# ---- risk ---------------------------------------------------------------------


def validated(*candidates: FindingCandidate):
    return FindingValidator().validate("s", list(candidates))


def test_points_are_severity_times_confidence() -> None:
    findings = validated(cand(severity=Severity.HIGH, confidence=Confidence.MEDIUM))
    risk = score_findings(findings)
    assert findings[0].risk_points == 12.0
    assert risk.score == 12.0 and risk.grade == "B"
    assert risk.factors[0].rule_id == "MCP-TEST-001"


def test_possible_findings_score_zero() -> None:
    findings = validated(cand(severity=Severity.CRITICAL, confidence=Confidence.LOW))
    risk = score_findings(findings)
    assert risk.score == 0 and risk.grade == "A"
    assert any("possible" in note for note in risk.notes)


def test_repeats_of_a_rule_count_a_quarter() -> None:
    findings = validated(*(cand(target=f"t{i}", severity=Severity.HIGH) for i in range(3)))
    assert score_findings(findings).score == 20 + 5 + 5


def test_score_is_capped() -> None:
    findings = validated(*(cand(rule=f"MCP-R-{i:03d}", severity=Severity.CRITICAL) for i in range(5)))
    assert score_findings(findings).score == 100


def test_confirmed_malicious_forces_f() -> None:
    findings = validated(cand(severity=Severity.LOW, confirmed=True, malicious=True))
    risk = score_findings(findings)
    assert risk.grade == "F" and risk.score == 100


def test_unconfirmed_malicious_does_not_force_f() -> None:
    findings = validated(cand(severity=Severity.LOW, malicious=True))
    assert score_findings(findings).grade == "B"


def test_incomplete_scan_is_never_grade_a() -> None:
    risk = score_findings([], ScanStatus.PARTIAL)
    assert risk.grade == "?"
    assert score_findings([], ScanStatus.COMPLETED).grade == "A"


def test_incomplete_scan_grade_is_a_lower_bound() -> None:
    low = validated(cand(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM))
    assert score_findings(low, ScanStatus.COMPLETED).grade == "B"
    assert score_findings(low, ScanStatus.FAILED).grade == "?"  # "low risk" would be a guess
    serious = validated(*(cand(rule=f"MCP-TEST-00{i}", target=f"tool{i}") for i in range(2)))
    risk = score_findings(serious, ScanStatus.FAILED)
    assert risk.grade not in ("A", "B", "?") and risk.label.endswith("or worse (the scan was not complete)")


def test_grade_bands() -> None:
    assert [grade_for(x)[0] for x in (0, 1, 14.9, 15, 34.9, 35, 59.9, 60, 100)] == [
        "A",
        "B",
        "B",
        "C",
        "C",
        "D",
        "D",
        "F",
        "F",
    ]


def test_suppressed_findings_add_no_points() -> None:
    finding = validated(cand())[0]
    finding.validation_status = ValidationStatus.SUPPRESSED
    assert score_findings([finding]).score == 0
