from pathlib import Path

from mcp_scanner.evaluation.cases import EvalCase, Expectation, load_cases
from mcp_scanner.evaluation.metrics import render_markdown, summarize
from mcp_scanner.evaluation.runner import CaseResult, judge
from mcp_scanner.models.finding import Evidence, Finding, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity, ValidationStatus

ROOT = Path(__file__).resolve().parents[2]


def finding(rule: str, severity: Severity = Severity.HIGH, confidence: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        id=f"F-{rule}",
        server="s",
        rule_id=rule,
        title="t",
        severity=severity,
        confidence=confidence,
        category=Category.QUALITY,
        description="d",
        evidence=[Evidence.make("x", "y")],
        target_kind=TargetKind.TOOL,
        target_name="t",
        validation_status=ValidationStatus.VALIDATED,
    )


def case(malicious: bool, **expect: object) -> EvalCase:
    return EvalCase(name="c", malicious=malicious, target="x.json", expect=Expectation(**expect))  # type: ignore[arg-type]


def test_judge_true_and_false_positives() -> None:
    result = judge(
        case(True, must_find=["MCP-A", "MCP-B-001"], must_not_find=["MCP-C"], min_grade="D"),
        [finding("MCP-A-001"), finding("MCP-C-002")],
        "C",
    )
    assert result.true_positives == ["MCP-A"]
    assert result.false_negatives == ["MCP-B-001"]
    assert result.false_positives == ["MCP-C-002 on t"]
    assert result.problems and not result.passed


def test_benign_case_counts_serious_findings_as_false_positives() -> None:
    result = judge(
        case(False, allow=["MCP-PERM"]),
        [
            finding("MCP-PERM-001"),
            finding("MCP-X-001", Severity.MEDIUM),
            finding("MCP-Y-001", Severity.LOW),
            finding("MCP-Z-001", confidence=Confidence.LOW),
        ],
        "B",
    )
    assert result.false_positives == ["MCP-X-001 on t"]


def test_summary_metrics() -> None:
    results = [
        CaseResult(
            name="m1", malicious=True, flagged=True, true_positives=["a", "b"], confidences=[1.0, 0.6], passed=True
        ),
        CaseResult(name="m2", malicious=True, flagged=False, false_negatives=["c"]),
        CaseResult(name="b1", malicious=False, flagged=True, false_positives=["x"]),
        CaseResult(name="b2", malicious=False, flagged=False, passed=True),
    ]
    s = summarize(results)
    assert s.detection_rate == 0.5 and s.false_negative_rate == 0.5
    assert s.false_positive_rate == 0.5
    assert s.precision == round(2 / 3, 4) and s.recall == round(2 / 3, 4)
    assert s.average_confidence == 0.8 and s.passed == 2
    assert "Detection rate: 50.0%" in render_markdown(s, results)


def test_bundled_cases_load_and_resolve() -> None:
    cases = load_cases(ROOT / "src" / "evals")
    assert len(cases) >= 12
    assert any(c.malicious for c in cases) and any(not c.malicious for c in cases)
    assert all("{python}" not in c.target and "{root}" not in c.target for c in cases)
