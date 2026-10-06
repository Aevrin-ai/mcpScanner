from pathlib import Path

import pytest

from conftest import make_context, registry, tool
from mcp_scanner.config.settings import RuleSettings
from mcp_scanner.core.errors import ConfigError
from mcp_scanner.models.severity import Severity
from mcp_scanner.rules.base import Rule
from mcp_scanner.rules.registry import RuleRegistry, id_matches
from mcp_scanner.rules.yaml_rules import load_yaml_rules


def test_at_least_35_builtin_rules_with_metadata() -> None:
    rules = registry().all()
    assert len(rules) >= 35
    for rule in rules:
        assert rule.id.startswith("MCP-") and rule.title and rule.description and rule.recommendation, rule.id
        assert "—" not in rule.description + rule.why_it_matters + rule.recommendation, rule.id


def test_every_category_from_the_plan_has_rules() -> None:
    prefixes = {r.id.rsplit("-", 1)[0] for r in registry().all()}
    for name in (
        "INJ",
        "POISON",
        "SHADOW",
        "EXEC",
        "FS",
        "NET",
        "SQL",
        "SECRET",
        "PRIV",
        "SCOPE",
        "PERM",
        "CFG",
        "AUTH",
        "SRC",
        "DEP",
        "DYN",
        "PROTO",
        "QUALITY",
    ):
        assert f"MCP-{name}" in prefixes


@pytest.mark.parametrize(
    ("rid", "patterns", "expected"),
    [
        ("MCP-EXEC-001", ["MCP-EXEC"], True),
        ("MCP-EXEC-001", ["MCP-EXEC-*"], True),
        ("MCP-EXEC-001", ["mcp-exec-001"], True),
        ("MCP-EXEC-001", ["MCP-EX"], False),
        ("MCP-EXEC-001", ["*"], True),
        ("MCP-FS-001", ["MCP-EXEC"], False),
    ],
)
def test_id_matching(rid: str, patterns: list[str], expected: bool) -> None:
    assert id_matches(rid, patterns) is expected


def test_select_enabled_and_disabled() -> None:
    chosen = registry().select(["MCP-EXEC"], ["MCP-EXEC-004"])
    ids = {r.id for r in chosen}
    assert "MCP-EXEC-001" in ids and "MCP-EXEC-004" not in ids and all(i.startswith("MCP-EXEC") for i in ids)
    with pytest.raises(ConfigError):
        registry().select(["MCP-NOPE"])


class _Boom(Rule):
    id = "MCP-TEST-900"
    title = "Crashes"

    def check(self, ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("bad rule")


def test_a_crashing_rule_does_not_stop_others() -> None:
    reg = RuleRegistry([_Boom(), registry().get("MCP-QUALITY-001")])  # type: ignore[list-item]
    ctx = make_context([tool("x")])
    run = reg.run(ctx, reg.all())
    assert run.errors and "MCP-TEST-900" in run.errors[0].message
    assert "MCP-QUALITY-001" in run.rules_run and run.candidates


def test_rules_that_need_source_are_skipped_without_it() -> None:
    reg = registry()
    run = reg.run(make_context([tool("x", "y")]), reg.select(["MCP-EXEC-002"]))
    assert run.rules_skipped == {"MCP-EXEC-002": "no source code"}


def test_severity_override() -> None:
    reg = registry()
    run = reg.run(
        make_context([tool("x")]),
        reg.select(["MCP-QUALITY-001"]),
        RuleSettings(severity_overrides={"MCP-QUALITY-001": Severity.HIGH}),
    )
    assert run.candidates[0].severity == Severity.HIGH


def write_rule(folder: Path, text: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "rule.yaml").write_text(text, encoding="utf-8")


def test_yaml_rule_loads_and_fires(tmp_path: Path) -> None:
    write_rule(
        tmp_path,
        """
id: CUSTOM-001
title: Mentions the internal billing host
severity: medium
category: data-exfiltration
confidence: high
description: A tool mentions billing.internal.
match:
  pattern: "billing\\\\.internal"
  surfaces: [tool-description]
""",
    )
    reg = RuleRegistry.load(extra_dirs=[str(tmp_path)])
    rule = reg.get("CUSTOM-001")
    assert rule is not None and rule.summary()["origin"].startswith("yaml")
    ctx = make_context([tool("pay", "Sends invoices to billing.internal.example")])
    run = reg.run(ctx, [rule])
    assert run.candidates and run.candidates[0].target_name == "pay"
    quiet = reg.run(make_context([tool("pay", "Sends invoices")]), [rule])
    assert not quiet.candidates


@pytest.mark.parametrize(
    "text",
    [
        "id: bad id\ntitle: x\nseverity: low\nmatch: {pattern: x}\n",
        "id: CUSTOM-002\ntitle: x\nseverity: nope\nmatch: {pattern: x}\n",
        "id: CUSTOM-003\ntitle: x\nseverity: low\nmatch: {pattern: '(unclosed'}\n",
        "id: CUSTOM-004\ntitle: x\nseverity: low\nmatch: {pattern: x, surfaces: [nowhere]}\n",
        "id: CUSTOM-005\ntitle: x\nseverity: low\nmatch: {pattern: x}\nrun_code: true\n",
    ],
)
def test_invalid_yaml_rules_are_rejected(tmp_path: Path, text: str) -> None:
    write_rule(tmp_path, text)
    with pytest.raises(ConfigError):
        load_yaml_rules(tmp_path)


def test_example_rules_folder_is_valid() -> None:
    folder = Path(__file__).resolve().parents[2] / "src" / "rules"
    assert load_yaml_rules(folder)
