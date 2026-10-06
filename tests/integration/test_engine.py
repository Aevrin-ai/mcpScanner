"""The whole scan pipeline against real fixture servers and files."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import EVAL_SERVERS, PYTHON, ROOT, SERVERS, server_command
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.models.result import ScanStatus
from mcp_scanner.models.severity import Severity, ValidationStatus
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest, exit_code


def scan(settings: Settings, target: str, **request: object) -> object:
    return ScanEngine(settings).run(ScanRequest(target=TargetRequest(target=target), **request))  # type: ignore[arg-type]


def active_rules(server) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in server.findings if f.counts_for_risk}


def test_safe_server_is_clean(settings: Settings) -> None:
    settings.dynamic.enabled = True
    report = scan(settings, server_command(SERVERS / "safe_server.py"))
    server = report.servers[0]
    assert server.status == ScanStatus.COMPLETED and server.is_safe is True and server.risk.grade == "A"
    assert {c.tool for c in server.observations.tool_calls} == {"add_numbers", "list_notes"}
    assert "save_note" in server.observations.skipped_tools
    assert exit_code(report, Severity.HIGH) == 0


def test_poisoned_server_static(settings: Settings) -> None:
    report = scan(settings, server_command(EVAL_SERVERS / "poisoned_server.py"))
    server = report.servers[0]
    assert {"MCP-POISON-001", "MCP-POISON-002", "MCP-SHADOW-002"} <= active_rules(server)
    assert server.risk.grade == "F" and server.is_safe is False
    assert exit_code(report, Severity.HIGH) == 1
    assert not server.observations.tool_calls  # static scan never calls tools


def test_canary_leak_is_confirmed(settings: Settings) -> None:
    settings.dynamic.enabled = True
    server = scan(settings, server_command(EVAL_SERVERS / "exfil_server.py")).servers[0]
    leak = [f for f in server.findings if f.rule_id == "MCP-DYN-001"]
    assert leak and leak[0].validation_status == ValidationStatus.CONFIRMED and leak[0].malicious
    assert server.risk.grade == "F" and server.risk.score == 100
    # The canary value itself never appears in the report.
    text = json.dumps(server.model_dump(mode="json"))
    assert "aevrin_canary_env_" not in text and "aevrin_canary_file_" not in text


def test_rug_pull_is_caught_and_new_text_is_scanned(settings: Settings) -> None:
    settings.dynamic.enabled = True
    server = scan(settings, server_command(EVAL_SERVERS / "rug_pull_server.py")).servers[0]
    rules = active_rules(server)
    assert "MCP-DYN-002" in rules and "MCP-POISON-002" in rules
    poison = next(f for f in server.findings if f.rule_id == "MCP-POISON-002")
    assert "(after change)" in poison.evidence[0].location


def test_dangerous_tools_are_not_called(settings: Settings) -> None:
    settings.dynamic.enabled = True
    server = scan(settings, server_command(EVAL_SERVERS / "command_server.py")).servers[0]
    assert server.observations.tool_calls == []
    assert set(server.observations.skipped_tools) == {"run_command", "ping_host", "calculate"}
    assert {"MCP-EXEC-002", "MCP-EXEC-003"} <= active_rules(server)


def test_offline_tools_file(settings: Settings) -> None:
    report = scan(settings, str(ROOT / "src" / "evals" / "tools" / "poisoned_tools.json"))
    server = report.servers[0]
    assert server.server["transport"] == "offline" and len(server.inventory.tools) == 3
    assert "MCP-POISON-004" in active_rules(server)


def test_config_file_without_connecting(settings: Settings) -> None:
    settings.scan.connect = False
    report = scan(settings, str(ROOT / "src" / "evals" / "configs" / "risky_client_config.json"))
    assert len(report.servers) == 6
    assert all(s.status == ScanStatus.COMPLETED and not s.inventory.tools for s in report.servers)
    rules = set().union(*(active_rules(s) for s in report.servers))
    assert {"MCP-SECRET-002", "MCP-CFG-002", "MCP-PRIV-002", "MCP-AUTH-001"} <= rules
    assert any("not started" in n for n in report.servers[0].risk.notes)


def test_shadowing_across_servers(settings: Settings, tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    safe = str(SERVERS / "safe_server.py")
    config.write_text(
        json.dumps(
            {"mcpServers": {"one": {"command": PYTHON, "args": [safe]}, "two": {"command": PYTHON, "args": [safe]}}}
        ),
        encoding="utf-8",
    )
    report = scan(settings, str(config))
    for server in report.servers:
        assert "MCP-SHADOW-003" in active_rules(server)


def test_pins_detect_changes_between_scans(settings: Settings, tmp_path: Path) -> None:
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps([{"name": "a", "description": "Adds numbers."}]), encoding="utf-8")
    first = scan(settings, str(tools)).servers[0]
    assert "MCP-DYN-003" not in active_rules(first)
    tools.write_text(json.dumps([{"name": "a", "description": "Adds numbers. Also reads files."}]), encoding="utf-8")
    second = scan(settings, str(tools)).servers[0]
    assert "MCP-DYN-003" in active_rules(second)
    third = scan(settings, str(tools), update_pins=True).servers[0]
    assert "MCP-DYN-003" in active_rules(third)  # reported once more, then accepted
    fourth = scan(settings, str(tools)).servers[0]
    assert "MCP-DYN-003" not in active_rules(fourth)


def test_min_severity_filter(settings: Settings) -> None:
    settings.scan.min_severity = Severity.HIGH
    server = scan(settings, str(ROOT / "src" / "evals" / "tools" / "leaky_tools.json")).servers[0]
    assert server.findings and all(f.severity.at_least(Severity.HIGH) for f in server.findings)


def test_failed_server_is_never_safe(settings: Settings) -> None:
    report = scan(settings, server_command(SERVERS / "crash_server.py"))
    server = report.servers[0]
    assert server.status == ScanStatus.FAILED and server.is_safe is None and server.risk.grade == "?"
    assert "could not load config" in server.errors[0].message
    assert exit_code(report, Severity.HIGH) == 2


def test_source_from_launch_command_is_analyzed(settings: Settings) -> None:
    server = scan(settings, server_command(EVAL_SERVERS / "command_server.py")).servers[0]
    assert server.server["source_path"] is None  # found from the args, not given
    assert any(f.evidence[0].kind == "source-code" for f in server.findings)
