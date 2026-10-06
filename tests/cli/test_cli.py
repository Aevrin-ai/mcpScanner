"""The command line app, through Typer's test runner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import ROOT, SERVERS, server_command
from mcp_scanner import __version__
from mcp_scanner.cli.app import app

runner = CliRunner()
POISONED = str(ROOT / "src" / "evals" / "tools" / "poisoned_tools.json")
BENIGN = str(ROOT / "src" / "evals" / "tools" / "benign_dev_tools.json")


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep pins and config files out of the real home folder."""
    monkeypatch.setenv("AEVRIN_PINS_FILE", str(tmp_path / "pins.json"))
    monkeypatch.chdir(tmp_path)


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0 and __version__ in result.output


def test_rules_list_and_show() -> None:
    listed = runner.invoke(app, ["rules", "list", "--json"])
    assert listed.exit_code == 0
    rules = json.loads(listed.output)
    assert len(rules) >= 35
    shown = runner.invoke(app, ["rules", "show", "MCP-POISON-001"])
    assert shown.exit_code == 0 and "Why it matters" in shown.output
    missing = runner.invoke(app, ["rules", "show", "MCP-NOPE-001"])
    assert missing.exit_code == 2


def test_rules_validate_example_folder() -> None:
    result = runner.invoke(app, ["rules", "validate", str(ROOT / "src" / "rules")])
    assert result.exit_code == 0 and "valid" in result.output


def test_scan_json_and_exit_codes() -> None:
    bad = runner.invoke(app, ["scan", POISONED, "--json"])
    assert bad.exit_code == 1
    data = json.loads(bad.stdout)
    assert data["servers"][0]["risk"]["grade"] == "F"
    good = runner.invoke(app, ["scan", BENIGN, "--json"])
    assert good.exit_code == 0
    relaxed = runner.invoke(app, ["scan", POISONED, "--fail-on", "none", "--json"])
    assert relaxed.exit_code == 0


def test_scan_console_output() -> None:
    result = runner.invoke(app, ["scan", POISONED])
    assert result.exit_code == 1
    assert "MCP-POISON-001" in result.stdout and "Risk" in result.stdout


def test_scan_writes_report_files_and_report_command_converts(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", POISONED, "-f", "json", "-f", "sarif", "-f", "markdown", "-o", str(out), "--fail-on", "none"]
    )
    assert result.exit_code == 0
    files = sorted(p.suffix for p in out.iterdir())
    assert files == [".json", ".md", ".sarif"]
    json_file = next(out.glob("*.json"))
    converted = runner.invoke(app, ["report", str(json_file), "-f", "markdown"])
    assert converted.exit_code == 0 and "# Aevrin MCP Scanner report" in converted.stdout


def test_scan_errors_exit_2() -> None:
    assert runner.invoke(app, ["scan"]).exit_code == 2
    assert runner.invoke(app, ["scan", BENIGN, "--format", "pdf"]).exit_code == 2
    assert runner.invoke(app, ["scan", BENIGN, "--rule", "MCP-NOPE"]).exit_code == 2


def test_scan_live_server_needs_allow_host_when_not_interactive() -> None:
    result = runner.invoke(app, ["scan", server_command(SERVERS / "safe_server.py"), "--sandbox", "process", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["servers"][0]["status"] == "failed"


def test_inspect_lists_tools() -> None:
    result = runner.invoke(app, ["inspect", BENIGN])
    assert result.exit_code == 0 and "search_repositories" in result.stdout


def test_scan_no_connect_on_config() -> None:
    result = runner.invoke(
        app, ["scan", str(ROOT / "src" / "evals" / "configs" / "clean_client_config.json"), "--no-connect", "--json"]
    )
    assert result.exit_code == 0
    assert all(s["summary"]["is_safe"] for s in json.loads(result.stdout)["servers"])


def test_discover_json_runs() -> None:
    result = runner.invoke(app, ["discover", "--json", "--all"])
    assert result.exit_code == 0
    assert any(row["client"] == "Claude Desktop" for row in json.loads(result.stdout))


def test_skills_commands() -> None:
    listed = runner.invoke(app, ["skills", "list", "--json"])
    assert listed.exit_code == 0 and any(s["name"] == "quick-scan" for s in json.loads(listed.stdout))
    assert runner.invoke(app, ["skills", "validate"]).exit_code == 0
    shown = runner.invoke(app, ["skills", "show", "deep-audit"])
    assert shown.exit_code == 0 and "Deep audit" in shown.stdout
    ran = runner.invoke(app, ["skills", "run", "quick-scan", "--input", f"target={BENIGN}"])
    assert ran.exit_code == 0


def test_eval_offline_case(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "eval",
            "--root",
            str(ROOT / "src" / "evals"),
            "--case",
            "benign-dev-tools-file",
            "--case",
            "poisoned-tools-file",
            "-o",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)["summary"]
    assert summary["passed"] == 2 and summary["detection_rate"] == 1.0
