"""The scanner must stay safe when the server is hostile."""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path

import psutil
import pytest

from conftest import SERVERS, server_command
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.logging.setup import RedactingFilter
from mcp_scanner.models.result import ScanStatus
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.sandbox.canary import CANARY_ENV_NAME, CanarySet
from mcp_scanner.sandbox.environment import build_server_env
from mcp_scanner.sandbox.workspace import Workspace
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest


def scan(settings: Settings, target: str, **request: object):  # type: ignore[no-untyped-def]
    return ScanEngine(settings).run(ScanRequest(target=TargetRequest(target=target), **request))  # type: ignore[arg-type]


def raw(mode: str) -> str:
    return f"{server_command(SERVERS / 'raw_server.py')} {mode}"


def test_host_execution_needs_permission(settings: Settings) -> None:
    settings.sandbox.allow_host = False
    asked: list[str] = []
    report = scan(
        settings, server_command(SERVERS / "safe_server.py"), host_confirm=lambda spec: asked.append(spec.name) or False
    )
    server = report.servers[0]
    assert asked == ["safe_server.py"]
    assert server.status == ScanStatus.FAILED and "--allow-host" in server.errors[0].message
    assert not server.inventory.tools


def test_scanner_secrets_never_reach_the_server(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-scanner-secret-must-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "scanner-aws-secret-must-not-leak")
    settings.dynamic.enabled = True
    server = scan(settings, raw("envtool")).servers[0]
    output = next(c.output_text for c in server.observations.tool_calls if c.tool == "env_tool")
    assert "must-not-leak" not in output
    assert CANARY_ENV_NAME in output  # the planted canary is there instead
    assert any(f.rule_id == "MCP-DYN-001" for f in server.findings)


def test_build_server_env_is_an_allowlist() -> None:
    host = {
        "PATH": "/bin",
        "OPENAI_API_KEY": "x",
        "GITHUB_TOKEN": "y",
        "HOME": "/home/me",
        "SSH_AUTH_SOCK": "/tmp/agent",
    }
    canary = CanarySet()
    with_ws = Workspace(canary)
    try:
        env = build_server_env({"MY_SETTING": "${GITHUB_TOKEN}"}, Settings().sandbox, with_ws, canary, host_env=host)
        assert "OPENAI_API_KEY" not in env and "SSH_AUTH_SOCK" not in env
        assert env["MY_SETTING"] == "y"  # only because the server config asked for it by name
        assert env["HOME"] == str(with_ws.home) and env[CANARY_ENV_NAME] == canary.env_value
    finally:
        with_ws.cleanup()


def test_hanging_server_times_out(settings: Settings) -> None:
    settings.timeouts.startup = 3
    start = time.monotonic()
    server = scan(settings, server_command(SERVERS / "hang_server.py")).servers[0]
    assert time.monotonic() - start < 30
    assert server.status == ScanStatus.FAILED and "No answer" in server.errors[0].message


def test_spammy_output_is_survived_and_reported(settings: Settings) -> None:
    settings.sandbox.max_message_mb = 1
    server = scan(settings, raw("spam")).servers[0]
    assert server.status == ScanStatus.COMPLETED and len(server.inventory.tools) == 1
    assert any(f.rule_id == "MCP-PROTO-002" for f in server.findings)


def test_endless_pages_are_cut_off(settings: Settings) -> None:
    server = scan(settings, raw("pages")).servers[0]
    assert server.status == ScanStatus.COMPLETED
    assert any(f.rule_id == "MCP-PROTO-004" for f in server.findings)


def test_whole_process_tree_is_killed(settings: Settings) -> None:
    server = scan(settings, raw("child")).servers[0]
    children = [e for e in server.observations.sandbox.child_processes if "sleep(600)" in e.cmdline]
    assert children, "the watchdog should have seen the child process"
    time.sleep(0.5)
    for event in children:
        if psutil.pid_exists(event.pid):
            proc = psutil.Process(event.pid)
            assert proc.status() == psutil.STATUS_ZOMBIE or "sleep(600)" not in " ".join(proc.cmdline())


def test_workspace_is_deleted(settings: Settings) -> None:
    before = set(Path(tempfile.gettempdir()).glob("aevrin-scan-*"))
    scan(settings, server_command(SERVERS / "safe_server.py"))
    after = set(Path(tempfile.gettempdir()).glob("aevrin-scan-*"))
    assert after - before == set()


def test_workspace_has_decoys_with_canary() -> None:
    canary = CanarySet()
    ws = Workspace(canary)
    try:
        assert canary.file_value in (ws.home / ".ssh" / "id_rsa").read_text(encoding="utf-8")
        assert canary.file_value in (ws.home / ".env").read_text(encoding="utf-8")
    finally:
        ws.cleanup()
    assert not ws.root.exists()


def test_log_filter_redacts_secrets() -> None:
    record = logging.LogRecord("x", logging.INFO, "f", 1, "token=%s", ("AKIAABCDEFGHIJKLMNOP",), None)
    RedactingFilter().filter(record)
    assert "AKIAABCDEFGHIJKLMNOP" not in record.getMessage()


def test_report_never_shows_env_or_header_values() -> None:
    spec = ServerSpec(
        name="s",
        transport=TransportType.HTTP,
        url="https://x.example/mcp",
        headers={"Authorization": "Bearer secret-value"},
        env={"TOKEN": "secret-env"},
    )
    summary = str(spec.public_summary())
    assert "secret-value" not in summary and "secret-env" not in summary and "Authorization" in summary
