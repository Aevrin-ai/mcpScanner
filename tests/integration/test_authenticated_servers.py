"""Servers that need a key: a bearer token over HTTP, and an API key in the env for stdio.

The key used here is a random test value. The scanner must pass it to the server, and it
must never show up in the report.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import time
from collections.abc import Iterator

import httpx
import pytest

from conftest import PYTHON, SERVERS, server_command
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.mcp.transports.http import auth_hint
from mcp_scanner.models.result import ScanReport, ScanStatus
from mcp_scanner.reports.json_report import report_to_dict
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest

TOKEN = "demo-" + secrets.token_hex(16)
AUTH_SERVER = SERVERS / "auth_server.py"


def scan(settings: Settings, request: TargetRequest) -> tuple[ScanReport, str]:
    settings.dynamic.enabled = True
    report = ScanEngine(settings).run(ScanRequest(target=request, use_pins=False))
    return report, json.dumps(report_to_dict(report))


@pytest.fixture
def auth_http_server() -> Iterator[str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    proc = subprocess.Popen(
        [PYTHON, str(AUTH_SERVER), "--http", str(port)],
        env={**os.environ, "AUTH_DEMO_TOKEN": TOKEN},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.kill()
        proc.wait(timeout=10)


@pytest.mark.slow
def test_bearer_token_server(settings: Settings, auth_http_server: str) -> None:
    report, _ = scan(settings, TargetRequest(target=auth_http_server))
    server = report.servers[0]
    assert server.status == ScanStatus.FAILED
    assert "HTTP 401" in server.errors[0].message and "Authorization: Bearer" in server.errors[0].message

    headers = {"Authorization": f"Bearer {TOKEN}"}
    report, text = scan(settings, TargetRequest(target=auth_http_server, extra_headers=headers))
    server = report.servers[0]
    assert server.status == ScanStatus.COMPLETED
    assert {t.name for t in server.inventory.tools} == {"whoami", "list_projects", "get_project"}
    assert any(c.tool == "whoami" and "demo-user" in c.output_text for c in server.observations.tool_calls)
    assert TOKEN not in text and server.server["header_keys"] == ["Authorization"]


@pytest.mark.slow
def test_api_key_in_env_for_stdio(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTH_DEMO_TOKEN", raising=False)
    command = server_command(AUTH_SERVER)
    report, _ = scan(settings, TargetRequest(target=command))
    assert report.servers[0].status == ScanStatus.FAILED
    assert "AUTH_DEMO_TOKEN is not set" in report.servers[0].errors[0].message

    report, text = scan(settings, TargetRequest(target=command, extra_env={"AUTH_DEMO_TOKEN": TOKEN}))
    server = report.servers[0]
    assert server.status == ScanStatus.COMPLETED and len(server.inventory.tools) == 3
    assert TOKEN not in text and server.server["env_keys"] == ["AUTH_DEMO_TOKEN"]


@pytest.mark.parametrize(
    ("challenge", "expected"),
    [
        ('Bearer realm="x"', "bearer token"),
        ('Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"', "MCP OAuth"),
        ('Basic realm="x"', "user name and password"),
        ("", "Add credentials with --header"),
    ],
)
def test_auth_hint_names_the_method(challenge: str, expected: str) -> None:
    headers = {"WWW-Authenticate": challenge} if challenge else {}
    assert expected in auth_hint(httpx.Response(401, headers=headers))
