"""Tests that need Docker or a real AI provider. They skip when those are not available.

Docker tests use the optional image from src/docker/sandbox-python.Dockerfile:
    docker build -f src/docker/sandbox-python.Dockerfile -t aevrin-sandbox-python .
The live AI test needs OPENROUTER_API_KEY and costs about two cents.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from conftest import EVAL_SERVERS, ROOT, SERVERS
from mcp_scanner.ai.review import AIReviewService
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.models.result import ScanStatus
from mcp_scanner.models.severity import ValidationStatus
from mcp_scanner.sandbox.docker import docker_available, image_exists
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest

SANDBOX_IMAGE = "aevrin-sandbox-python"


def _image_exists(name: str) -> bool:
    return bool(shutil.which("docker")) and image_exists(name)


needs_docker = pytest.mark.skipif(
    not (docker_available() and _image_exists(SANDBOX_IMAGE)), reason=f"needs Docker and the {SANDBOX_IMAGE} image"
)


def docker_settings(settings: Settings) -> Settings:
    settings.sandbox.mode = "docker"
    settings.sandbox.allow_host = False  # the Docker sandbox must never need host permission
    settings.sandbox.docker_image_python = SANDBOX_IMAGE
    settings.timeouts.startup = 90
    return settings


def scan(settings: Settings, target: str):  # type: ignore[no-untyped-def]
    return ScanEngine(settings).run(ScanRequest(target=TargetRequest(target=target)))


@pytest.mark.docker
@needs_docker
def test_safe_server_in_docker(settings: Settings) -> None:
    settings = docker_settings(settings)
    settings.dynamic.enabled = True
    server = scan(settings, f"python {SERVERS / 'safe_server.py'}").servers[0]
    assert server.status == ScanStatus.COMPLETED and server.risk.grade == "A"
    assert server.observations.sandbox.sandbox_mode == "docker"
    assert server.observations.tool_calls


@pytest.mark.docker
@needs_docker
def test_canary_leak_and_persistence_seen_in_docker(settings: Settings) -> None:
    settings = docker_settings(settings)
    settings.dynamic.enabled = True
    leak = scan(settings, f"python {EVAL_SERVERS / 'exfil_server.py'}").servers[0]
    assert any(f.rule_id == "MCP-DYN-001" and f.validation_status == ValidationStatus.CONFIRMED for f in leak.findings)
    planted = scan(settings, f"python {EVAL_SERVERS / 'persistence_server.py'}").servers[0]
    assert set(planted.observations.sandbox.files_written) >= {"home/.bashrc", "home/.ssh/authorized_keys"}


@pytest.mark.docker
@needs_docker
def test_no_containers_are_left_behind(settings: Settings) -> None:
    scan(docker_settings(settings), f"python {SERVERS / 'safe_server.py'}")
    names = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=aevrin-scan-", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    assert names == []


@pytest.mark.ai
@pytest.mark.skipif(not os.environ.get("OPENROUTER_API_KEY"), reason="needs OPENROUTER_API_KEY")
def test_live_ai_review_with_openrouter(settings: Settings) -> None:
    settings.ai.enabled = True
    settings.ai.provider = "openrouter"
    settings.ai.max_output_tokens = 1500
    engine = ScanEngine(settings, ai_reviewer=AIReviewService(settings.ai))
    report = engine.run(
        ScanRequest(target=TargetRequest(target=str(ROOT / "src" / "evals" / "tools" / "poisoned_tools.json")))
    )
    ai = report.servers[0].ai
    assert not ai.errors, ai.errors
    assert ai.summary and report.ai_usage.calls == 1 and report.ai_usage.input_tokens > 0
    reviewed = [f for f in report.servers[0].findings if f.ai_review]
    assert reviewed and all(f.ai_review.verdict in ("likely-real", "likely-false-positive", "unsure") for f in reviewed)
