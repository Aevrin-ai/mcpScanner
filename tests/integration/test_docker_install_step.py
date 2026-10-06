"""The Docker install step, end to end. These download packages, so they only run when
AEVRIN_NETWORK_TESTS=1 is set and Docker is running.

    AEVRIN_NETWORK_TESTS=1 pytest tests/integration/test_docker_install_step.py
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.models.result import ScanStatus
from mcp_scanner.sandbox.docker import docker_available
from mcp_scanner.scanner.engine import ScanEngine, ScanRequest

pytestmark = [
    pytest.mark.docker,
    pytest.mark.network,
    pytest.mark.slow,
    pytest.mark.skipif(
        os.environ.get("AEVRIN_NETWORK_TESTS") != "1" or not docker_available(),
        reason="set AEVRIN_NETWORK_TESTS=1 and start Docker",
    ),
]

SERVER = '''from mcp.server.fastmcp import FastMCP

mcp = FastMCP("repo-demo")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
'''


def docker_settings(settings: Settings) -> Settings:
    settings.sandbox.mode = "docker"
    settings.sandbox.allow_host = False
    settings.sandbox.network = "none"  # the server itself never gets a network
    return settings


def leftovers() -> tuple[list[str], list[str]]:
    def names(*args: str) -> list[str]:
        return subprocess.run(["docker", *args], capture_output=True, text=True, check=False).stdout.split()

    return names("ps", "-a", "-q", "--filter", "name=aevrin-scan-"), names(
        "volume", "ls", "-q", "--filter", "name=aevrin-deps-"
    )


def test_npx_server_runs_without_network(settings: Settings) -> None:
    report = ScanEngine(docker_settings(settings)).run(
        ScanRequest(target=TargetRequest(target="npx -y @modelcontextprotocol/server-memory@2026.8.31"))
    )
    server = report.servers[0]
    assert server.status == ScanStatus.COMPLETED, server.errors
    assert len(server.inventory.tools) >= 5
    assert server.observations.sandbox.sandbox_mode == "docker"
    assert leftovers() == ([], [])


def test_repository_folder_runs_with_run_flag(settings: Settings, tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(SERVER, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("mcp>=1.20,<2\n", encoding="utf-8")
    report = ScanEngine(docker_settings(settings)).run(
        ScanRequest(target=TargetRequest(target=str(tmp_path), run=True))
    )
    server = report.servers[0]
    assert server.status == ScanStatus.COMPLETED, server.errors
    assert [t.name for t in server.inventory.tools] == ["add"]
    assert server.server["repository"]["entry"] == "server.py"
    assert leftovers() == ([], [])


def test_run_flag_refuses_the_process_sandbox(settings: Settings, tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(SERVER, encoding="utf-8")
    settings.sandbox.mode = "process"
    report = ScanEngine(settings).run(ScanRequest(target=TargetRequest(target=str(tmp_path), run=True)))
    assert report.servers[0].status == ScanStatus.FAILED
    assert "needs the Docker sandbox" in report.servers[0].errors[0].message
