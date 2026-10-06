"""Shared test helpers.

Server tests start real processes with the process sandbox. They only run our own
fixture servers from tests/fixtures and src/evals/servers, so allow_host is set here.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_scanner.analyzers.dependencies import DependencyFacts, analyze_dependencies
from mcp_scanner.analyzers.source import analyze_source
from mcp_scanner.config.settings import Settings
from mcp_scanner.models.mcp import PromptInfo, ResourceInfo, ServerInventory, ToolInfo
from mcp_scanner.models.observations import DynamicObservations
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.rules.registry import RuleRegistry
from mcp_scanner.scanner.context import ScanContext
from mcp_scanner.validators.finding_validator import FindingValidator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SERVERS = FIXTURES / "servers"
EVAL_SERVERS = ROOT / "src" / "evals" / "servers"
PYTHON = sys.executable


def server_command(path: Path) -> str:
    return f'"{PYTHON}" "{path}"' if " " in PYTHON or " " in str(path) else f"{PYTHON} {path}"


@pytest.fixture(autouse=True)
def no_report_lookups(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never fetch public reports from the internet. Mark a test with `real_report_lookup` to use the real function."""
    if "real_report_lookup" not in request.keywords:
        monkeypatch.setattr("mcp_scanner.analyzers.prescanned.lookup", lambda *args, **kwargs: None)


@pytest.fixture(autouse=True)
def isolated_license_state(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never read a real license or write to the real ~/.aevrin-mcp-scanner."""
    monkeypatch.setenv("AEVRIN_STATE_DIR", str(tmp_path_factory.mktemp("aevrin-state")))
    for name in ("AEVRIN_LICENSE", "AEVRIN_LICENSE_FILE", "AEVRIN_INSTALLATION_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("mcp_scanner.licensing.status._CACHE", None)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings for tests: process sandbox, host allowed, pins in a temp folder, short timeouts."""
    s = Settings()
    s.sandbox.mode = "process"
    s.sandbox.allow_host = True
    s.scan.pins_file = str(tmp_path / "pins.json")
    s.timeouts.startup = 30
    s.timeouts.request = 15
    s.timeouts.tool_call = 10
    return s


_REGISTRY: RuleRegistry | None = None


def registry() -> RuleRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = RuleRegistry.load()
    return _REGISTRY


def tool(
    name: str,
    description: str = "",
    properties: dict[str, Any] | None = None,
    required: list[str] | None = None,
    annotations: dict[str, Any] | None = None,
) -> ToolInfo:
    schema: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    data: dict[str, Any] = {"name": name, "description": description, "inputSchema": schema}
    if annotations:
        data["annotations"] = annotations
    return ToolInfo.from_wire(data)


def make_context(
    tools: list[ToolInfo] | None = None,
    *,
    spec: ServerSpec | None = None,
    instructions: str | None = None,
    prompts: list[PromptInfo] | None = None,
    resources: list[ResourceInfo] | None = None,
    observations: DynamicObservations | None = None,
    source_text: str | None = None,
    source_name: str = "server.py",
    tmp_path: Path | None = None,
    dependencies: DependencyFacts | None = None,
    peer_tools: dict[str, str] | None = None,
    connected: bool = True,
) -> ScanContext:
    spec = spec or ServerSpec(name="test-server", transport=TransportType.OFFLINE, tools_file="tools.json")
    source = None
    if source_text is not None:
        assert tmp_path is not None, "source_text needs tmp_path"
        path = tmp_path / source_name
        path.write_text(source_text, encoding="utf-8")
        source = analyze_source(path)
    return ScanContext(
        spec=spec,
        inventory=ServerInventory(
            instructions=instructions, tools=tools or [], prompts=prompts or [], resources=resources or []
        ),
        observations=observations or DynamicObservations(),
        source=source,
        dependencies=dependencies if dependencies is not None else analyze_dependencies(spec, None),
        peer_tools=peer_tools or {},
        connected=connected,
    )


def run_rules(ctx: ScanContext, *rule_ids: str) -> list:
    """Run rules (all when none given) and return validated findings."""
    reg = registry()
    rules = reg.select(list(rule_ids)) if rule_ids else reg.all()
    run = reg.run(ctx, rules)
    assert not run.errors, run.errors
    return FindingValidator().validate(ctx.spec.name, run.candidates)


def rule_ids(findings: list, active_only: bool = True) -> set[str]:
    return {f.rule_id for f in findings if f.counts_for_risk or not active_only}
