"""Keys passed on a command line (--api-key VALUE) must never show up in a report."""

from __future__ import annotations

import json

import pytest

from conftest import make_context, run_rules
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest, resolve_targets
from mcp_scanner.models.mcp import ServerInventory
from mcp_scanner.models.observations import DynamicObservations, ProcessEvent
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.scanner.engine import scrub_runtime_text
from mcp_scanner.utils.secrets import mask_args, mask_command_line

KEY = "ctx7sk-9f8e7d6c5b4a39281706f5e4d3c2b1a0"


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "@upstash/context7-mcp@4.1.1", "--api-key", KEY],
        ["-y", "@upstash/context7-mcp@4.1.1", f"--api-key={KEY}"],
        ["server.js", "--github-token", KEY],
        ["server.js", "--password", KEY, "--port", "80"],
        ["server.js", "-t", "x", "--token", KEY],
    ],
)
def test_mask_args_hides_secret_flag_values(args: list[str]) -> None:
    shown = mask_args(args)
    assert KEY not in " ".join(shown) and "redacted" in " ".join(shown)
    assert len(shown) == len(args)


def test_mask_args_leaves_normal_args_alone() -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/home/me/docs", "--port", "8080"]
    assert mask_args(args) == args
    assert mask_args(["--key-file", "/etc/key.pem", "--tokenizer", "fast"]) == [
        "--key-file",
        "/etc/key.pem",
        "--tokenizer",
        "fast",
    ]


def test_mask_command_line() -> None:
    line = f"node /x/dist/index.js --api-key {KEY} --transport stdio"
    masked = mask_command_line(line)
    assert KEY not in masked and masked.endswith("--transport stdio")
    assert KEY not in mask_command_line(f"node index.js --api-key={KEY}")


def test_report_target_and_name_never_show_the_key() -> None:
    command = f"npx -y @upstash/context7-mcp@4.1.1 --api-key {KEY}"
    spec = resolve_targets(TargetRequest(target=command), Settings())[0]
    assert spec.name == "context7-mcp"
    summary = json.dumps(spec.public_summary())
    assert KEY not in summary and "--api-key" in summary


def test_runtime_text_is_scrubbed() -> None:
    obs = DynamicObservations()
    obs.sandbox.child_processes = [ProcessEvent(pid=1, name="node", cmdline=f"node index.js --api-key {KEY}")]
    obs.sandbox.stderr_tail = f"Starting with --api-key {KEY}"
    scrub_runtime_text(ServerInventory(), obs)
    assert KEY not in obs.sandbox.child_processes[0].cmdline and KEY not in obs.sandbox.stderr_tail


def test_key_in_config_args_is_reported() -> None:
    spec = ServerSpec(
        name="context7",
        transport=TransportType.STDIO,
        command="npx",
        args=["-y", "@upstash/context7-mcp@4.1.1", "--api-key", KEY],
        origin="mcp.json",
        origin_kind="config",
    )
    findings = run_rules(make_context(spec=spec), "MCP-SECRET-002")
    assert findings and "arg 4" in findings[0].description
    assert KEY not in json.dumps([f.model_dump(mode="json") for f in findings])
