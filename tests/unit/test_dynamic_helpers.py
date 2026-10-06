from pathlib import Path

from conftest import tool
from mcp_scanner.analyzers.capabilities import analyze_tool
from mcp_scanner.analyzers.dynamic.pins import PinStore, compare, tool_hash
from mcp_scanner.analyzers.dynamic.probes import build_arguments, call_policy, value_for
from mcp_scanner.analyzers.dynamic.runner import canary_locations, content_text
from mcp_scanner.models.mcp import ServerInventory
from mcp_scanner.models.observations import ToolCallRecord
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.sandbox.canary import CanarySet


def test_tool_hash_changes_with_description() -> None:
    a, b = tool("x", "one"), tool("x", "two")
    assert tool_hash(a) == tool_hash(tool("x", "one"))
    assert tool_hash(a) != tool_hash(b)


def test_compare_reports_added_removed_changed() -> None:
    changes = compare({"a": "1", "b": "2"}, {"b": "3", "c": "4"}, "during-session")
    assert {(c.tool, c.change) for c in changes} == {("a", "removed"), ("b", "changed"), ("c", "added")}


def test_pin_store_trust_on_first_use(tmp_path: Path) -> None:
    spec = ServerSpec(name="s", transport=TransportType.OFFLINE, tools_file="t.json")
    path = tmp_path / "pins.json"
    store = PinStore(path)
    assert store.check(spec, [tool("a", "one")]) == []
    store.record(spec, [tool("a", "one")], overwrite=False)
    store.save()
    again = PinStore(path)
    changes = again.check(spec, [tool("a", "two")])
    assert [(c.tool, c.change, c.when) for c in changes] == [("a", "changed", "since-last-scan")]
    # Without overwrite the old pin stays, so the change is reported until accepted.
    again.record(spec, [tool("a", "two")], overwrite=False)
    assert again.check(spec, [tool("a", "two")])
    again.record(spec, [tool("a", "two")], overwrite=True)
    assert again.check(spec, [tool("a", "two")]) == []


def test_broken_pin_file_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    path.write_text("{broken", encoding="utf-8")
    assert PinStore(path).data["servers"] == {}


def test_call_policy() -> None:
    def policy(t, allow=False):  # type: ignore[no-untyped-def]
        return call_policy(t, analyze_tool(t), allow)

    assert policy(tool("get_weather", "Get the weather", {"city": {"type": "string"}})) is None
    assert policy(tool("run_command", "Run a shell command", {"command": {"type": "string"}})) is not None
    assert policy(tool("delete_note", "Remove a note", {"id": {"type": "string"}})) is not None
    assert policy(tool("save_note", "Save a note", {"text": {"type": "string"}})) is not None
    assert policy(tool("fetch_url", "Fetch a page", {"url": {"type": "string"}})) is not None
    assert policy(tool("lookup", "Look up", annotations={"destructiveHint": True})) == "marked destructive"
    assert policy(tool("update_cache", "x", annotations={"readOnlyHint": True})) is None
    assert policy(tool("run_command", "Run", {"command": {"type": "string"}}), allow=True) is None


def test_build_arguments_fills_only_required_values() -> None:
    canary = CanarySet()
    t = tool(
        "x",
        properties={
            "a": {"type": "integer", "minimum": 5},
            "b": {"type": "string", "enum": ["one", "two"]},
            "c": {"type": "string"},
            "d": {"type": "boolean"},
            "path": {"type": "string"},
            "opt": {"type": "string"},
            "nested": {"type": "object", "properties": {"k": {"type": "number"}}, "required": ["k"]},
        },
        required=["a", "b", "c", "d", "path", "nested"],
    )
    args = build_arguments(t, canary)
    assert args == {
        "a": 5,
        "b": "one",
        "c": canary.input_value,
        "d": False,
        "path": "aevrin-canary.txt",
        "nested": {"k": 1.0},
    }


def test_value_for_respects_string_limits() -> None:
    canary = CanarySet()
    assert len(value_for("x", {"type": "string", "maxLength": 4}, canary)) == 4
    assert value_for("x", {"type": "string", "format": "uri"}, canary) == "https://example.com/"
    assert value_for("x", {"anyOf": [{"type": "null"}, {"type": "integer"}]}, canary) == 1


def test_content_text_reads_every_shape() -> None:
    result = {
        "content": [{"type": "text", "text": "one"}, {"type": "resource", "resource": {"text": "two"}}],
        "structuredContent": {"k": "three"},
    }
    assert content_text(result, 1000) == 'one\ntwo\n{"k": "three"}'
    assert content_text({"messages": [{"content": {"type": "text", "text": "hi"}}]}, 1000) == "hi"
    assert content_text({"contents": [{"text": "res"}]}, 1000) == "res"


def test_canary_locations() -> None:
    canary = CanarySet()
    inv = ServerInventory(instructions=f"token {canary.env_value}", tools=[tool("a", "clean")])
    calls = [ToolCallRecord(tool="a", output_text=f"key={canary.file_value}")]
    found = canary_locations(canary.secret_values(), inv, calls)
    assert found == ["server instructions", "tool a > call result"]
    assert canary_locations([], inv, calls) == []
