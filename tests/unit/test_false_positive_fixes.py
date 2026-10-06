"""False positives found on a large real server, kept fixed with small examples."""

from __future__ import annotations

from conftest import make_context, run_rules, tool
from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.analyzers.source.python_analyzer import analyze_python
from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.risk.engine import score_findings
from mcp_scanner.rules.builtin.scope import is_multi_action
from mcp_scanner.validators.finding_validator import FindingValidator

HEAD = "from mcp.server import MCPServer\nimport os, shutil, subprocess, hashlib, json\nmcp = MCPServer('x')\n"


def categories(code: str) -> list[str]:
    _, hits, _ = analyze_python(HEAD + code, "server.py")
    return [h.category for h in hits]


def test_str_replace_is_not_a_file_write() -> None:
    code = "@mcp.tool()\ndef t(subdir: str) -> str:\n    return subdir.replace('\\\\', '/')\n"
    assert f.FILE_WRITE not in categories(code)


def test_datetime_replace_is_not_a_file_write() -> None:
    code = (
        "from datetime import timezone\n@mcp.tool()\ndef t(when: str):\n    return when.replace(tzinfo=timezone.utc)\n"
    )
    assert f.FILE_WRITE not in categories(code)


def test_path_replace_with_one_argument_is_still_a_write() -> None:
    code = "from pathlib import Path\n@mcp.tool()\ndef t(name: str) -> None:\n    Path(name).replace('/tmp/x')\n"
    assert f.FILE_WRITE in categories(code)


def test_compile_alone_is_not_code_execution() -> None:
    code = "@mcp.tool()\ndef check(source: str) -> str:\n    compile(source, '<s>', 'exec')\n    return 'ok'\n"
    assert f.CODE_EVAL not in categories(code)
    run = "@mcp.tool()\ndef run(source: str) -> None:\n    code = compile(source, '<s>', 'exec')\n    exec(code)\n"
    assert f.CODE_EVAL in categories(run)


def test_environment_copy_for_a_child_process_is_not_a_dump() -> None:
    child = "def go() -> None:\n    env = dict(os.environ)\n    env['X'] = '1'\n    subprocess.run(['ls'], env=env)\n"
    assert f.ENV_DUMP not in categories(child)
    inline = "def go() -> None:\n    subprocess.run(['ls'], env=os.environ.copy())\n"
    assert f.ENV_DUMP not in categories(inline)
    dump = "def go() -> str:\n    return json.dumps(dict(os.environ))\n"
    assert f.ENV_DUMP in categories(dump)


def test_hashed_file_names_and_prefix_guards_are_sanitized() -> None:
    hashed = (
        "@mcp.tool()\ndef cache(path: str) -> None:\n"
        "    name = hashlib.sha1(path.encode()).hexdigest()\n"
        "    open(os.path.join('/cache', name + '.json'), 'w').write('x')\n"
    )
    _, hits, _ = analyze_python(HEAD + hashed, "server.py")
    assert not [h for h in hits if h.category == f.FILE_WRITE and h.tainted]
    guarded = (
        "@mcp.tool()\ndef clean(staging: str) -> None:\n"
        "    if not os.path.basename(staging).startswith('mine-'):\n        return\n"
        "    shutil.rmtree(staging)\n"
    )
    _, hits, _ = analyze_python(HEAD + guarded, "server.py")
    assert all(h.sanitized for h in hits if h.category == f.FILE_WRITE)


def test_multi_action_tools_make_hidden_behavior_possible_only() -> None:
    long = "App operations.\n\nActions:\n  start() -> ok\n  stop() -> ok\n  status() -> s\n"
    assert is_multi_action(long) and not is_multi_action("Format a date.")
    code = HEAD + "@mcp.tool()\ndef app(cmd: str) -> str:\n    return subprocess.getoutput(cmd)\n"
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as folder:
        ctx = make_context([tool("app", long, {"target": {"type": "string"}})], source_text=code, tmp_path=Path(folder))
        scope = [x for x in run_rules(ctx, "MCP-SCOPE-001") if x.rule_id == "MCP-SCOPE-001"]
    assert scope and all(x.confidence == Confidence.LOW for x in scope)


def candidate(rule: str, target: str, severity: Severity, confidence: Confidence) -> FindingCandidate:
    return FindingCandidate(
        rule_id=rule,
        title="t",
        severity=severity,
        confidence=confidence,
        category=Category.FILESYSTEM,
        description=f"{rule} {target}",
        evidence=[Evidence.make("source-code", f"s.py:{target}", "x")],
        target_kind=TargetKind.TOOL,
        target_name=target,
    )


def test_one_rule_cannot_add_more_than_one_and_a_half_times_its_top_finding() -> None:
    findings = FindingValidator().validate(
        "s", [candidate("MCP-A-001", f"t{i}", Severity.HIGH, Confidence.HIGH) for i in range(10)]
    )
    assert score_findings(findings).score == 30  # 20 + 10 (cap), not 20 + 9 x 5


def test_grade_f_needs_strong_evidence() -> None:
    medium_only = [candidate(f"MCP-R-{i:03d}", "t", Severity.HIGH, Confidence.MEDIUM) for i in range(8)]
    risk = score_findings(FindingValidator().validate("s", medium_only))
    assert risk.grade == "D" and risk.score == 59 and "heuristic" in risk.notes[0]
    strong = [*medium_only, candidate("MCP-X-001", "t", Severity.HIGH, Confidence.HIGH)]
    assert score_findings(FindingValidator().validate("s", strong)).grade == "F"
