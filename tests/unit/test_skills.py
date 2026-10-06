from pathlib import Path

import pytest

from mcp_scanner.config.settings import Settings
from mcp_scanner.core.errors import SkillError
from mcp_scanner.scanner.engine import ScanEngine
from mcp_scanner.skills.loader import discover_skills, interpolate, load_skill, resolve_inputs, split_front_matter
from mcp_scanner.skills.runner import SkillRunner

ROOT = Path(__file__).resolve().parents[2]
TOOLS_FILE = ROOT / "src" / "evals" / "tools" / "poisoned_tools.json"


def make_skill(folder: Path, front: str, body: str = "Instructions for the agent.\n") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SKILL.md").write_text(f"---\n{front}\n---\n{body}", encoding="utf-8")
    return folder


def test_bundled_skills_are_valid() -> None:
    skills, errors = discover_skills()
    names = {s.name for s in skills}
    assert {"quick-scan", "deep-audit", "audit-client-configs", "ci-gate"} <= names
    assert not errors
    assert all(not s.problems for s in skills), [(s.name, s.problems) for s in skills]


def test_front_matter_errors() -> None:
    with pytest.raises(SkillError):
        split_front_matter("no front matter")
    with pytest.raises(SkillError):
        split_front_matter("---\nname: x\n")


def test_unknown_action_is_rejected(tmp_path: Path) -> None:
    folder = make_skill(
        tmp_path / "bad-skill",
        "name: bad-skill\ndescription: Runs a shell script.\nworkflow:\n  - action: shell\n    with: {cmd: ls}",
    )
    with pytest.raises(SkillError, match="unknown action"):
        load_skill(folder)


def test_problems_are_found(tmp_path: Path) -> None:
    folder = make_skill(
        tmp_path / "other-name",
        "name: my-skill\ndescription: A skill with mistakes.\nworkflow:\n  - action: report\n  - action: scan\n    with: {target: '${inputs.missing}', allow_host: true}",
        body="",
    )
    problems = " | ".join(load_skill(folder).problems)
    assert "folder name" in problems
    assert "instructions below the front matter are empty" in problems
    assert "unknown options: allow_host" in problems
    assert "inputs.missing" in problems
    assert "needs a scan step before it" in problems


def test_inputs_and_interpolation(tmp_path: Path) -> None:
    folder = make_skill(
        tmp_path / "in-skill",
        "name: in-skill\ndescription: Checks inputs work.\ninputs:\n  target: {required: true}\n  level: {default: high}\nworkflow:\n  - action: scan\n    with: {target: '${inputs.target}'}",
    )
    skill = load_skill(folder)
    with pytest.raises(SkillError, match="needs the input 'target'"):
        resolve_inputs(skill, {})
    with pytest.raises(SkillError, match="Unknown input"):
        resolve_inputs(skill, {"target": "x", "nope": "y"})
    values = resolve_inputs(skill, {"target": "x"})
    assert values == {"target": "x", "level": "high"}
    assert interpolate({"a": "${inputs.target}", "b": ["pre-${inputs.level}"], "c": 3}, values) == {
        "a": "x",
        "b": ["pre-high"],
        "c": 3,
    }


def test_runner_scans_through_the_engine(tmp_path: Path) -> None:
    folder = make_skill(
        tmp_path / "offline-check",
        "name: offline-check\ndescription: Scan a tools file and write Markdown.\ninputs:\n  target: {required: true}\n"
        f"workflow:\n  - action: scan\n    with: {{target: '${{inputs.target}}', formats: [json], output: '{tmp_path.as_posix()}', fail_on: high}}\n"
        f"  - action: report\n    with: {{formats: [markdown], output: '{tmp_path.as_posix()}'}}",
    )
    settings = Settings()
    settings.scan.pins_file = str(tmp_path / "pins.json")
    messages: list[str] = []
    runner = SkillRunner(settings, ScanEngine, lambda label, text: messages.append(label + text))
    result = runner.run(load_skill(folder), {"target": str(TOOLS_FILE)})
    assert result.exit_code == 1  # the poisoned tools file has high findings
    assert {p.suffix for p in result.files} == {".json", ".md"}
    assert result.reports[0].servers[0].findings
    assert messages


def test_runner_refuses_invalid_skill(tmp_path: Path) -> None:
    folder = make_skill(
        tmp_path / "wrong-folder",
        "name: right-name\ndescription: Folder does not match.\nworkflow:\n  - action: discover",
    )
    with pytest.raises(SkillError, match="not valid"):
        SkillRunner(Settings(), ScanEngine, lambda a, b: None).run(load_skill(folder), {})
