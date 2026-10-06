# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Load and check skills.

A skill is a folder with a SKILL.md file. The YAML front matter at the top says
what the skill is, which inputs it takes, and a `workflow` of steps. The rest of
the file is plain instructions that any agent or person can follow.

Skills are data only. They cannot run their own code, and they can only use a
short list of safe actions. They cannot turn on host execution or dangerous tool
calls; only the person running the scanner can do that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcp_scanner.core.errors import SkillError

SKILL_FILE = "SKILL.md"
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_REF = re.compile(r"\$\{inputs\.([A-Za-z_][A-Za-z0-9_]*)\}")

# Action -> options a step may set. Anything else is rejected.
ACTIONS: dict[str, set[str]] = {
    "scan": {
        "target",
        "discover",
        "server",
        "dynamic",
        "ai",
        "ai_provider",
        "ai_model",
        "min_severity",
        "fail_on",
        "formats",
        "output",
        "rules",
        "disable_rules",
        "source",
        "transport",
    },
    "inspect": {"target", "server", "transport"},
    "discover": set(),
    "report": {"formats", "output"},
}


class SkillInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = ""
    required: bool = False
    default: Any = None


class SkillStep(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    action: str
    id: str | None = None
    name: str | None = None
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")

    @field_validator("action")
    @classmethod
    def _known_action(cls, value: str) -> str:
        if value not in ACTIONS:
            raise ValueError(f"unknown action '{value}'. Allowed: {', '.join(ACTIONS)}")
        return value


class SkillMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = Field(min_length=10)
    version: str = "1.0.0"
    tags: list[str] = Field(default_factory=list)
    inputs: dict[str, SkillInput] = Field(default_factory=dict)
    workflow: list[SkillStep] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def _name_format(cls, value: str) -> str:
        if not _NAME.match(value):
            raise ValueError("name must use lower case letters, digits, and dashes")
        return value


@dataclass
class Skill:
    meta: SkillMeta
    path: Path
    body: str
    problems: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.meta.name


def split_front_matter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        raise SkillError("SKILL.md must start with '---' front matter")
    parts = text.split("\n---", 1)
    if len(parts) != 2:
        raise SkillError("SKILL.md front matter has no closing '---'")
    head = parts[0][3:]
    body = parts[1].lstrip("-").lstrip("\n")
    try:
        data = yaml.safe_load(head) or {}
    except yaml.YAMLError as exc:
        raise SkillError(f"front matter is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SkillError("front matter must be a YAML mapping")
    return data, body


def load_skill(folder: Path) -> Skill:
    path = folder / SKILL_FILE
    if not path.is_file():
        raise SkillError(f"{folder} has no {SKILL_FILE}")
    data, body = split_front_matter(path.read_text(encoding="utf-8"))
    try:
        meta = SkillMeta.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
        raise SkillError(f"{path}: {problems}") from exc
    skill = Skill(meta=meta, path=path, body=body)
    skill.problems = check_skill(skill)
    return skill


def check_skill(skill: Skill) -> list[str]:
    """Problems the schema cannot catch on its own."""
    problems = []
    if skill.path.parent.name != skill.name:
        problems.append(f"folder name '{skill.path.parent.name}' should match the skill name '{skill.name}'")
    if not skill.body.strip():
        problems.append("the instructions below the front matter are empty")
    declared = set(skill.meta.inputs)
    for index, step in enumerate(skill.meta.workflow, start=1):
        unknown = set(step.with_) - ACTIONS[step.action]
        if unknown:
            problems.append(f"step {index} ({step.action}) has unknown options: {', '.join(sorted(unknown))}")
        for value in step.with_.values():
            for ref in _REF.findall(str(value)):
                if ref not in declared:
                    problems.append(f"step {index} uses ${{inputs.{ref}}} but no input '{ref}' is declared")
        if step.action == "report" and not any(s.action == "scan" for s in skill.meta.workflow[: index - 1]):
            problems.append(f"step {index} (report) needs a scan step before it")
    return problems


def skill_dirs(extra: list[str] | None = None) -> list[Path]:
    """Where skills live: bundled, the repo 'skills' folder, the user folder, and extra folders."""
    dirs: list[Path] = []
    try:
        bundled = Path(str(resources.files("mcp_scanner").joinpath("bundled", "skills")))
        dirs.append(bundled)
    except (ModuleNotFoundError, TypeError):
        pass
    repo = Path(__file__).resolve().parents[2] / "skills"
    dirs += [repo, Path.home() / ".aevrin-mcp-scanner" / "skills", Path.cwd() / "skills"]
    dirs += [Path(p).expanduser() for p in extra or []]
    seen: set[Path] = set()
    unique = []
    for d in dirs:
        resolved = d.resolve()
        if resolved not in seen and d.is_dir():
            seen.add(resolved)
            unique.append(d)
    return unique


def discover_skills(extra: list[str] | None = None) -> tuple[list[Skill], list[str]]:
    """Return (skills, load errors). Later folders win when two skills share a name."""
    found: dict[str, Skill] = {}
    errors: list[str] = []
    for folder in skill_dirs(extra):
        for child in sorted(folder.iterdir()):
            if not (child / SKILL_FILE).is_file():
                continue
            try:
                skill = load_skill(child)
            except SkillError as exc:
                errors.append(str(exc))
                continue
            found[skill.name] = skill
    return sorted(found.values(), key=lambda s: s.name), errors


def find_skill(name: str, extra: list[str] | None = None) -> Skill:
    direct = Path(name).expanduser()
    if (direct / SKILL_FILE).is_file():
        return load_skill(direct)
    skills, _ = discover_skills(extra)
    for skill in skills:
        if skill.name == name:
            return skill
    raise SkillError(f"No skill named '{name}'. See `mcp-scanner skills list`.")


def resolve_inputs(skill: Skill, given: dict[str, str]) -> dict[str, Any]:
    unknown = set(given) - set(skill.meta.inputs)
    if unknown:
        raise SkillError(f"Unknown input(s) for skill '{skill.name}': {', '.join(sorted(unknown))}")
    values: dict[str, Any] = {}
    for name, spec in skill.meta.inputs.items():
        if name in given:
            values[name] = given[name]
        elif spec.default is not None:
            values[name] = spec.default
        elif spec.required:
            raise SkillError(f"Skill '{skill.name}' needs the input '{name}': {spec.description}")
    return values


def interpolate(value: Any, inputs: dict[str, Any]) -> Any:
    """Fill ${inputs.x} placeholders. A value that is only a placeholder keeps the input's type."""
    if isinstance(value, str):
        whole = _REF.fullmatch(value.strip())
        if whole:
            return inputs.get(whole.group(1))
        return _REF.sub(lambda m: str(inputs.get(m.group(1), "")), value)
    if isinstance(value, list):
        return [interpolate(v, inputs) for v in value]
    if isinstance(value, dict):
        return {k: interpolate(v, inputs) for k, v in value.items()}
    return value
