# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Eval cases: a target plus what the scanner should and should not find.

Each case is a folder in `src/evals/cases/` with a `case.yaml`:

    name: poisoned-notes
    description: Tool descriptions hide orders for the agent.
    malicious: true
    target: "{python} {root}/servers/poisoned_server.py"
    source: "{root}/servers/poisoned_server.py"      # optional
    dynamic: true
    expect:
      must_find: [MCP-POISON-001, MCP-POISON-002]
      must_not_find: [MCP-EXEC-001]
      min_grade: D          # at least this bad (malicious cases)
      max_grade: B          # at most this bad (benign cases)
      allow: [MCP-QUALITY]  # benign cases: these rules do not count as false positives

`{python}` is the Python that runs the scanner. `{root}` is the evals folder.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mcp_scanner.core.errors import ConfigError

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


class Expectation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    must_find: list[str] = Field(default_factory=list)
    must_not_find: list[str] = Field(default_factory=list)
    min_grade: str | None = None
    max_grade: str | None = None
    allow: list[str] = Field(default_factory=list)


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    malicious: bool
    target: str
    source: str | None = None
    dynamic: bool = False
    connect: bool = True
    tags: list[str] = Field(default_factory=list)
    expect: Expectation = Field(default_factory=Expectation)
    path: str = ""

    def resolved(self, root: Path) -> EvalCase:
        """Fill {python} and {root} placeholders."""
        python = f'"{sys.executable}"' if " " in sys.executable else sys.executable
        values = {"python": python, "root": root.resolve().as_posix()}

        def fill(text: str | None) -> str | None:
            return text.format(**values) if text else text

        return self.model_copy(update={"target": fill(self.target), "source": fill(self.source)})

    @property
    def starts_server(self) -> bool:
        target = self.target.strip()
        return not target.lower().endswith((".json", ".yaml", ".yml")) and not target.startswith("http")


def load_cases(root: Path, only: list[str] | None = None) -> list[EvalCase]:
    folder = root / "cases"
    if not folder.is_dir():
        raise ConfigError(f"No eval cases folder at {folder}")
    cases = []
    for path in sorted(folder.glob("*/case.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            case = EvalCase.model_validate({**data, "path": str(path)})
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigError(f"Invalid eval case {path}: {exc}") from exc
        if only and case.name not in only and path.parent.name not in only:
            continue
        cases.append(case.resolved(root))
    return cases
