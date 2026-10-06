# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Simple custom rules written in YAML.

A YAML rule searches text surfaces with a regular expression. Example:

    id: CUSTOM-001
    title: Mentions our internal hostname
    severity: medium
    category: data-exfiltration
    confidence: high
    description: A tool mentions the internal billing host.
    recommendation: Remove internal hostnames from tool metadata.
    match:
      pattern: "billing\\.internal\\.example"
      surfaces: [tool-description, param-description]   # optional
      tool_name: "^billing_"                             # optional

One file may hold one rule, or a list under `rules:`.
YAML rules cannot run code. They only match text.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcp_scanner.analyzers.text import excerpt, normalize
from mcp_scanner.core.errors import ConfigError
from mcp_scanner.models.finding import Evidence, FindingCandidate
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import Rule
from mcp_scanner.rules.matching import looks_defensive
from mcp_scanner.scanner.context import ScanContext

_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
SURFACE_KINDS = {
    "instructions",
    "tool-name",
    "tool-title",
    "tool-description",
    "tool-annotation",
    "param-description",
    "param-value",
    "param-name",
    "prompt-description",
    "prompt-argument",
    "prompt-text",
    "resource-description",
    "resource-text",
    "tool-output",
}


class YamlMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str | None = None
    patterns: list[str] = Field(default_factory=list)
    surfaces: list[str] = Field(default_factory=list)
    tool_name: str | None = None
    case_sensitive: bool = False

    @field_validator("surfaces")
    @classmethod
    def _known_surfaces(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - SURFACE_KINDS)
        if unknown:
            raise ValueError(f"unknown surface kinds: {', '.join(unknown)}")
        return value

    def all_patterns(self) -> list[str]:
        return ([self.pattern] if self.pattern else []) + self.patterns


class YamlRuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    severity: Severity
    category: Category = Category.QUALITY
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    why_it_matters: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    malicious: bool = False
    match: YamlMatch

    @field_validator("id")
    @classmethod
    def _id_format(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError("id must look like 'CUSTOM-001' (capital letters, digits, dashes)")
        return value


class YamlRule(Rule):
    origin: ClassVar[str] = "yaml"

    def __init__(self, spec: YamlRuleSpec, path: str) -> None:
        self.spec = spec
        self.path = path
        flags = 0 if spec.match.case_sensitive else re.IGNORECASE
        self._regexes = [re.compile(p, flags | re.MULTILINE) for p in spec.match.all_patterns()]
        self._tool_name = re.compile(spec.match.tool_name) if spec.match.tool_name else None
        # Instance fields shadow the class fields, so the base class helpers work unchanged.
        self.id = spec.id  # type: ignore[misc]
        self.title = spec.title  # type: ignore[misc]
        self.category = spec.category  # type: ignore[misc]
        self.severity = spec.severity  # type: ignore[misc]
        self.description = spec.description  # type: ignore[misc]
        self.why_it_matters = spec.why_it_matters  # type: ignore[misc]
        self.recommendation = spec.recommendation  # type: ignore[misc]
        self.references = tuple(spec.references)  # type: ignore[misc]

    def summary(self) -> dict[str, Any]:
        data = super().summary()
        data["origin"] = f"yaml ({self.path})"
        return data

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        wanted = set(self.spec.match.surfaces)
        for surface in ctx.surfaces:
            if wanted and surface.kind not in wanted:
                continue
            if self._tool_name and not self._tool_name.search(surface.target_name):
                continue
            text = normalize(surface.text)
            for regex in self._regexes:
                match = regex.search(text)
                if not match:
                    continue
                confidence = (
                    Confidence.LOW if looks_defensive(text, match.start(), match.end()) else self.spec.confidence
                )
                yield self.finding(
                    surface.target_kind,
                    surface.target_name,
                    self.spec.description or f"Custom rule {self.id} matched.",
                    [
                        Evidence.make(
                            "text-match",
                            surface.location,
                            excerpt(text, match.start(), match.end()),
                            f"pattern {regex.pattern}",
                        )
                    ],
                    confidence=confidence,
                    malicious=self.spec.malicious,
                    context_text=text[max(0, match.start() - 60) : match.start()],
                )
                break


def load_yaml_rules(folder: str | Path) -> list[YamlRule]:
    """Load every *.yaml / *.yml rule file in a folder. Raises ConfigError with a clear message."""
    root = Path(folder).expanduser()
    if not root.is_dir():
        raise ConfigError(f"Rules folder not found: {root}")
    rules: list[YamlRule] = []
    for path in sorted([*root.glob("*.yaml"), *root.glob("*.yml")]):
        rules.extend(load_yaml_rule_file(path))
    return rules


def load_yaml_rule_file(path: Path) -> list[YamlRule]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Could not read rule file {path}: {exc}") from exc
    items: list[Any] = doc.get("rules", []) if isinstance(doc, dict) and "rules" in doc else [doc]
    rules = []
    for index, item in enumerate(items):
        try:
            spec = YamlRuleSpec.model_validate(item)
            rules.append(YamlRule(spec, str(path)))
        except ValidationError as exc:
            problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
            raise ConfigError(f"Invalid rule #{index + 1} in {path}: {problems}") from exc
        except re.error as exc:
            raise ConfigError(f"Invalid regular expression in {path}: {exc}") from exc
    return rules
