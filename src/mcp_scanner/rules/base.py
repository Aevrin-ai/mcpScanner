# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The base class for every security rule.

A rule is one idea, for example "a tool description tells the agent to hide things
from the user". It reads facts from the ScanContext and returns FindingCandidates.

To add a rule, write a small subclass in `rules/builtin/` and set the class fields.
The registry finds it automatically.

    class MyRule(Rule):
        id = "MCP-EXAMPLE-001"
        title = "Example"
        category = Category.QUALITY
        severity = Severity.LOW
        description = "What the rule checks."
        recommendation = "What to do about it."

        def check(self, ctx):
            for tool in ctx.tools:
                if not tool.description:
                    yield self.finding(TargetKind.TOOL, tool.name, "No description.", [...])
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

from mcp_scanner.models.finding import AnalysisKind, Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity

if TYPE_CHECKING:
    from mcp_scanner.scanner.context import ScanContext

# Things a rule may need. If a need is missing, the rule is skipped, not failed.
NEEDS_SOURCE = "source"
NEEDS_DYNAMIC = "dynamic"
NEEDS_DEPENDENCIES = "dependencies"


class Rule:
    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    category: ClassVar[Category] = Category.QUALITY
    severity: ClassVar[Severity] = Severity.INFO
    description: ClassVar[str] = ""
    why_it_matters: ClassVar[str] = ""
    attack_scenario: ClassVar[str] = ""
    recommendation: ClassVar[str] = ""
    references: ClassVar[tuple[str, ...]] = ()
    needs: ClassVar[frozenset[str]] = frozenset()
    analysis: ClassVar[AnalysisKind] = AnalysisKind.STATIC
    # Where the rule came from: "builtin", "yaml", or "plugin".
    origin: ClassVar[str] = "builtin"

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        raise NotImplementedError

    def can_run(self, ctx: ScanContext) -> str | None:
        """Return a reason when the rule cannot run on this context, else None."""
        if NEEDS_SOURCE in self.needs and ctx.source is None:
            return "no source code"
        if NEEDS_DYNAMIC in self.needs and not ctx.dynamic_enabled:
            return "dynamic analysis is off"
        if NEEDS_DEPENDENCIES in self.needs and ctx.dependencies is None:
            return "no dependency data"
        return None

    def finding(
        self,
        target_kind: TargetKind,
        target_name: str,
        description: str,
        evidence: list[Evidence],
        *,
        confidence: Confidence = Confidence.MEDIUM,
        severity: Severity | None = None,
        title: str | None = None,
        malicious: bool = False,
        confirmed: bool = False,
        context_text: str = "",
        analysis: AnalysisKind | None = None,
        recommendation: str | None = None,
    ) -> FindingCandidate:
        """Build a candidate with this rule's fixed fields filled in."""
        return FindingCandidate(
            rule_id=self.id,
            title=title or self.title,
            severity=severity or self.severity,
            confidence=confidence,
            category=self.category,
            description=description,
            evidence=evidence,
            target_kind=target_kind,
            target_name=target_name,
            why_it_matters=self.why_it_matters,
            attack_scenario=self.attack_scenario,
            recommendation=recommendation or self.recommendation,
            references=list(self.references),
            analysis=analysis or self.analysis,
            confirmed=confirmed,
            malicious=malicious,
            context_text=context_text,
        )

    def summary(self) -> dict[str, Any]:
        """Rule data for `mcp-scanner rules` and the docs."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "why_it_matters": self.why_it_matters,
            "attack_scenario": self.attack_scenario,
            "recommendation": self.recommendation,
            "references": list(self.references),
            "needs": sorted(self.needs),
            "origin": self.origin,
        }
