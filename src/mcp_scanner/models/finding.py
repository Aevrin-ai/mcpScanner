# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Models for security findings."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field

from mcp_scanner.models.severity import Category, Confidence, Severity, ValidationStatus

MAX_SNIPPET = 400


class TargetKind(str, Enum):
    """What part of the server a finding is about."""

    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"
    SERVER = "server"
    CONFIG = "config"
    SOURCE = "source"
    DEPENDENCY = "dependency"


class AnalysisKind(str, Enum):
    """Which kind of analysis produced the finding."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    AI = "ai"


class Evidence(BaseModel):
    """One piece of proof. Short, so reports stay readable."""

    kind: str
    location: str
    snippet: str = ""
    detail: str | None = None

    @classmethod
    def make(cls, kind: str, location: str, snippet: str = "", detail: str | None = None) -> Evidence:
        text = snippet if len(snippet) <= MAX_SNIPPET else snippet[:MAX_SNIPPET] + "...(cut)"
        return cls(kind=kind, location=location, snippet=text, detail=detail)


class FindingCandidate(BaseModel):
    """What a rule returns. The validator turns it into a Finding."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    target_kind: TargetKind
    target_name: str
    why_it_matters: str = ""
    attack_scenario: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    analysis: AnalysisKind = AnalysisKind.STATIC
    # True when dynamic evidence proves the problem is real.
    confirmed: bool = False
    # True when the evidence shows hostile intent, not just risk.
    malicious: bool = False
    # Text near the match, used by the validator to look for negation.
    context_text: str = ""

    def dedupe_key(self) -> str:
        first = self.evidence[0] if self.evidence else None
        location = first.location if first else ""
        return f"{self.rule_id}|{self.target_kind.value}|{self.target_name}|{location}"


class FindingAIReview(BaseModel):
    """What the AI thought about one finding. It never changes the severity."""

    verdict: str  # "likely-real", "likely-false-positive", or "unsure"
    explanation: str
    provider: str
    model: str


class Finding(FindingCandidate):
    """A validated finding as it appears in reports."""

    id: str
    server: str
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    validation_notes: list[str] = Field(default_factory=list)
    risk_points: float = 0.0
    ai_review: FindingAIReview | None = None

    @staticmethod
    def make_id(server: str, candidate: FindingCandidate) -> str:
        """A stable ID, so the same finding has the same ID in every scan."""
        raw = f"{server}|{candidate.dedupe_key()}".encode()
        return "F-" + hashlib.sha256(raw).hexdigest()[:10]

    @property
    def counts_for_risk(self) -> bool:
        return self.validation_status.counts_for_risk
