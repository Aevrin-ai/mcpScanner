# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Models for risk scores."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    """One line in the "why is the score this number" table."""

    finding_id: str
    rule_id: str
    target: str
    severity: str
    confidence: str
    points: float
    reason: str


class RiskScore(BaseModel):
    """The risk of one server. 0 is best, 100 is worst."""

    score: float = 0.0
    grade: str = "A"
    label: str = "No known risk"
    factors: list[RiskFactor] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
