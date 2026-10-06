# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Models for AI analysis results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AIUsage(BaseModel):
    """How much AI was used. Cost is only filled when prices are configured."""

    provider: str | None = None
    model: str | None = None
    calls: int = 0
    failed_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float | None = None

    def add(self, other: AIUsage) -> None:
        self.calls += other.calls
        self.failed_calls += other.failed_calls
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        if other.estimated_cost_usd is not None:
            self.estimated_cost_usd = (self.estimated_cost_usd or 0.0) + other.estimated_cost_usd


class AIObservation(BaseModel):
    """Something the AI noticed that no rule found. Always treated as unverified."""

    target: str
    title: str
    description: str
    suggested_severity: str = "low"


class AIReview(BaseModel):
    """The full AI result for one server."""

    enabled: bool = False
    provider: str | None = None
    model: str | None = None
    summary: str | None = None
    observations: list[AIObservation] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    usage: AIUsage = Field(default_factory=AIUsage)
    skipped_reason: str | None = None
