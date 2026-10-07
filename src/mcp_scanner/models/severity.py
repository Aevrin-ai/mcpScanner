# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Severity, confidence, category, and validation status values."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """How bad a finding is if it is real."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Bigger number means worse. Used for sorting and thresholds."""
        return _SEVERITY_RANK[self.value]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Use one of: {allowed}") from exc


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Confidence(str, Enum):
    """How sure we are that a finding is real."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    def raised(self) -> Confidence:
        return Confidence.MEDIUM if self is Confidence.LOW else Confidence.HIGH

    def lowered(self) -> Confidence:
        return Confidence.MEDIUM if self is Confidence.HIGH else Confidence.LOW


class Category(str, Enum):
    """The kind of problem a finding describes."""

    PROMPT_INJECTION = "prompt-injection"
    TOOL_POISONING = "tool-poisoning"
    TOOL_SHADOWING = "tool-shadowing"
    COMMAND_EXECUTION = "command-execution"
    CODE_EXECUTION = "code-execution"
    FILESYSTEM = "filesystem-access"
    NETWORK = "network-access"
    DATA_EXFILTRATION = "data-exfiltration"
    SECRETS = "secrets"
    PRIVILEGE = "privilege-escalation"
    EXCESSIVE_PERMISSIONS = "excessive-permissions"
    INJECTION = "injection"
    SUPPLY_CHAIN = "supply-chain"
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    RUNTIME_BEHAVIOR = "runtime-behavior"
    PROTOCOL = "protocol"
    QUALITY = "quality"


class ValidationStatus(str, Enum):
    """What the validator decided about a finding."""

    CONFIRMED = "confirmed"  # proven by dynamic evidence
    VALIDATED = "validated"  # strong deterministic evidence
    UNVERIFIED = "unverified"  # heuristic match, a human should look
    LIKELY_FALSE_POSITIVE = "likely-false-positive"
    SUPPRESSED = "suppressed"  # a user said to ignore it

    @property
    def counts_for_risk(self) -> bool:
        return self in (
            ValidationStatus.CONFIRMED,
            ValidationStatus.VALIDATED,
            ValidationStatus.UNVERIFIED,
        )
