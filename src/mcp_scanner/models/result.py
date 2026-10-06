# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Models for scan results and the final report."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mcp_scanner.models.ai import AIReview, AIUsage
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.mcp import ServerInventory
from mcp_scanner.models.observations import DynamicObservations
from mcp_scanner.models.risk import RiskScore
from mcp_scanner.models.severity import Severity

REPORT_SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanStatus(str, Enum):
    COMPLETED = "completed"  # every stage worked
    PARTIAL = "partial"  # some stages failed, results are incomplete
    FAILED = "failed"  # we could not scan the server at all


class ScanError(BaseModel):
    """A problem during the scan. Messages never contain secrets."""

    stage: str
    message: str
    fatal: bool = False


class PrescannedFinding(BaseModel):
    severity: str
    title: str
    description: str = ""
    tool: str | None = None


class PrescannedReport(BaseModel):
    """A public report from an earlier scan of the same server, made elsewhere.

    Shown only when this scan could not finish or found no tools. It is never mixed
    into this scan's findings or score.
    """

    grade: str
    score: float = 0.0
    version: str = ""
    scanned_at: str = ""
    source_url: str = ""
    tools: list[str] = Field(default_factory=list)
    findings: list[PrescannedFinding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ServerResult(BaseModel):
    """Everything we learned about one server."""

    server: dict[str, Any]
    status: ScanStatus = ScanStatus.COMPLETED
    inventory: ServerInventory = Field(default_factory=ServerInventory)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskScore = Field(default_factory=RiskScore)
    errors: list[ScanError] = Field(default_factory=list)
    rules_run: list[str] = Field(default_factory=list)
    observations: DynamicObservations = Field(default_factory=DynamicObservations)
    ai: AIReview = Field(default_factory=AIReview)
    # A public report from an earlier scan, when this one could not finish. Not part of the score.
    prescanned: PrescannedReport | None = None
    duration_seconds: float = 0.0
    stage_seconds: dict[str, float] = Field(default_factory=dict)

    @property
    def name(self) -> str:
        return str(self.server.get("name", "unknown"))

    @property
    def active_findings(self) -> list[Finding]:
        """Findings that are not suppressed and not likely false positives."""
        return [f for f in self.findings if f.counts_for_risk]

    @property
    def is_safe(self) -> bool | None:
        """True, False, or None. None means "we do not know", because the scan was incomplete.

        A failed scan must never look like a clean scan.
        """
        if any(f.severity.at_least(Severity.LOW) for f in self.active_findings):
            return False
        if self.status != ScanStatus.COMPLETED:
            return None
        return True

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.active_findings:
            counts[finding.severity.value] += 1
        return counts


class ScanOptionsSummary(BaseModel):
    """The settings a scan used, for the report. No secrets here."""

    dynamic: bool = False
    sandbox_mode: str = "auto"
    ai_enabled: bool = False
    ai_provider: str | None = None
    ai_model: str | None = None
    min_severity: str = "info"
    rules_selected: list[str] = Field(default_factory=list)
    source_path: str | None = None


class ProductInfo(BaseModel):
    """Who made the scanner that wrote this report, and under which license it ran."""

    name: str
    vendor: str
    version: str
    copyright: str
    license: str  # SPDX identifier of the source license
    license_state: str  # see licensing/license.py STATES
    licensee: str | None = None
    license_id: str | None = None
    license_notice: str
    build: str  # "official", "modified", or "development"
    build_notice: str | None = None


class ScanReport(BaseModel):
    """The full output of one scan run."""

    schema_version: str = REPORT_SCHEMA_VERSION
    scanner: str = "Aevrin MCP Scanner"
    scanner_version: str = ""
    scan_id: str = ""
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    options: ScanOptionsSummary = Field(default_factory=ScanOptionsSummary)
    servers: list[ServerResult] = Field(default_factory=list)
    ai_usage: AIUsage = Field(default_factory=AIUsage)
    errors: list[ScanError] = Field(default_factory=list)
    # Branding and license status. Filled by the engine, and by every reporter if missing.
    product: ProductInfo | None = None

    @property
    def status(self) -> ScanStatus:
        if not self.servers:
            return ScanStatus.FAILED
        statuses = {s.status for s in self.servers}
        if statuses == {ScanStatus.COMPLETED}:
            return ScanStatus.COMPLETED
        if statuses == {ScanStatus.FAILED}:
            return ScanStatus.FAILED
        return ScanStatus.PARTIAL

    def all_findings(self) -> list[Finding]:
        return [f for s in self.servers for f in s.findings]

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for server in self.servers:
            for key, value in server.severity_counts().items():
                counts[key] += value
        return counts

    def worst_severity(self) -> Severity | None:
        active = [f for s in self.servers for f in s.active_findings]
        if not active:
            return None
        return max((f.severity for f in active), key=lambda s: s.rank)
