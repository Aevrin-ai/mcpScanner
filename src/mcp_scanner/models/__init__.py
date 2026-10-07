# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Shared data models. Every part of the scanner talks using these."""

from mcp_scanner.models.ai import AIObservation, AIReview, AIUsage
from mcp_scanner.models.finding import (
    AnalysisKind,
    Evidence,
    Finding,
    FindingAIReview,
    FindingCandidate,
    TargetKind,
)
from mcp_scanner.models.mcp import (
    PromptArgument,
    PromptInfo,
    ResourceInfo,
    ResourceTemplateInfo,
    ServerInventory,
    ToolInfo,
)
from mcp_scanner.models.observations import (
    DynamicObservations,
    NetworkEvent,
    ProcessEvent,
    ProtocolEvent,
    SandboxObservations,
    ToolCallRecord,
    ToolChange,
)
from mcp_scanner.models.result import (
    ScanError,
    ScanOptionsSummary,
    ScanReport,
    ScanStatus,
    ServerResult,
)
from mcp_scanner.models.risk import RiskFactor, RiskScore
from mcp_scanner.models.server import ServerSpec, TransportType
from mcp_scanner.models.severity import Category, Confidence, Severity, ValidationStatus

__all__ = [
    "AIObservation",
    "AIReview",
    "AIUsage",
    "AnalysisKind",
    "Category",
    "Confidence",
    "DynamicObservations",
    "Evidence",
    "Finding",
    "FindingAIReview",
    "FindingCandidate",
    "NetworkEvent",
    "ProcessEvent",
    "PromptArgument",
    "PromptInfo",
    "ProtocolEvent",
    "ResourceInfo",
    "ResourceTemplateInfo",
    "RiskFactor",
    "RiskScore",
    "SandboxObservations",
    "ScanError",
    "ScanOptionsSummary",
    "ScanReport",
    "ScanStatus",
    "ServerInventory",
    "ServerResult",
    "ServerSpec",
    "Severity",
    "TargetKind",
    "ToolCallRecord",
    "ToolChange",
    "ToolInfo",
    "TransportType",
    "ValidationStatus",
]
