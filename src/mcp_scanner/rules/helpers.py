# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Small helpers shared by built-in rules."""

from __future__ import annotations

from mcp_scanner.analyzers.capabilities import Capability, Signal, ToolCapabilities
from mcp_scanner.analyzers.source.facts import CodeHit, SourceFacts
from mcp_scanner.models.finding import Evidence, TargetKind
from mcp_scanner.models.severity import Confidence


def signal_evidence(signals: list[Signal], limit: int = 3) -> list[Evidence]:
    ordered = sorted(signals, key=lambda s: not s.strong)[:limit]
    return [
        Evidence.make("schema" if s.strong else "text-match", s.location, s.snippet or s.reason, s.reason)
        for s in ordered
    ]


def capability_confidence(caps: ToolCapabilities, cap: Capability) -> Confidence:
    """Strong (schema) signals are high confidence. Two weak signals are medium. One weak signal is a guess."""
    if caps.strong(cap):
        return Confidence.HIGH
    return Confidence.MEDIUM if len(caps.signals.get(cap, [])) >= 2 else Confidence.LOW


def hit_target(hit: CodeHit) -> tuple[TargetKind, str]:
    """Source hits inside a tool are reported on that tool, so they can back up metadata findings."""
    if hit.tool:
        return TargetKind.TOOL, hit.tool
    where = f"{hit.file}:{hit.function}" if hit.function else hit.file
    return TargetKind.SOURCE, where


def code_evidence(hit: CodeHit) -> Evidence:
    detail = hit.detail
    if hit.tainted_params:
        detail += f"; tool input reaches it: {', '.join(hit.tainted_params)}"
    elif hit.tainted:
        detail += "; built from a variable"
    return Evidence.make("source-code", hit.location, hit.snippet, detail)


def lower_for_js(hit: CodeHit, confidence: Confidence) -> Confidence:
    """The JavaScript checks are line patterns, so they are less sure than the Python AST checks."""
    return confidence.lowered() if hit.language == "javascript" else confidence


def function_has(source: SourceFacts, hit: CodeHit, *categories: str) -> bool:
    return any(source.same_function(hit, c) for c in categories)
