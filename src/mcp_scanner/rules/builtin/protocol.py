# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Protocol behavior: what the server did on the wire."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_scanner.models.finding import AnalysisKind, Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import Rule
from mcp_scanner.scanner.context import ScanContext

SPEC = "https://modelcontextprotocol.io/specification/2025-11-25"
OLD_PROTOCOLS = {"2024-10-07", "2024-11-05"}


def _events(ctx: ScanContext, *kinds: str) -> list:
    return [e for e in ctx.observations.protocol_events if e.kind in kinds]


class ServerRequestsClient(Rule):
    id = "MCP-PROTO-001"
    title = "Server asked the client for extra powers"
    category = Category.PROTOCOL
    severity = Severity.MEDIUM
    description = "The server sent requests like sampling/createMessage, elicitation/create, or roots/list, even though the scanner said it does not support them."
    why_it_matters = (
        "Sampling lets a server use your AI model and your money with its own prompts. Elicitation asks the user for "
        "data. A server that asks without being offered may be probing for weak clients."
    )
    attack_scenario = "During tools/list the server asks the client model to 'summarize the user's recent files'."
    recommendation = "Deny sampling and elicitation for this server in your client unless you need them."
    references = (f"{SPEC}/client/sampling",)
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        methods = sorted({e.method or "unknown" for e in _events(ctx, "server-request")})
        if not methods:
            return
        sampling = any(m.startswith("sampling/") for m in methods)
        yield self.finding(
            TargetKind.SERVER,
            ctx.spec.name,
            f"The server asked the client to run: {', '.join(methods)}.",
            [Evidence.make("protocol", "server requests", ", ".join(methods), "requests the client did not offer")],
            confidence=Confidence.HIGH,
            severity=Severity.HIGH if sampling else Severity.MEDIUM,
        )


class NonJsonOutput(Rule):
    id = "MCP-PROTO-002"
    title = "Server writes non-protocol text to its output"
    category = Category.PROTOCOL
    severity = Severity.LOW
    description = "The server printed lines that are not JSON-RPC messages on the protocol channel."
    why_it_matters = "This breaks some clients, and odd output deserves a look. Logs belong on stderr."
    attack_scenario = "A server prints banners or debug data to stdout, which some clients pass to the model."
    recommendation = "Send logs to stderr."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        events = _events(ctx, "non-json-output", "invalid-message", "unexpected-message")
        if events:
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                f"The server sent {len(events)} message(s) that are not valid protocol messages.",
                [Evidence.make("protocol", "server output", events[0].detail, events[0].kind)],
                confidence=Confidence.HIGH,
            )


class CrossOriginEndpoint(Rule):
    id = "MCP-PROTO-003"
    title = "SSE server points the client to another host"
    category = Category.PROTOCOL
    severity = Severity.HIGH
    description = "The SSE endpoint event told the client to send its messages to a different host."
    why_it_matters = "The client would send its requests, and maybe its credentials, to a host you never chose."
    attack_scenario = "A server at mcp.example.com tells clients to post messages to collector.example.net."
    recommendation = "Do not use this server. The scanner refused to follow the endpoint."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for event in _events(ctx, "cross-origin-endpoint"):
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                "The server's SSE endpoint is on another host.",
                [Evidence.make("protocol", "sse endpoint", event.detail, event.kind)],
                confidence=Confidence.HIGH,
            )


class OversizedOutput(Rule):
    id = "MCP-PROTO-004"
    title = "Server sent too much data"
    category = Category.PROTOCOL
    severity = Severity.LOW
    description = "The server sent a message over the size limit, or kept sending list pages past the page limit."
    why_it_matters = "Huge answers can flood the agent's context or crash clients."
    attack_scenario = "tools/list returns endless pages so the client hangs."
    recommendation = "Check why the server sends so much. Clients should limit message sizes."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        events = _events(ctx, "oversized-message", "pagination-limit")
        if events:
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                f"{events[0].detail}.",
                [Evidence.make("protocol", "server output", events[0].detail, events[0].kind)],
                confidence=Confidence.HIGH,
            )


class OldProtocol(Rule):
    id = "MCP-PROTO-005"
    title = "Server uses an old protocol version"
    category = Category.PROTOCOL
    severity = Severity.INFO
    description = "The server answered with a protocol version from 2024."
    why_it_matters = "Old versions lack newer safety features like tool annotations and the authorization spec."
    attack_scenario = "Not an attack by itself. It points to a server that may not be maintained."
    recommendation = "Update the server or its MCP SDK."
    references = (f"{SPEC}/changelog",)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        version = ctx.inventory.protocol_version
        if ctx.connected and version in OLD_PROTOCOLS:
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                f"The server speaks protocol version {version}.",
                [Evidence.make("protocol", "initialize", version or "", "protocolVersion")],
                confidence=Confidence.HIGH,
            )
