# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Malicious or dangerous patterns in server source code."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.models.finding import FindingCandidate
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import NEEDS_SOURCE, Rule
from mcp_scanner.rules.helpers import code_evidence, function_has, hit_target, lower_for_js
from mcp_scanner.scanner.context import ScanContext


class ObfuscatedExecution(Rule):
    id = "MCP-SRC-001"
    title = "Code runs hidden, decoded code"
    category = Category.CODE_EXECUTION
    severity = Severity.CRITICAL
    description = "Source code decodes text (base64, hex, zlib) and runs it with eval or exec."
    why_it_matters = "Honest code has no reason to hide what it runs. This is a common malware pattern."
    attack_scenario = "exec(base64.b64decode('aW1wb3J0IG9z...')) downloads and starts a second stage."
    recommendation = "Treat the server as malicious. Do not run it."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.OBFUSCATED_EXEC):
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                "The code decodes hidden text and runs it as code.",
                [code_evidence(hit)],
                confidence=lower_for_js(hit, Confidence.HIGH),
                malicious=True,
            )


class ReverseShell(Rule):
    id = "MCP-SRC-002"
    title = "Code opens a reverse shell"
    category = Category.COMMAND_EXECUTION
    severity = Severity.CRITICAL
    description = (
        "Source code connects a network socket to a shell, which gives a remote person control of the machine."
    )
    why_it_matters = "This is remote control of your computer."
    attack_scenario = "On start, the server connects to the attacker's host and attaches /bin/sh to the socket."
    recommendation = "Treat the server as malicious. Do not run it, and check machines where it ran."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.REVERSE_SHELL):
            kind, name = hit_target(hit)
            yield self.finding(
                kind, name, f"The code {hit.detail}.", [code_evidence(hit)], confidence=Confidence.HIGH, malicious=True
            )


class Persistence(Rule):
    id = "MCP-SRC-003"
    title = "Code touches startup files"
    category = Category.PRIVILEGE
    severity = Severity.HIGH
    description = "Source code names shell startup files, SSH authorized_keys, cron, or OS autostart locations."
    why_it_matters = "Writing there makes code run again later, even after the server is removed."
    attack_scenario = "The server appends a line to ~/.bashrc that downloads a script on every new terminal."
    recommendation = "Find out why the code needs these files. Remove the server if there is no clear reason."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.PERSISTENCE):
            writes = function_has(ctx.source, hit, f.FILE_WRITE, f.COMMAND)
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                f"The code {'writes to' if writes else 'mentions'} a startup location ({hit.detail}).",
                [code_evidence(hit)],
                severity=Severity.HIGH if writes else Severity.MEDIUM,
                confidence=Confidence.HIGH if writes else Confidence.LOW,
                malicious=writes,
            )


class TemplateInjection(Rule):
    id = "MCP-SRC-004"
    title = "Tool input is used as a template"
    category = Category.CODE_EXECUTION
    severity = Severity.HIGH
    description = "Source code builds a Jinja2, Mako, or similar template from tool input."
    why_it_matters = (
        "Template syntax like {{ ... }} can reach Python objects and run code (server side template injection)."
    )
    attack_scenario = "A 'render' tool passes the user's text to jinja2.Template(). The text is '{{ cycler.__init__.__globals__.os.popen(\"id\").read() }}'."
    recommendation = "Pass input as template variables, never as the template itself. Use a sandboxed environment."
    references = ("https://cwe.mitre.org/data/definitions/1336.html",)
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.TEMPLATE):
            if not hit.tainted:
                continue
            kind, name = hit_target(hit)
            yield self.finding(
                kind, name, "Tool input becomes template code.", [code_evidence(hit)], confidence=Confidence.MEDIUM
            )
