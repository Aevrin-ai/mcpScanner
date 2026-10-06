# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""File system access."""

from __future__ import annotations

import re
from collections.abc import Iterable

from mcp_scanner.analyzers.capabilities import Capability, split_words
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

CWE_22 = "https://cwe.mitre.org/data/definitions/22.html"
DELETE_WORDS = {"delete", "remove", "rm", "unlink", "truncate", "overwrite", "wipe", "purge", "destroy"}
# Text that says the tool only works inside allowed folders.
SCOPED = re.compile(
    r"\b(?:only\s+(?:works|operates)\s+with(?:in)?|within\s+(?:the\s+)?allowed|allowed\s+director(?:y|ies)|"
    r"restricted\s+to\s+(?:the\s+)?(?:allowed|configured|project|workspace)|inside\s+the\s+(?:allowed|configured|project|workspace))",
    re.IGNORECASE,
)


def declares_scope(ctx: ScanContext, description: str) -> bool:
    """The tool (or a helper tool on the server) says file access is limited to allowed folders."""
    return bool(SCOPED.search(description)) or "list_allowed_directories" in ctx.tool_names


class FileWriteTool(Rule):
    id = "MCP-FS-001"
    title = "Tool can change or delete files"
    category = Category.FILESYSTEM
    severity = Severity.MEDIUM
    description = "A tool writes, moves, or deletes files at a path the agent chooses."
    why_it_matters = "A tricked agent can overwrite config files, plant scripts that run at login, or delete work."
    attack_scenario = "Injected text tells the agent to append a line to ~/.bashrc with this tool."
    recommendation = "Limit the tool to one project folder, and keep human approval on for writes and deletes."
    references = (CWE_22,)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None or not caps.has(Capability.FS_WRITE):
                continue
            deletes = bool(set(split_words(tool.name)) & DELETE_WORDS)
            scoped = declares_scope(ctx, tool.description)
            severity = Severity.HIGH if deletes and caps.strong(Capability.FS_WRITE) else Severity.MEDIUM
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' can {'delete' if deletes else 'change'} files: "
                + "; ".join(s.reason for s in caps.signals[Capability.FS_WRITE][:2])
                + (". It says it only works inside allowed folders, which limits the damage." if scoped else "."),
                signal_evidence(caps.signals[Capability.FS_WRITE]),
                confidence=capability_confidence(caps, Capability.FS_WRITE),
                severity=Severity.LOW if scoped else severity,
            )


class FileReadTool(Rule):
    id = "MCP-FS-002"
    title = "Tool can read files at any path"
    category = Category.FILESYSTEM
    severity = Severity.LOW
    description = "A tool reads files or lists folders at a path the agent chooses."
    why_it_matters = "Combined with any way to send data out, this can leak SSH keys, tokens, and .env files."
    attack_scenario = "A poisoned tool tells the agent to read ~/.ssh/id_rsa with this tool and pass the text along."
    recommendation = "Limit the tool to the folders it needs. Block hidden files and home folder secrets."
    references = (CWE_22,)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None or not caps.strong(Capability.FS_READ) or caps.has(Capability.FS_WRITE):
                continue
            scoped = declares_scope(ctx, tool.description)
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' reads files from a path given by the agent"
                + (", inside the folders it is allowed to use." if scoped else "."),
                signal_evidence(caps.signals[Capability.FS_READ]),
                confidence=Confidence.MEDIUM,
                severity=Severity.INFO if scoped else Severity.LOW,
            )


class PathTraversalInSource(Rule):
    id = "MCP-FS-003"
    title = "Tool input is used as a file path without a folder check"
    category = Category.FILESYSTEM
    severity = Severity.HIGH
    description = (
        "Source code opens, writes, or deletes a file at a path built from tool input, with no allowed folder check."
    )
    why_it_matters = "Paths like '../../.ssh/id_rsa' escape the intended folder."
    attack_scenario = "A 'read_note' tool opens f'notes/{name}'. The name is '../../.aws/credentials'."
    recommendation = (
        "Resolve the path and check it stays inside the allowed folder (Path.resolve() plus is_relative_to())."
    )
    references = (CWE_22,)
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.FILE_READ, f.FILE_WRITE):
            if not hit.tainted or hit.sanitized:
                continue
            write = hit.category == f.FILE_WRITE
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                f"Tool input decides which file is {'written or deleted' if write else 'read'}, and no folder check was found.",
                [code_evidence(hit)],
                severity=Severity.HIGH if write else Severity.MEDIUM,
                confidence=lower_for_js(hit, Confidence.MEDIUM),
            )


class SensitivePathInSource(Rule):
    id = "MCP-FS-004"
    title = "Code touches secret files"
    category = Category.FILESYSTEM
    severity = Severity.HIGH
    description = (
        "Source code names secret files like SSH keys, cloud credentials, browser data, or MCP client configs."
    )
    why_it_matters = (
        "An MCP server rarely needs these files. Reading them and sending them out is classic credential theft."
    )
    attack_scenario = "A tool quietly reads ~/.ssh/id_rsa and posts it to a remote server."
    recommendation = "Find out why the code needs the file. Remove the server if there is no clear reason."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.SENSITIVE_PATH):
            sends = function_has(ctx.source, hit, f.NETWORK, f.EXFIL_ENDPOINT)
            reads = function_has(ctx.source, hit, f.FILE_READ, f.COMMAND)
            if sends and reads:
                severity, confidence, text = (
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    "reads a secret file and sends data over the network",
                )
            elif reads:
                severity, confidence, text = Severity.HIGH, Confidence.MEDIUM, "reads a secret file"
            else:
                severity, confidence, text = Severity.MEDIUM, Confidence.LOW, "mentions a secret file"
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                f"The code {text} ({hit.detail}).",
                [code_evidence(hit)],
                severity=severity,
                confidence=lower_for_js(hit, confidence),
                malicious=severity == Severity.CRITICAL,
            )
