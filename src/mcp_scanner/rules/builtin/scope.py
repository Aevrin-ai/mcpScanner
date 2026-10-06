# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Scope: does the tool do more than it says?"""

from __future__ import annotations

import re
from collections.abc import Iterable

from mcp_scanner.analyzers.capabilities import Capability, split_words
from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import NEEDS_SOURCE, Rule
from mcp_scanner.rules.helpers import code_evidence, function_has, signal_evidence
from mcp_scanner.scanner.context import ScanContext

# Source hit category -> metadata capabilities that would explain it.
EXPLAINED_BY: dict[str, tuple[Capability, ...]] = {
    f.COMMAND: (Capability.EXEC,),
    f.CODE_EVAL: (Capability.EXEC,),
    f.NETWORK: (Capability.NETWORK, Capability.MESSAGING, Capability.BROWSER),
    f.FILE_WRITE: (Capability.FS_WRITE,),
    f.ENV_DUMP: (),
    f.SENSITIVE_PATH: (Capability.FS_READ, Capability.FS_WRITE),
    f.EXFIL_ENDPOINT: (),
}
PLAIN_WORDS = {
    f.COMMAND: "runs system commands",
    f.CODE_EVAL: "runs dynamic code",
    f.NETWORK: "makes network requests",
    f.FILE_WRITE: "writes or deletes files",
    f.ENV_DUMP: "reads all environment variables",
    f.SENSITIVE_PATH: "touches secret files",
    f.EXFIL_ENDPOINT: "contacts a data collection service",
}
# Words in a description that honestly explain network use.
NETWORK_WORDS = {
    "api",
    "http",
    "https",
    "web",
    "url",
    "fetch",
    "download",
    "remote",
    "online",
    "service",
    "github",
    "slack",
    "search",
    "weather",
    "cloud",
    "server",
    "request",
    "endpoint",
}


class UndisclosedBehavior(Rule):
    id = "MCP-SCOPE-001"
    title = "Tool code does something its description does not mention"
    category = Category.EXCESSIVE_PERMISSIONS
    severity = Severity.HIGH
    description = "The source code of a tool runs commands, sends network requests, or touches secret files, but the tool's metadata says nothing about it."
    why_it_matters = "Users approve tools based on the description. Hidden behavior is how backdoors look."
    attack_scenario = "A 'format_date' tool also posts its arguments to a remote server."
    recommendation = "Read the tool code. Ask the maintainer to document the behavior, or remove the server."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        reported: set[tuple[str, str]] = set()
        for hit in ctx.source.hits:
            if hit.tool is None or hit.category not in EXPLAINED_BY or (hit.tool, hit.category) in reported:
                continue
            tool = ctx.inventory.tool(hit.tool)
            caps = ctx.capabilities.get(hit.tool)
            if tool is None or caps is None:
                continue
            if any(caps.has(c) for c in EXPLAINED_BY[hit.category]):
                continue
            words = set(split_words(f"{tool.name} {tool.description}"))
            if hit.category == f.NETWORK and words & NETWORK_WORDS:
                continue
            if hit.category == f.FILE_WRITE and not hit.tainted:
                continue
            if hit.category == f.COMMAND and not hit.tainted and "shell" not in hit.detail:
                continue  # a fixed helper program, like a syntax checker, is not hidden behavior
            if hit.category == f.SENSITIVE_PATH and not function_has(
                ctx.source, hit, f.FILE_READ, f.FILE_WRITE, f.COMMAND
            ):
                continue  # only a mention, for example inside a returned string
            reported.add((hit.tool, hit.category))
            hidden_exfil = hit.category in (f.ENV_DUMP, f.EXFIL_ENDPOINT, f.SENSITIVE_PATH)
            yield self.finding(
                TargetKind.TOOL,
                hit.tool,
                f"Tool '{hit.tool}' {PLAIN_WORDS[hit.category]}, but its description does not say so.",
                [
                    code_evidence(hit),
                    Evidence.make(
                        "text-match",
                        f"tool {tool.name} > description",
                        tool.description[:200] or "(empty)",
                        "what the tool claims",
                    ),
                ],
                # A tool with many actions has a long, list-like description. Matching code to one of
                # those actions is not reliable, so the finding becomes "possible" (0 points).
                confidence=Confidence.LOW if is_multi_action(tool.description) else Confidence.MEDIUM,
                severity=Severity.CRITICAL if hidden_exfil else Severity.HIGH,
            )


def is_multi_action(description: str) -> bool:
    lines = [line.strip() for line in description.splitlines() if line.strip()]
    action_lines = sum(
        1 for line in lines if re.match(r"^(?:[-*]\s+)?[\w.]+\s*\(", line) or line.startswith(("- ", "* "))
    )
    return len(description) > 1500 or action_lines >= 5 or "actions:" in description.lower()


DESTRUCTIVE_WORDS = {"delete", "remove", "drop", "destroy", "wipe", "purge", "truncate", "kill", "terminate", "rm"}


class AnnotationMismatch(Rule):
    id = "MCP-SCOPE-002"
    title = "Tool annotations do not match what the tool does"
    category = Category.EXCESSIVE_PERMISSIONS
    severity = Severity.MEDIUM
    description = "A tool says it is read-only or not destructive, but its name or schema shows it writes, deletes, or runs commands."
    why_it_matters = "Clients use these hints to skip approval prompts. A false 'readOnlyHint' removes a safety check."
    attack_scenario = "A tool marked readOnlyHint=true deletes files, and the client runs it without asking."
    recommendation = "Fix the annotations. Do not trust annotations from servers you do not control."
    references = ("https://modelcontextprotocol.io/specification/2025-11-25/server/tools#tool-annotations",)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None:
                continue
            notes = tool.annotations
            words = set(split_words(tool.name))
            where = f"tool {tool.name} > annotations"
            if notes.get("readOnlyHint") is True:
                for cap in (Capability.EXEC, Capability.FS_WRITE):
                    if caps.strong(cap) or (cap == Capability.FS_WRITE and words & DESTRUCTIVE_WORDS):
                        yield self.finding(
                            TargetKind.TOOL,
                            tool.name,
                            f"Tool '{tool.name}' is marked read-only, but it looks able to {'run commands' if cap == Capability.EXEC else 'change files'}.",
                            [
                                Evidence.make("schema", where, "readOnlyHint: true", "annotation"),
                                *signal_evidence(caps.signals.get(cap, []), 1),
                            ],
                            confidence=Confidence.MEDIUM,
                        )
                        break
            if notes.get("destructiveHint") is False and words & DESTRUCTIVE_WORDS:
                yield self.finding(
                    TargetKind.TOOL,
                    tool.name,
                    f"Tool '{tool.name}' is marked not destructive, but its name says it deletes or removes things.",
                    [Evidence.make("schema", where, "destructiveHint: false", "annotation")],
                    confidence=Confidence.MEDIUM,
                )
