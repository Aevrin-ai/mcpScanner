# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Console report: a readable summary on the terminal."""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_scanner.models.finding import Finding
from mcp_scanner.models.result import ScanReport, ServerResult
from mcp_scanner.models.severity import Severity
from mcp_scanner.reports.base import (
    PRESCANNED_TITLE,
    SEVERITY_ORDER,
    Reporter,
    footer_lines,
    grouped_prescanned,
    status_line,
    visible,
)

STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_STYLE = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "bold red",
    "F": "bold white on red",
    "?": "bold magenta",
}


class ConsoleReporter(Reporter):
    name = "console"
    extension = "txt"

    def __init__(self, show_evidence: bool = True, verbose: bool = False) -> None:
        self.show_evidence = show_evidence
        self.verbose = verbose

    def render(self, report: ScanReport) -> str:
        console = Console(record=True, width=110, force_terminal=False, color_system=None)
        self.print(report, console)
        return console.export_text()

    def print(self, report: ScanReport, console: Console) -> None:
        for server in report.servers:
            self._server(server, console)
        if len(report.servers) > 1:
            self._overview(report, console)
        if report.ai_usage.calls:
            u = report.ai_usage
            cost = f", about ${u.estimated_cost_usd:.4f}" if u.estimated_cost_usd is not None else ""
            console.print(
                f"AI usage: {u.calls} call(s), {u.input_tokens} in / {u.output_tokens} out tokens{cost}", style="dim"
            )
        for error in report.errors:
            console.print(f"Error ({error.stage}): {error.message}", style="red")
        for line in footer_lines(report):
            console.print(Text(line), style="dim")

    def _server(self, server: ServerResult, console: Console) -> None:
        counts = server.severity_counts()
        inv = server.inventory
        head = Table.grid(padding=(0, 2))
        head.add_column(style="bold")
        head.add_column()
        head.add_row("Server", server.name)
        head.add_row("Target", str(server.server.get("target", "")))
        head.add_row("Status", status_line(server.status.value, server.is_safe))
        head.add_row(
            "Risk",
            Text(
                f"{server.risk.grade}  {server.risk.score:g}/100  {server.risk.label}",
                style=GRADE_STYLE.get(server.risk.grade, ""),
            ),
        )
        head.add_row("Inventory", f"{len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources")
        head.add_row("Findings", "  ".join(f"{s}: {counts[s]}" for s in SEVERITY_ORDER if counts[s]) or "none")
        sandbox = server.observations.sandbox.sandbox_mode
        if sandbox not in ("none", ""):
            head.add_row("Sandbox", sandbox)
        console.print(Panel(head, title="Aevrin MCP Scanner", expand=False))
        for note in server.risk.notes:
            console.print(f"  note: {note}", style="dim")
        for error in server.errors:
            console.print(f"  error ({error.stage}): {error.message}", style="red")
        active = [f for f in server.findings if f.counts_for_risk]
        for finding in active:
            console.print(self._finding(finding))
        hidden = len(server.findings) - len(active)
        if hidden:
            console.print(
                f"  {hidden} finding(s) suppressed or likely false positives (see the JSON report).", style="dim"
            )
        if server.prescanned is not None:
            self._prescanned(server, console)
        if server.ai.enabled:
            self._ai(server, console)
        console.print()

    @staticmethod
    def _prescanned(server: ServerResult, console: Console) -> None:
        report = server.prescanned
        assert report is not None
        console.print(f"{PRESCANNED_TITLE}:", style="bold cyan")
        facts = [f"grade {report.grade}"]
        if report.version:
            facts.append(f"version {report.version}")
        if report.scanned_at:
            facts.append(f"scanned {report.scanned_at}")
        facts.append(f"{len(report.tools)} tools")
        console.print("  " + ", ".join(facts))
        rows, info = grouped_prescanned(report)
        for severity, title, count, tools, description in rows[:12]:
            where = f" ({', '.join(tools)}{', ...' if count > len(tools) else ''})" if tools else ""
            times = f" x{count}" if count > 1 else ""
            # Text, not markup: "[critical]" would otherwise be read as a style name and vanish.
            console.print(Text(visible(f"  [{severity}] {title}{times}{where}: {description[:160]}")))
        if info:
            console.print(f"  and {info} info item(s)", style="dim")

    def _finding(self, finding: Finding) -> Panel:
        body: list[Text] = [Text(visible(finding.description))]
        if finding.why_it_matters and self.verbose:
            body.append(Text(f"Why it matters: {finding.why_it_matters}", style="dim"))
        if self.show_evidence:
            for evidence in finding.evidence[:3]:
                body.append(Text(visible(f"Evidence: {evidence.location}: {evidence.snippet}"), style="dim"))
        if finding.recommendation:
            body.append(Text(f"Fix: {finding.recommendation}", style="green"))
        status = finding.validation_status.value
        meta = f"confidence {finding.confidence.value}, {status}, {finding.risk_points:g} pts"
        if finding.malicious:
            meta += ", looks malicious"
        body.append(Text(meta, style="dim italic"))
        if finding.ai_review:
            body.append(Text(f"AI: {finding.ai_review.verdict}. {finding.ai_review.explanation}", style="magenta"))
        title = Text()
        title.append(f" {finding.severity.value.upper()} ", style=STYLE[finding.severity])
        title.append(f" {finding.rule_id}  {finding.title}  ")
        title.append(visible(f"[{finding.target_kind.value} {finding.target_name}]"), style="bold")
        return Panel(Group(*body), title=title, title_align="left", expand=True)

    @staticmethod
    def _ai(server: ServerResult, console: Console) -> None:
        ai = server.ai
        console.print("AI review (an opinion, not verified):", style="bold magenta")
        if ai.summary:
            console.print(f"  {ai.summary}")
        for obs in ai.observations:
            console.print(f"  [{obs.suggested_severity}] {obs.target}: {obs.title}. {obs.description}")
        if ai.skipped_reason:
            console.print(f"  skipped: {ai.skipped_reason}", style="dim")
        for error in ai.errors:
            console.print(f"  error: {error}", style="red")

    @staticmethod
    def _overview(report: ScanReport, console: Console) -> None:
        table = Table(title="All servers")
        for col in ("Server", "Status", "Grade", "Score", *[s.title() for s in SEVERITY_ORDER]):
            table.add_column(col)
        for server in report.servers:
            counts = server.severity_counts()
            table.add_row(
                server.name,
                server.status.value,
                Text(server.risk.grade, style=GRADE_STYLE.get(server.risk.grade, "")),
                f"{server.risk.score:g}",
                *[str(counts[s]) for s in SEVERITY_ORDER],
            )
        console.print(table)
