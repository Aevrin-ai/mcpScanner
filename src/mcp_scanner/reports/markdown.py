# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Markdown report, for pull requests, tickets, and wikis."""

from __future__ import annotations

from mcp_scanner.models.finding import Finding
from mcp_scanner.models.result import ScanReport, ServerResult
from mcp_scanner.reports.base import (
    PRESCANNED_TITLE,
    SEVERITY_ORDER,
    Reporter,
    footer_lines,
    grouped_prescanned,
    status_line,
    visible,
)


def _cell(text: str) -> str:
    return visible(text).replace("|", "\\|").replace("\n", " ")


def _code(text: str) -> str:
    return "`" + visible(text).replace("`", "'").replace("\n", " ") + "`"


class MarkdownReporter(Reporter):
    name = "markdown"
    extension = "md"

    def render(self, report: ScanReport) -> str:
        lines = [
            f"# {report.scanner} report",
            "",
            f"- Scan ID: `{report.scan_id}`",
            f"- Version: {report.scanner_version}",
            f"- Started: {report.started_at.isoformat(timespec='seconds')}",
            f"- Duration: {report.duration_seconds:.1f}s",
            f"- Status: **{report.status.value}**",
            f"- Dynamic analysis: {'on' if report.options.dynamic else 'off'}",
            f"- AI review: {'on (' + str(report.options.ai_provider) + ')' if report.options.ai_enabled else 'off'}",
            "",
            "## Summary",
            "",
            "| Server | Status | Grade | Score | " + " | ".join(s.title() for s in SEVERITY_ORDER) + " |",
            "|---|---|---|---|" + "---|" * len(SEVERITY_ORDER),
        ]
        for server in report.servers:
            counts = server.severity_counts()
            lines.append(
                f"| {_cell(server.name)} | {server.status.value} | {server.risk.grade} | {server.risk.score:g} | "
                + " | ".join(str(counts[s]) for s in SEVERITY_ORDER)
                + " |"
            )
        for server in report.servers:
            lines += self._server(server)
        if report.ai_usage.calls:
            u = report.ai_usage
            cost = f", about ${u.estimated_cost_usd:.4f}" if u.estimated_cost_usd is not None else ""
            lines += [
                "",
                "## AI usage",
                "",
                f"{u.calls} call(s) to {u.provider} {u.model}: {u.input_tokens} input and {u.output_tokens} output tokens{cost}.",
            ]
        lines += ["", "---", "", "The risk score is a sorting aid, not a measurement. See docs/risk-scoring.md.", ""]
        lines += [f"{line}  " for line in footer_lines(report)] + [""]
        return "\n".join(lines)

    def _server(self, server: ServerResult) -> list[str]:
        inv = server.inventory
        lines = [
            "",
            f"## {server.name}",
            "",
            f"- Target: {_code(str(server.server.get('target', '')))}",
            f"- Transport: {server.server.get('transport')}",
            f"- Status: {status_line(server.status.value, server.is_safe)}",
            f"- Risk: **{server.risk.grade}** ({server.risk.score:g}/100, {server.risk.label})",
            f"- Inventory: {len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources",
        ]
        for note in server.risk.notes:
            lines.append(f"- Note: {note}")
        if server.errors:
            lines += ["", "### Errors", ""]
            lines += [f"- {e.stage}: {_cell(e.message)}" for e in server.errors]
        active = [f for f in server.findings if f.counts_for_risk]
        other = [f for f in server.findings if not f.counts_for_risk]
        lines += ["", f"### Findings ({len(active)})", ""]
        if not active:
            lines.append("No active findings.")
        for finding in active:
            lines += self._finding(finding)
        if other:
            lines += ["", f"### Suppressed or likely false positives ({len(other)})", ""]
            lines += [
                f"- {f.rule_id} on {f.target_kind.value} `{f.target_name}`: {f.validation_status.value}. {'; '.join(f.validation_notes)}"
                for f in other
            ]
        if server.risk.factors:
            lines += ["", "### Why this score", "", "| Points | Rule | Target | Reason |", "|---|---|---|---|"]
            lines += [
                f"| {x.points:g} | {x.rule_id} | {_cell(x.target)} | {_cell(x.reason)} |" for x in server.risk.factors
            ]
        if server.prescanned is not None:
            lines += self._prescanned(server)
        if server.ai.enabled:
            lines += self._ai(server)
        return lines

    @staticmethod
    def _prescanned(server: ServerResult) -> list[str]:
        report = server.prescanned
        assert report is not None
        lines = ["", f"### {PRESCANNED_TITLE}", ""]
        lines.append(
            f"Grade {report.grade}, version {report.version or 'unknown'}, scanned {report.scanned_at or 'unknown'}, "
            f"{len(report.tools)} tools."
        )
        rows, info = grouped_prescanned(report)
        if rows:
            lines += ["", "| Severity | Finding | Count | Tools | Detail |", "|---|---|---|---|---|"]
            lines += [
                f"| {severity} | {_cell(title)} | {count} | {_cell(', '.join(tools))} | {_cell(description[:200])} |"
                for severity, title, count, tools, description in rows
            ]
        if info:
            lines += ["", f"And {info} info item(s)."]
        return lines

    @staticmethod
    def _finding(finding: Finding) -> list[str]:
        lines = [
            f"#### [{finding.severity.value.upper()}] {finding.rule_id}: {finding.title}",
            "",
            f"- Target: {finding.target_kind.value} `{finding.target_name}`",
            f"- Confidence: {finding.confidence.value}, status: {finding.validation_status.value}, points: {finding.risk_points:g}",
            f"- What: {finding.description}",
        ]
        if finding.why_it_matters:
            lines.append(f"- Why it matters: {finding.why_it_matters}")
        for evidence in finding.evidence:
            detail = f" ({evidence.detail})" if evidence.detail else ""
            lines.append(f"- Evidence: {evidence.location}{detail}: {_code(evidence.snippet)}")
        if finding.recommendation:
            lines.append(f"- Fix: {finding.recommendation}")
        for note in finding.validation_notes:
            lines.append(f"- Note: {note}")
        if finding.ai_review:
            lines.append(
                f"- AI ({finding.ai_review.provider}): {finding.ai_review.verdict}. {finding.ai_review.explanation}"
            )
        lines.append("")
        return lines

    @staticmethod
    def _ai(server: ServerResult) -> list[str]:
        ai = server.ai
        lines = ["", "### AI review (unverified opinion)", ""]
        if ai.summary:
            lines += [ai.summary, ""]
        for obs in ai.observations:
            lines.append(f"- [{obs.suggested_severity}] {obs.target}: **{obs.title}**. {obs.description}")
        if ai.skipped_reason:
            lines.append(f"- Skipped: {ai.skipped_reason}")
        for error in ai.errors:
            lines.append(f"- Error: {error}")
        return lines
