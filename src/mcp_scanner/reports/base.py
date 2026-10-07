# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Reporter interface and registry.

Every reporter reads the same ScanReport and returns text. Reporters never
re-compute scan data. To add a format, write one class and add it to REPORTERS.
"""

from __future__ import annotations

import unicodedata
from abc import ABC, abstractmethod
from typing import Any

from mcp_scanner.models.result import PrescannedFinding, PrescannedReport, ProductInfo, ScanReport, ServerResult
from mcp_scanner.models.severity import Severity


class Reporter(ABC):
    name: str = ""
    extension: str = ""

    @abstractmethod
    def render(self, report: ScanReport) -> str: ...


def ensure_product(report: ScanReport) -> ProductInfo:
    """The branding and license block of a report. Each reporter calls this itself, so a
    report never goes out without it, even if the engine step that fills it is removed."""
    if report.product is None:
        from mcp_scanner.licensing.status import product_info

        report.product = product_info()
    return report.product


def footer_lines(report: ScanReport) -> list[str]:
    """The attribution, license, and build lines at the end of every report."""
    from mcp_scanner.branding import attribution

    product = ensure_product(report)
    lines = [attribution(product.version), product.license_notice]
    if product.build_notice:
        lines.append(product.build_notice)
    return lines


def server_summary(server: ServerResult) -> dict[str, Any]:
    """Small computed values that every format shows the same way."""
    return {
        "status": server.status.value,
        "is_safe": server.is_safe,
        "severity_counts": server.severity_counts(),
        "active_findings": len(server.active_findings),
        "all_findings": len(server.findings),
    }


def safe_label(value: bool | None) -> str:
    if value is True:
        return "no known issues"
    if value is False:
        return "issues found"
    return "unknown (scan incomplete)"


PRESCANNED_TITLE = "Public report from an earlier scan (not made by this scan, not part of its score)"
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def grouped_prescanned(report: PrescannedReport) -> tuple[list[tuple[str, str, int, list[str], str]], int]:
    """Findings of a public report, grouped by severity and title: (rows, how many info items were left out).

    Each row is (severity, title, count, some tool names, one description).
    """
    groups: dict[tuple[str, str], list[PrescannedFinding]] = {}
    info = 0
    for finding in report.findings:
        if finding.severity == "info":
            info += 1
            continue
        groups.setdefault((finding.severity, finding.title), []).append(finding)
    rows = [
        (severity, title, len(items), sorted({f.tool for f in items if f.tool})[:5], items[0].description)
        for (severity, title), items in groups.items()
    ]
    rows.sort(key=lambda row: (_SEVERITY_RANK.get(row[0], 5), -row[2]))
    return rows, info


def status_line(status: str, is_safe: bool | None) -> str:
    """One plain line about how far the scan got and what it found."""
    found = safe_label(is_safe)
    if status == "failed":
        # The server never answered, so only the checks that need no running server happened.
        return f"failed: the server did not start, only code and config checks ran ({found})"
    if status == "partial":
        return f"partial: some checks did not finish ({found})"
    return f"{status} ({found})"


def visible(text: str) -> str:
    """Show invisible and control characters as escapes, so reports cannot hide text or break a terminal."""
    out = []
    for ch in text:
        if ch in "\n\t":
            out.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs") or 0xE0000 <= ord(ch) <= 0xE007F:
            out.append(ch.encode("unicode_escape").decode("ascii"))
        else:
            out.append(ch)
    return "".join(out)


SEVERITY_ORDER = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]
