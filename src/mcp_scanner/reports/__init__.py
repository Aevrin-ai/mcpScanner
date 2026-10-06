# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Report formats. Add a format with one Reporter class and one line in REPORTERS."""

from __future__ import annotations

from mcp_scanner.reports.base import Reporter
from mcp_scanner.reports.console import ConsoleReporter
from mcp_scanner.reports.json_report import JsonReporter, load_report, report_to_dict
from mcp_scanner.reports.markdown import MarkdownReporter
from mcp_scanner.reports.sarif import SarifReporter

REPORTERS: dict[str, type[Reporter]] = {
    "console": ConsoleReporter,
    "json": JsonReporter,
    "markdown": MarkdownReporter,
    "sarif": SarifReporter,
}

__all__ = ["REPORTERS", "Reporter", "get_reporter", "load_report", "report_to_dict"]


def get_reporter(name: str) -> Reporter:
    try:
        return REPORTERS[name]()
    except KeyError as exc:
        raise ValueError(f"Unknown report format '{name}'. Use one of: {', '.join(REPORTERS)}") from exc
