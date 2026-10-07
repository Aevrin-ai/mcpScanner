# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""JSON report: the full record of a scan. Other formats can be made from it later."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_scanner.models.result import ScanReport
from mcp_scanner.reports.base import Reporter, ensure_product, server_summary


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    ensure_product(report)
    data = report.model_dump(mode="json")
    data["status"] = report.status.value
    worst = report.worst_severity()
    data["summary"] = {
        "servers": len(report.servers),
        "severity_counts": report.severity_counts(),
        "worst_severity": worst.value if worst else None,
    }
    for server_data, server in zip(data["servers"], report.servers, strict=True):
        server_data["summary"] = server_summary(server)
    return data


class JsonReporter(Reporter):
    name = "json"
    extension = "json"

    def render(self, report: ScanReport) -> str:
        return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False)


def load_report(path: str | Path) -> ScanReport:
    """Read a JSON report written by this scanner."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ScanReport.model_validate(data)
