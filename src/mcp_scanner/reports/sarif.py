# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""SARIF 2.1.0 report, for GitHub code scanning and other CI tools."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_scanner import PRODUCT_NAME
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.result import ScanReport, ServerResult
from mcp_scanner.models.severity import Severity
from mcp_scanner.reports.base import Reporter, ensure_product

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub reads this number to rank security alerts.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
_FILE_LINE = re.compile(r"^(?P<file>[^:]+(?::\\[^:]+)?):(?P<line>\d+)$")


class SarifReporter(Reporter):
    name = "sarif"
    extension = "sarif"

    def render(self, report: ScanReport) -> str:
        product = ensure_product(report)
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for server in report.servers:
            for finding in server.findings:
                rules.setdefault(finding.rule_id, _rule(finding))
                results.append(_result(finding, server))
        run = {
            "tool": {
                "driver": {
                    "name": PRODUCT_NAME,
                    "organization": product.vendor,
                    "version": report.scanner_version,
                    "rules": list(rules.values()),
                }
            },
            "properties": {
                "copyright": product.copyright,
                "license": product.license,
                "licenseNotice": product.license_notice,
                "build": product.build,
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": report.status.value != "failed",
                    "toolExecutionNotifications": [
                        {"level": "error" if e.fatal else "warning", "message": {"text": f"{e.stage}: {e.message}"}}
                        for server in report.servers
                        for e in server.errors
                    ],
                }
            ],
        }
        return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2, ensure_ascii=False)


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": re.sub(r"[^A-Za-z0-9]", "", finding.title.title()),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.why_it_matters or finding.title},
        "help": {"text": finding.recommendation or finding.title},
        "properties": {
            "category": finding.category.value,
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "tags": ["security", "mcp", finding.category.value],
        },
    }


def _result(finding: Finding, server: ServerResult) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": LEVEL[finding.severity],
        "message": {"text": f"[{server.name}] {finding.description}"},
        "locations": [_location(finding, server)],
        "partialFingerprints": {"aevrinFindingId": finding.id},
        "properties": {
            "server": server.name,
            "target": f"{finding.target_kind.value} {finding.target_name}",
            "confidence": finding.confidence.value,
            "validationStatus": finding.validation_status.value,
            "riskPoints": finding.risk_points,
            "security-severity": SECURITY_SEVERITY[finding.severity],
        },
    }
    if not finding.counts_for_risk:
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": "; ".join(finding.validation_notes) or finding.validation_status.value,
            }
        ]
    return result


def _location(finding: Finding, server: ServerResult) -> dict[str, Any]:
    for evidence in finding.evidence:
        if evidence.kind in ("source-code", "dependency"):
            match = _FILE_LINE.match(evidence.location)
            file = match.group("file") if match else evidence.location
            physical: dict[str, Any] = {"artifactLocation": {"uri": _uri(file, server)}}
            if match:
                physical["region"] = {"startLine": int(match.group("line"))}
            return {"physicalLocation": physical}
    origin = server.server.get("origin")
    if finding.target_kind.value == "config" and origin:
        return {"physicalLocation": {"artifactLocation": {"uri": Path(str(origin)).as_posix()}}}
    name = f"{server.name}/{finding.target_kind.value}/{finding.target_name}"
    return {
        "logicalLocations": [
            {"name": finding.target_name, "fullyQualifiedName": name, "kind": finding.target_kind.value}
        ]
    }


def _uri(file: str, server: ServerResult) -> str:
    root = server.server.get("source_path")
    path = Path(file)
    if root and not path.is_absolute():
        base = Path(str(root))
        path = (base if base.is_dir() else base.parent) / path
    return path.as_posix()
