# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Public reports from earlier scans, used when a scan cannot finish.

The reports are JSON files, one per server, in a public folder (`scan.prescanned_url`).
A report is used only when it clearly belongs to the server being scanned: its source
repository or its npm package must match exactly. Anything else is ignored, so a
lookup can never attach another server's report.

The report is kept apart from this scan's result: own section, own grade, never mixed
into the findings or the score.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from mcp_scanner.config.settings import ScanSettings
from mcp_scanner.models.result import PrescannedFinding, PrescannedReport
from mcp_scanner.models.server import ServerSpec
from mcp_scanner.sandbox.docker import command_basename
from mcp_scanner.sandbox.prepare import package_name, split_npx

log = logging.getLogger(__name__)
TIMEOUT = 8.0
MAX_BYTES = 5_000_000
MAX_FINDINGS = 200
# Grades in these reports: S means no findings at all, I means incomplete.
EM_DASH, EN_DASH = chr(0x2014), chr(0x2013)
_GRADES = {"S": "A", "I": "?"}
# Sentences that name another product or tell you to run its tools are left out.
_OTHER_PRODUCT = re.compile(r"[^.]*\b(?:tool\s*trust|agent\s*safe)[^.]*\.?\s*", re.IGNORECASE)


def _kebab(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _repo_key(url: str) -> str | None:
    """'https://github.com/Owner/Repo.git/' -> 'github.com/owner/repo'."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2 or not parsed.netloc:
        return None
    host = parsed.netloc.lower().removeprefix("www.")
    return f"{host}/{parts[0].lower()}/{parts[1].lower().removesuffix('.git')}"


def _npm_package(spec: ServerSpec) -> str | None:
    if spec.repo is not None or not spec.command:
        return None
    if command_basename(spec.command) not in ("npx", "bunx", "pnpx"):
        return None
    parts = split_npx(spec.args)
    return package_name(parts[0][0]) if parts else None


def candidates(spec: ServerSpec) -> tuple[list[str], str | None, str | None]:
    """(report names to try, the repository it must match, the npm package it must match)."""
    names: list[str] = []
    repo_key = _repo_key(spec.repo.url) if spec.repo is not None else None
    if repo_key and not repo_key.startswith("github.com/"):
        repo_key = None  # the reports cover GitHub repositories; local folders are never looked up
    if repo_key:
        _, owner, repo = repo_key.split("/")
        names += [_kebab(repo), _kebab(f"{owner}-{repo}")]
    package = _npm_package(spec)
    if package:
        scope, _, bare = package.lstrip("@").rpartition("/")
        names += [_kebab(bare), _kebab(f"{scope}-{bare}")] if scope else [_kebab(bare)]
    return list(dict.fromkeys(n for n in names if n)), repo_key, package


def _matches(doc: dict[str, Any], repo_key: str | None, package: str | None) -> bool:
    if repo_key and isinstance(doc.get("source_url"), str) and _repo_key(doc["source_url"]) == repo_key:
        return True
    return bool(package) and doc.get("npm_package") == package


def _clean(text: Any, limit: int = 600) -> str:
    plain = str(text or "").replace(f" {EM_DASH} ", ": ").replace(EM_DASH, "-").replace(EN_DASH, "-")
    return _OTHER_PRODUCT.sub("", plain).strip()[:limit]


def _title(text: Any) -> str:
    words = str(text or "").replace("_", " ").strip()
    return (words[:1].upper() + words[1:].lower()) if words.isupper() else words


def to_report(doc: dict[str, Any]) -> PrescannedReport:
    findings = []
    for item in (doc.get("findings") or [])[:MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        findings.append(
            PrescannedFinding(
                severity=str(item.get("severity", "info")).lower(),
                title=_clean(_title(item.get("title")), 200) or "Finding",
                description=_clean(item.get("description")),
                tool=str(item["tool_name"]) if item.get("tool_name") else None,
            )
        )
    summary: dict[str, Any] = doc["summary"] if isinstance(doc.get("summary"), dict) else {}
    grade = str(doc.get("grade", "?"))
    return PrescannedReport(
        grade=_GRADES.get(grade, grade),
        score=float(doc.get("risk_score") or 0),
        version=_clean(doc.get("version"), 100),
        scanned_at=str(doc.get("scan_date") or "")[:10],
        source_url=str(doc.get("source_url") or ""),
        tools=[str(t) for t in (doc.get("tool_names") or []) if isinstance(t, str)][:500],
        findings=findings,
        severity_counts={str(k): int(v) for k, v in summary.items() if isinstance(v, int)},
    )


def lookup(spec: ServerSpec, settings: ScanSettings, client: httpx.Client | None = None) -> PrescannedReport | None:
    """A matching public report for this server, or None. Never raises."""
    names, repo_key, package = candidates(spec)
    if not names or not settings.prescanned_url:
        return None
    base = settings.prescanned_url.rstrip("/")
    own = client is None
    http = client or httpx.Client(timeout=TIMEOUT, follow_redirects=True)
    try:
        for name in names:
            try:
                response = http.get(f"{base}/{name}.json")
                if response.status_code != 200 or len(response.content) > MAX_BYTES:
                    continue
                doc = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                log.debug("Report lookup %s failed: %s", name, exc)
                continue
            if isinstance(doc, dict) and _matches(doc, repo_key, package):
                return to_report(doc)
    finally:
        if own:
            http.close()
    return None
