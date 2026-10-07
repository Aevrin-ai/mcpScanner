# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Turn raw rule candidates into clean, trustworthy findings.

Steps, in order:
  1. drop candidates without evidence
  2. merge duplicates (same rule, same target, same first evidence location)
  3. negation: "this tool does NOT run commands" -> likely false positive
  4. corroboration: metadata and source code agree -> raise confidence
  5. status: confirmed (dynamic proof), validated (high confidence), or unverified
  6. user suppressions (with a reason and an optional expiry date)
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections import defaultdict
from datetime import date

from mcp_scanner.config.settings import Suppression
from mcp_scanner.models.finding import Evidence, Finding, FindingCandidate
from mcp_scanner.models.severity import Category, Confidence, ValidationStatus
from mcp_scanner.rules.patterns import NEGATION
from mcp_scanner.rules.registry import id_matches

log = logging.getLogger(__name__)

MAX_EVIDENCE = 5
METADATA_KINDS = {"text-match", "schema", "hidden-text", "encoded-text"}
CODE_KINDS = {"source-code"}
RUNTIME_KINDS = {"dynamic", "sandbox"}
# Categories that describe the same danger from different angles.
_RELATED = [
    {Category.COMMAND_EXECUTION, Category.CODE_EXECUTION},
    {Category.NETWORK, Category.DATA_EXFILTRATION},
    {Category.FILESYSTEM},
    {Category.SECRETS, Category.DATA_EXFILTRATION},
    {Category.TOOL_POISONING, Category.PROMPT_INJECTION, Category.TOOL_SHADOWING, Category.DATA_EXFILTRATION},
]


def _related(a: Category, b: Category) -> bool:
    return a == b or any(a in group and b in group for group in _RELATED)


def _kinds(candidate: FindingCandidate) -> set[str]:
    return {e.kind for e in candidate.evidence}


class FindingValidator:
    def __init__(self, suppressions: list[Suppression] | None = None, today: date | None = None) -> None:
        self.suppressions = suppressions or []
        self.today = today or date.today()

    def validate(self, server: str, candidates: list[FindingCandidate]) -> list[Finding]:
        merged = self._merge([c for c in candidates if c.evidence])
        findings = [self._to_finding(server, c) for c in merged]
        for finding in findings:
            self._check_negation(finding)
        self._corroborate(findings)
        for finding in findings:
            self._set_status(finding)
            self._apply_suppressions(server, finding)
        return sorted(findings, key=lambda f: (-f.severity.rank, -f.confidence.rank, f.rule_id, f.target_name))

    # ---- 2. merge -----------------------------------------------------------

    @staticmethod
    def _merge(candidates: list[FindingCandidate]) -> list[FindingCandidate]:
        by_key: dict[str, FindingCandidate] = {}
        for candidate in candidates:
            # Same rule, same target, same message: one finding with several pieces of evidence.
            key = f"{candidate.rule_id}|{candidate.target_kind.value}|{candidate.target_name}|{candidate.description}"
            first = by_key.get(key)
            if first is None:
                by_key[key] = candidate.model_copy(deep=True)
                continue
            if candidate.severity.rank > first.severity.rank:
                first.severity = candidate.severity
            if candidate.confidence.rank > first.confidence.rank:
                first.confidence = candidate.confidence
            first.malicious = first.malicious or candidate.malicious
            first.confirmed = first.confirmed or candidate.confirmed
            first.evidence = _unique_evidence([*first.evidence, *candidate.evidence])
        return list(by_key.values())

    @staticmethod
    def _to_finding(server: str, candidate: FindingCandidate) -> Finding:
        data = candidate.model_dump()
        data["evidence"] = _unique_evidence(candidate.evidence)
        return Finding(**data, id=Finding.make_id(server, candidate), server=server)

    # ---- 3. negation --------------------------------------------------------

    @staticmethod
    def _check_negation(finding: Finding) -> None:
        if finding.confirmed or not finding.context_text:
            return
        # Only look inside the same sentence: "it will not work. Do not tell the user" is not a negation.
        clause = re.split(r"[.!?;:\n]", finding.context_text)[-1]
        if clause.strip() and NEGATION.search(clause):
            finding.validation_status = ValidationStatus.LIKELY_FALSE_POSITIVE
            finding.malicious = False
            finding.validation_notes.append(
                "A negation word comes right before the match, so the text likely says the opposite."
            )

    # ---- 4. corroboration ---------------------------------------------------

    @staticmethod
    def _corroborate(findings: list[Finding]) -> None:
        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for finding in findings:
            if finding.validation_status != ValidationStatus.LIKELY_FALSE_POSITIVE:
                groups[(finding.target_kind.value, finding.target_name)].append(finding)
        for group in groups.values():
            for finding in group:
                own = _kinds(finding)
                for other in group:
                    if other is finding or not _related(finding.category, other.category):
                        continue
                    theirs = _kinds(other)
                    independent = (own & METADATA_KINDS and theirs & (CODE_KINDS | RUNTIME_KINDS)) or (
                        own & CODE_KINDS and theirs & (METADATA_KINDS | RUNTIME_KINDS)
                    )
                    if independent:
                        finding.confidence = finding.confidence.raised()
                        finding.validation_notes.append(
                            f"Backed up by {other.rule_id} from a different kind of evidence."
                        )
                        break

    # ---- 5. status ----------------------------------------------------------

    @staticmethod
    def _set_status(finding: Finding) -> None:
        if finding.validation_status == ValidationStatus.LIKELY_FALSE_POSITIVE:
            return
        if finding.confirmed:
            finding.validation_status = ValidationStatus.CONFIRMED
        elif finding.confidence == Confidence.HIGH:
            finding.validation_status = ValidationStatus.VALIDATED
        else:
            finding.validation_status = ValidationStatus.UNVERIFIED
            if finding.confidence == Confidence.LOW:
                finding.validation_notes.append("Possible issue: the evidence is weak, so it adds no risk points.")

    # ---- 6. suppressions ----------------------------------------------------

    def _apply_suppressions(self, server: str, finding: Finding) -> None:
        for rule in self.suppressions:
            if not id_matches(finding.rule_id, [rule.rule_id]):
                continue
            if not fnmatch.fnmatch(server, rule.server) or not fnmatch.fnmatch(finding.target_name, rule.target):
                continue
            if rule.expires and rule.expires < self.today:
                finding.validation_notes.append(f"A suppression expired on {rule.expires.isoformat()}: {rule.reason}")
                continue
            finding.validation_status = ValidationStatus.SUPPRESSED
            finding.validation_notes.append(f"Suppressed: {rule.reason}")
            return


def _unique_evidence(items: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str]] = set()
    result = []
    for item in items:
        key = (item.location, item.snippet)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result[:MAX_EVIDENCE]
