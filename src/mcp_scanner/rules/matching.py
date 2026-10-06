# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Shared helpers for rules that search text surfaces with patterns."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from mcp_scanner.analyzers.text import TextSurface, excerpt, normalize
from mcp_scanner.models.finding import Evidence
from mcp_scanner.models.severity import Confidence
from mcp_scanner.rules.patterns import ATTACK_NOUN, DEFENSIVE_VERB, TextPattern

# Text inside quotes is often an example ("blocks phrases like 'ignore previous instructions'").
_QUOTE_CHARS = "\"'`“”‘’"


@dataclass
class TextHit:
    surface: TextSurface
    pattern: TextPattern
    text: str  # the normalized text that was searched
    start: int
    end: int

    @property
    def matched(self) -> str:
        return self.text[self.start : self.end]

    @property
    def before(self) -> str:
        """Text just before the match. The validator looks for negation words here."""
        return self.text[max(0, self.start - 60) : self.start]

    def evidence(self) -> Evidence:
        return Evidence.make(
            "text-match", self.surface.location, excerpt(self.text, self.start, self.end), self.pattern.label
        )

    @property
    def defensive(self) -> bool:
        """True when the text talks ABOUT the attack, for example a filter or a detector."""
        return looks_defensive(self.text, self.start, self.end)


def looks_defensive(text: str, start: int, end: int) -> bool:
    """True when the match is a quoted example, or the text is about detecting attacks."""
    if _inside_quotes(text, start, end):
        return True
    # Both words must sit near the match, so one harmless sentence cannot cover a whole description.
    nearby = text[max(0, start - 200) : end + 200]
    return bool(DEFENSIVE_VERB.search(nearby) and ATTACK_NOUN.search(nearby))


def _inside_quotes(text: str, start: int, end: int) -> bool:
    left = text[max(0, start - 3) : start]
    right = text[end : end + 3]
    return any(q in left for q in _QUOTE_CHARS) and any(q in right for q in _QUOTE_CHARS)


def find_hits(surfaces: Iterable[TextSurface], patterns: Iterable[TextPattern]) -> Iterator[TextHit]:
    """First match of each pattern in each surface."""
    pattern_list = list(patterns)
    for surface in surfaces:
        if surface.kind in ("tool-name", "param-name"):
            continue
        text = normalize(surface.text)
        for pattern in pattern_list:
            match = pattern.regex.search(text)
            if match:
                yield TextHit(surface, pattern, text, match.start(), match.end())


def hit_confidence(hit: TextHit) -> Confidence:
    """Pattern confidence, lowered when the text looks like it describes attacks instead of doing one."""
    return Confidence.LOW if hit.defensive else hit.pattern.confidence


def first_match(regex: re.Pattern[str], text: str) -> re.Match[str] | None:
    return regex.search(text)
