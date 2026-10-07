# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Find and hide secrets.

The same patterns are used to:
  - report secrets found in tool metadata, config files, and source code
  - hide secrets before text goes to an AI provider or a log file

Patterns are tight on purpose. A secret scanner that cries wolf is ignored.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    confidence: str  # "high" means the format is unique to that kind of secret


def _p(name: str, pattern: str, confidence: str = "high", flags: int = 0) -> SecretPattern:
    return SecretPattern(name, re.compile(pattern, flags), confidence)


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    _p("Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    _p("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _p("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    _p("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _p("Anthropic API key", r"\bsk-ant-[a-z]{3,6}\d{2}-[A-Za-z0-9_\-]{60,}"),
    _p("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}"),
    _p("OpenAI style API key", r"\bsk-(?:proj-|svcacct-)[A-Za-z0-9_\-]{40,}", "medium"),
    _p("xAI API key", r"\bxai-[A-Za-z0-9]{50,}\b"),
    _p("Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    _p("Slack webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    _p("Discord webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    _p("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("Stripe live key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    _p("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b"),
    _p("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "medium"),
    _p(
        "Password in connection URL",
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^\s:/@'\"]+:[^\s@/'\"]{3,}@",
    ),
)

# key = value style secrets. Only reported when the value looks random enough.
_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:api[_\-]?key|secret|passw(?:or)?d|token|access[_\-]?key|private[_\-]?key|auth))\b"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-/+=.]{16,})"
)
_PLACEHOLDER_WORDS = (
    "your",
    "xxxx",
    "example",
    "changeme",
    "placeholder",
    "dummy",
    "sample",
    "redacted",
    "insert",
    "<",
    "${",
    "test",
    "fake",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def is_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(word in lower for word in _PLACEHOLDER_WORDS) or len(set(value)) <= 3


_KEY_WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PAT", "CREDENTIALS", "APIKEY")


def is_key_name(name: str) -> bool:
    """An environment variable that holds a key: NOTION_TOKEN, OPENAI_API_KEY. Not ENABLE_TOKEN_PASSTHROUGH."""
    return name.upper().rsplit("_", 1)[-1] in _KEY_WORDS


# A value that is code, not a literal: `token = process.env.NOTION_TOKEN` or `key = options.authToken`.
# Only letters and underscores between the dots; real keys have digits or other characters.
CODE_REFERENCE = re.compile(r"^(?:[A-Za-z_]+\.)+[A-Za-z_]+$")


def looks_random(value: str, threshold: float = 3.5) -> bool:
    return len(value) >= 16 and shannon_entropy(value) >= threshold and not is_placeholder(value)


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    start: int
    end: int
    confidence: str

    def preview(self, text: str) -> str:
        return mask(text[self.start : self.end])


def find_secrets(text: str, *, include_assignments: bool = True) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for pattern in SECRET_PATTERNS:
        for m in pattern.regex.finditer(text):
            matches.append(SecretMatch(pattern.name, m.start(), m.end(), pattern.confidence))
    if include_assignments:
        for m in _ASSIGNMENT.finditer(text):
            value = m.group(2)
            if looks_random(value) and not CODE_REFERENCE.match(value) and not _overlaps(matches, m.start(2), m.end(2)):
                matches.append(SecretMatch("Hardcoded credential", m.start(2), m.end(2), "medium"))
    return sorted(matches, key=lambda s: s.start)


def _overlaps(matches: list[SecretMatch], start: int, end: int) -> bool:
    return any(m.start < end and start < m.end for m in matches)


def mask(value: str) -> str:
    """Show only the first few characters, so a person can recognize the key but not use it."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...(redacted, {len(value)} chars)"


# Command line flags whose value is a credential: --api-key, --token, --github-token, --password, ...
SECRET_FLAG = re.compile(
    r"^--?(?:[a-z0-9]+[-_])*(?:api[-_]?key|apikey|key|token|secret|password|passwd|pat|auth|bearer|credentials?)$",
    re.IGNORECASE,
)
_SECRET_FLAG_IN_TEXT = re.compile(
    r"((?<!\S)--?(?:[a-z0-9]+[-_])*(?:api[-_]?key|apikey|key|token|secret|password|passwd|pat|auth|bearer|credentials?)"
    r"(?:=|\s+))([^\s\"']+)",
    re.IGNORECASE,
)


def mask_args(args: list[str]) -> list[str]:
    """A copy of command line arguments that is safe to show: values of secret flags are masked."""
    shown: list[str] = []
    hide_next = False
    for arg in args:
        if hide_next and not arg.startswith("-"):
            shown.append(mask(arg))
            hide_next = False
            continue
        hide_next = False
        flag, eq, value = arg.partition("=")
        if flag.startswith("-") and SECRET_FLAG.match(flag):
            if eq:
                shown.append(f"{flag}={mask(value)}")
            else:
                shown.append(arg)
                hide_next = True
            continue
        shown.append(redact(arg))
    return shown


def mask_command_line(text: str) -> str:
    """Like mask_args, for a whole command line as one string."""
    return redact(_SECRET_FLAG_IN_TEXT.sub(lambda m: m.group(1) + mask(m.group(2)), text))


def redact(text: str) -> str:
    """Replace every secret in the text with a marker."""
    matches = find_secrets(text)
    if not matches:
        return text
    out, last = [], 0
    for m in matches:
        if m.start < last:
            continue
        out.append(text[last : m.start])
        out.append(f"[REDACTED {m.kind}]")
        last = m.end
    out.append(text[last:])
    return "".join(out)


SECRET_NAME_WORDS = ("key", "token", "secret", "password", "passwd", "pwd", "credential", "auth", "pat", "apikey")


def name_looks_secret(name: str) -> bool:
    """True for names like OPENAI_API_KEY or db_password."""
    words = re.split(r"[^a-z0-9]+", name.lower())
    joined = name.lower().replace("-", "_")
    if any(
        w in ("key", "token", "secret", "password", "passwd", "pwd", "credential", "credentials", "apikey", "pat")
        for w in words
    ):
        return True
    return any(s in joined for s in ("api_key", "apikey", "secret", "password", "access_token", "auth_token"))
