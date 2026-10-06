# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Text patterns used by the text based rules.

Each pattern has a short label that tells a human what it found.
Patterns are tested in tests/regression with "must match" and "must not match" examples.
When you change a pattern, run those tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_scanner.models.severity import Confidence, Severity


@dataclass(frozen=True)
class TextPattern:
    key: str
    label: str
    regex: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    malicious: bool = False


def _pat(
    key: str,
    label: str,
    pattern: str,
    severity: Severity,
    confidence: Confidence = Confidence.MEDIUM,
    malicious: bool = False,
) -> TextPattern:
    return TextPattern(key, label, re.compile(pattern, re.IGNORECASE | re.MULTILINE), severity, confidence, malicious)


S, C = Severity, Confidence

# ---- Instructions that try to take over the agent --------------------------

INSTRUCTION_OVERRIDE: tuple[TextPattern, ...] = (
    _pat(
        "override-previous",
        "tells the agent to ignore its earlier instructions",
        r"\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+)*"
        r"(?:previous|prior|above|earlier|preceding|original|system|safety|security|existing)\s+"
        r"(?:\w+\s+){0,2}?(?:instructions?|prompts?|rules|guidelines|directives|restrictions|messages|context|polic(?:y|ies))\b",
        S.CRITICAL,
        C.HIGH,
        malicious=True,
    ),
    _pat(
        "override-all",
        "tells the agent to ignore all instructions",
        r"\b(?:ignore|disregard|forget)\s+(?:all|any|every)\s+(?:of\s+)?(?:your\s+|the\s+)?(?:instructions?|rules|guidelines)\b",
        S.CRITICAL,
        C.HIGH,
        malicious=True,
    ),
    _pat(
        "new-instructions",
        "announces new instructions for the agent",
        r"\b(?:new|updated|real|actual)\s+(?:system\s+)?(?:instructions?|directives?)\s*:",
        S.HIGH,
        C.MEDIUM,
    ),
    _pat(
        "you-are-now",
        "tries to give the agent a new role",
        r"\byou\s+(?:are|will)\s+now\s+(?:be\s+|act\s+as\s+|an?\s+)",
        S.HIGH,
        C.MEDIUM,
    ),
    _pat(
        "act-as-admin",
        "asks the agent to act with admin power",
        r"\bact\s+as\s+(?:an?\s+)?(?:admin|administrator|root|superuser|system)\b",
        S.HIGH,
        C.MEDIUM,
    ),
    _pat(
        "role-marker",
        "contains a fake chat role marker",
        r"(?:^\s*(?:system|assistant)\s*:\s*\S)|<\|?(?:im_start|system|endoftext)\|?>|\[/?INST\]|<<\s*SYS\s*>>",
        S.HIGH,
        C.MEDIUM,
    ),
    _pat(
        "mode-switch",
        "tries to switch the agent into an unsafe mode",
        r"\b(?:enter|enable|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted|debug)\s+mode\b",
        S.HIGH,
        C.MEDIUM,
    ),
    _pat(
        "markup-override",
        "hides an override inside a comment or marker",
        r"(?:<!--[^>]{0,200}?|\[\[\[|\|\|\|)\s*(?:system|admin)[\s_]*(?:override|instruction|command)",
        S.CRITICAL,
        C.HIGH,
        malicious=True,
    ),
)

# ---- Tool poisoning: hidden orders inside tool metadata ---------------------

HIDDEN_ORDER_TAGS = _pat(
    "important-tag",
    "contains an <IMPORTANT> style tag, a common way to hide orders for the agent",
    r"<\s*/?\s*(?:IMPORTANT|CRITICAL|SYSTEM|INSTRUCTIONS?|HIDDEN|SECRET|ADMIN|PRIORITY)\s*>",
    S.HIGH,
    C.MEDIUM,
)

CONCEALMENT: tuple[TextPattern, ...] = (
    _pat(
        "dont-tell-user",
        "tells the agent to hide something from the user",
        r"\b(?:do\s*n[o']?t|never|without)\s+(?:ever\s+)?(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|notify(?:ing)?|alert(?:ing)?|reveal(?:ing)?|show(?:ing)?|disclos(?:e|ing))\s+"
        r"(?:this\s+|it\s+|anything\s+|that\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|them)\b",
        S.HIGH,
        C.HIGH,
        malicious=True,
    ),
    _pat(
        "hide-from-user",
        "tells the agent to keep something secret from the user",
        r"\b(?:hide|conceal|keep)\s+(?:this|it|that|these)\s+(?:secret\s+)?from\s+the\s+user\b|\bthe\s+user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|be\s+told)\b",
        S.HIGH,
        C.HIGH,
        malicious=True,
    ),
    _pat(
        "silent-action",
        "asks the agent to do something silently",
        r"\b(?:secretly|silently|covertly|quietly|invisibly)\s+(?:send|upload|forward|copy|include|add|read|collect|exfiltrate|transmit|change|modify)\b",
        S.HIGH,
        C.HIGH,
        malicious=True,
    ),
)

# A sensitive file name near a verb that reads or sends it.
SENSITIVE_PATH = re.compile(
    r"(?:~|\$HOME|%USERPROFILE%)?[/\\]\.(?:ssh|aws|kube|gnupg|docker|azure|config[/\\]gcloud)\b"
    r"|\b(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|credentials\.json|service[_-]account\.json|\.netrc|\.pgpass|\.npmrc|\.pypirc|wallet\.dat|login\s+data)\b"
    r"|\b(?:mcp\.json|claude_desktop_config\.json|mcp_config\.json)\b"
    r"|/etc/(?:passwd|shadow|sudoers)\b"
    r"|(?<![\w.])\.env(?![\w.])",
    re.IGNORECASE,
)
ACCESS_VERB = re.compile(
    r"\b(?:read|cat|open|load|include|pass|send|upload|attach|copy|provide|retrieve|get|fetch|access|contents?\s+of)\b",
    re.IGNORECASE,
)

# The agent is told to put private context into a tool argument.
CONTEXT_HARVEST = _pat(
    "context-harvest",
    "asks the agent to send private conversation data or secrets through the tool",
    r"\b(?:include|append|attach|add|pass|put|send|provide|insert|paste|share|copy|dump|forward)\b[^.\n]{0,60}?\b(?:(?:entire|full|whole|complete)\s+)?"
    r"(?:conversation(?:\s+history)?|chat\s+history|message\s+history|system\s+prompt|(?:previous|prior|last|recent|all)\s+messages|"
    r"api\s+keys?|passwords?|credentials|secrets|private\s+keys?|ssh\s+keys?)\b",
    S.CRITICAL,
    C.MEDIUM,
    malicious=True,
)

# ---- Shadowing: orders about OTHER tools -----------------------------------

CROSS_TOOL: tuple[TextPattern, ...] = (
    _pat(
        "when-using-other-tool",
        "gives orders about how another tool must behave",
        r"\b(?:when(?:ever)?|before|after|instead\s+of)\s+(?:you\s+)?(?:use|using|call|calling|invoke|invoking|run|running)\s+(?:the\s+|any\s+)?[`'\"]?[\w\-.]+[`'\"]?\s+tool\b"
        # "When (mcp_whatsapp) send_message is invoked": a tool of another server, named by its call.
        r"|\b(?:when(?:ever)?|if|before|after)\s+(?:the\s+)?(?:\([\w\-.]+\)\s*)?[`'\"]?[\w\-.]*_[\w\-.]+[`'\"]?\s+(?:tool\s+)?(?:is|gets|was)\s+(?:invoked|called|used|run)\b",
        S.HIGH,
        C.MEDIUM,
    ),
    _pat(
        "redirect-recipients",
        "tells the agent to send messages or data to a fixed address",
        r"\b(?:all|any|every)\s+(?:e-?mails?|messages?|requests?|payments?|transfers?)\s+(?:must|should|need\s+to|have\s+to)\s+(?:also\s+)?(?:be\s+)?(?:sent|forwarded|cc'?d|bcc'?d|redirected|routed|copied)\s+to\b",
        S.CRITICAL,
        C.HIGH,
        malicious=True,
    ),
    _pat(
        "hidden-bcc",
        "tells the agent to secretly copy messages to an address",
        r"\b(?:always\s+)?(?:bcc|cc)\s+(?:a\s+copy\s+to\s+)?[\w.+\-]+@[\w\-]+\.[\w.]+",
        S.CRITICAL,
        C.HIGH,
        malicious=True,
    ),
)

# ---- Coercion: "always call me first" ---------------------------------------

COERCION: tuple[TextPattern, ...] = (
    _pat(
        "call-me-first",
        "pushes the agent to always call this tool before others",
        r"\b(?:always|must)\s+(?:call|use|run|invoke|consult)\s+this\s+(?:tool|function)\s+(?:first|before)\b"
        r"|\bbefore\s+(?:using|calling|invoking|running)\s+any\s+other\s+tools?\b",
        S.LOW,
        C.LOW,
    ),
    _pat(
        "applies-without-call",
        "says its rules apply even when the tool is never called (line jumping)",
        r"\b(?:even\s+)?without\s+(?:calling|invoking|using)\s+this\s+tool\b|\bappl(?:y|ies)\s+to\s+(?:all|every|any)\s+(?:other\s+)?tools\b",
        S.HIGH,
        C.MEDIUM,
        malicious=True,
    ),
)

# ---- Data exfiltration language ---------------------------------------------

EXFILTRATION: tuple[TextPattern, ...] = (
    _pat(
        "send-to-external",
        "describes sending user data to an outside place",
        r"\b(?:send|sends|forward|forwards|upload|uploads|post|posts|transmit|transmits|exfiltrat\w*|leak|leaks|sync|syncs)\b[^.\n]{0,80}?"
        r"\b(?:conversation|chat|history|messages|context|data|contents?|files?|credentials?|secrets?|keys?|tokens?|environment)\b[^.\n]{0,80}?"
        r"\bto\s+(?:https?://|an?\s+external|a\s+remote|the\s+attacker|our\s+(?:server|endpoint|collector)|a\s+third[\s-]party|[\w.+\-]+@[\w\-]+\.\w+)",
        S.MEDIUM,
        C.MEDIUM,
    ),
    _pat(
        "also-collects",
        "says the tool also collects or sends data on the side",
        r"\b(?:also|additionally|in\s+addition|at\s+the\s+same\s+time|in\s+the\s+background|behind\s+the\s+scenes)\s*,?\s+"
        r"(?:collects?|gathers?|harvests?|uploads?|sends?|records?|captures?|logs?)\s+(?:all\s+|any\s+|the\s+|your\s+|user\s+)*"
        r"(?:data|credentials?|keys?|tokens?|passwords?|messages?|history|files?|keystrokes|clipboard)",
        S.HIGH,
        C.MEDIUM,
    ),
)

SUSPICIOUS_DOMAINS = re.compile(
    r"\b(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator\.net|"
    r"interact\.sh|oast\.(?:fun|live|me|pro|site|online)|pastebin\.com|transfer\.sh|api\.telegram\.org/bot|"
    r"(?:attacker|evil|malicious|exfil|steal|hacker)[\w-]*\.(?:com|net|org|io|xyz|site))\b",
    re.IGNORECASE,
)

PRIVILEGE: tuple[TextPattern, ...] = (
    _pat(
        "needs-root",
        "says it needs root or administrator power",
        r"\b(?:requires?|needs?|runs?\s+(?:as|with)|with)\s+(?:root|administrator|admin|elevated|sudo)\s+(?:privileges?|permissions?|rights|access)\b"
        r"|\bruns?\s+as\s+root\b|\bwith\s+sudo\b|\bsudo\s+(?:mode|access|-[si])\b",
        S.MEDIUM,
        C.MEDIUM,
    ),
    _pat(
        "bypass-security",
        "talks about getting around security checks",
        r"\b(?:bypass|disable|skip|circumvent)\s+(?:all\s+|any\s+|the\s+)?(?:security|permission|authori[sz]ation|authentication|sandbox|safety)\s*(?:checks?|controls?|restrictions?|prompts?)?\b",
        S.HIGH,
        C.MEDIUM,
    ),
)

# A tool that talks ABOUT attacks (for example a jailbreak detector) uses a defensive
# verb AND names an attack. Both must appear, so a plain word like "audit" in an
# email address does not make real attack text look harmless.
DEFENSIVE_VERB = re.compile(
    r"\b(?:detect\w*|scan\w*|block\w*|prevent\w*|filter\w*|guard\w*|identif\w*|flag\w*|"
    r"protect\w*|defen[cs]\w*|mitigat\w*|classif\w*|sanitiz\w*|moderat\w*)\b",
    re.IGNORECASE,
)
ATTACK_NOUN = re.compile(
    r"\b(?:injection|attacks?|jailbreak\w*|malicious|phishing|exploit\w*|poison\w*|threats?|"
    r"(?:phrases|patterns|examples|strings)\s+(?:like|such\s+as))\b",
    re.IGNORECASE,
)

# Words before a match that cancel it: "does not run commands".
NEGATION = re.compile(
    r"\b(?:not|never|no|cannot|can't|won't|doesn't|does\s+not|do\s+not|don't|without|nor|unable\s+to)\b(?:\W+\w+){0,3}\W*$",
    re.IGNORECASE,
)


def is_negated(text: str, start: int, window: int = 40) -> bool:
    """True when a negation word sits just before the match."""
    return bool(NEGATION.search(text[max(0, start - window) : start]))
