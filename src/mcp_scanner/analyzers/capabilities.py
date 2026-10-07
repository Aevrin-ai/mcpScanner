# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Guess what a tool can do from its name, description, and input schema.

We match whole words, never parts of words. Matching parts of words causes silly
mistakes, like "file" inside "profile" or "rest" inside "interest".

Each guess keeps its reasons, so a rule can show the evidence.
A "strong" signal comes from the input schema (for example a free text `command`
parameter). A "weak" signal only comes from words in the name or description.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_scanner.models.mcp import ToolInfo
from mcp_scanner.rules.patterns import is_negated


class Capability(str, Enum):
    EXEC = "exec"  # run commands or code
    FS_READ = "fs-read"
    FS_WRITE = "fs-write"  # create, change, or delete files
    NETWORK = "network"  # call any URL the agent gives it
    DATABASE = "database"
    MESSAGING = "messaging"  # send email, chat, or posts to other people
    BROWSER = "browser"
    SECRETS = "secrets"  # handles credentials


@dataclass
class Signal:
    reason: str
    strong: bool
    location: str
    snippet: str = ""


@dataclass
class ToolCapabilities:
    tool: str
    signals: dict[Capability, list[Signal]] = field(default_factory=dict)

    def add(self, cap: Capability, signal: Signal) -> None:
        self.signals.setdefault(cap, []).append(signal)

    def has(self, cap: Capability) -> bool:
        return cap in self.signals

    def strong(self, cap: Capability) -> bool:
        return any(s.strong for s in self.signals.get(cap, []))

    def names(self) -> list[str]:
        return sorted(c.value for c in self.signals)


def split_words(identifier: str) -> list[str]:
    """`runShellCommand` -> [run, shell, command]; `read_file` -> [read, file]."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", identifier)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


# ---- word lists ------------------------------------------------------------

EXEC_PARAMS = {
    "command",
    "cmd",
    "shell",
    "script",
    "code",
    "source_code",
    "python_code",
    "js_code",
    "javascript",
    "bash",
    "powershell",
    "shell_command",
    "commandline",
    "command_line",
    "snippet",
    "program",
    "expression_code",
}
EXEC_NAME_WORDS = {"exec", "execute", "shell", "bash", "powershell", "terminal", "eval", "repl", "subprocess", "sh"}
EXEC_DESC = re.compile(
    r"\b(?:execut\w*|runs?|running|evaluat\w*|invok\w*)\s+(?:arbitrary\s+|any\s+|the\s+given\s+|the\s+provided\s+|user[\s-]provided\s+|a\s+|shell\s+|system\s+|os\s+|raw\s+)*"
    r"(?:shell\s+|terminal\s+|system\s+|bash\s+|powershell\s+)?(?:commands?|scripts?|code|python|javascript|js\s+code|bash|powershell|programs?)\b"
    r"|\bshell\s+commands?\b|\bsubprocess\b|\beval\s*\(|\barbitrary\s+(?:code|commands?)\b",
    re.IGNORECASE,
)

PATH_PARAMS = {
    "path",
    "file",
    "filepath",
    "file_path",
    "filename",
    "file_name",
    "dir",
    "directory",
    "folder",
    "dirpath",
    "dir_path",
    "destination",
    "dest",
    "source_path",
    "target_path",
    "output_path",
    "input_path",
    "paths",
}
FILE_WORDS = {"file", "files", "directory", "directories", "dir", "folder", "folders", "path", "filesystem"}
WRITE_VERBS = {
    "write",
    "delete",
    "remove",
    "move",
    "rename",
    "create",
    "edit",
    "overwrite",
    "append",
    "save",
    "mkdir",
    "rm",
    "unlink",
    "chmod",
    # "download" saves a file on this machine. "upload" is a read: it sends a local file away.
    "download",
    "modify",
    "replace",
    "patch",
    "truncate",
}
READ_VERBS = {"read", "get", "open", "cat", "view", "list", "search", "find", "load", "tail", "head", "upload"}
FS_WRITE_DESC = re.compile(
    r"\b(?:writes?|deletes?|removes?|overwrites?|creates?|modif(?:y|ies)|moves?|renames?|edits?)\b[^.\n]{0,40}\b(?:files?|director(?:y|ies)|folders?)\b",
    re.IGNORECASE,
)
FS_READ_DESC = re.compile(
    r"\b(?:reads?|opens?|lists?|returns?\s+the\s+contents?\s+of)\b[^.\n]{0,40}\b(?:files?|director(?:y|ies)|folders?)\b",
    re.IGNORECASE,
)

URL_PARAMS = {
    "url",
    "uri",
    "endpoint",
    "href",
    "link",
    "webhook",
    "webhook_url",
    "callback",
    "callback_url",
    "target_url",
    "base_url",
    "urls",
    "website",
}
HOST_PARAMS = {"host", "hostname", "domain", "ip", "ip_address", "server"}
NET_NAME_WORDS = {
    "fetch",
    "http",
    "request",
    "download",
    "curl",
    "scrape",
    "crawl",
    "browse",
    "webhook",
    "wget",
    "ping",
    "traceroute",
    "nslookup",
    "dns",
    "whois",
    "portscan",
    "nmap",
}
NET_DESC = re.compile(
    r"\b(?:fetch(?:es)?|downloads?|retrieves?|requests?|calls?|sends?\s+(?:an?\s+)?http\s+requests?\s+to)\b[^.\n]{0,40}\b(?:any\s+)?(?:urls?|web\s*pages?|websites?|endpoints?|the\s+internet)\b"
    r"|\bhttp\s+requests?\b|\bany\s+url\b",
    re.IGNORECASE,
)

DB_PARAMS = {"sql", "query_sql", "sql_query", "statement", "sql_statement"}
DB_DESC = re.compile(
    r"\b(?:sql|database|postgres(?:ql)?|mysql|sqlite|mariadb|mongodb|bigquery|snowflake|redshift|clickhouse)\b",
    re.IGNORECASE,
)

MSG_NAME_WORDS = {
    "send",
    "post",
    "publish",
    "email",
    "mail",
    "message",
    "sms",
    "tweet",
    "notify",
    "reply",
    "forward",
    "slack",
    "chat",
}
MSG_PARAMS = {
    "to",
    "recipient",
    "recipients",
    "email",
    "emails",
    "cc",
    "bcc",
    "channel",
    "phone",
    "phone_number",
    "chat_id",
}

BROWSER_NAME_WORDS = {"browser", "navigate", "page", "playwright", "puppeteer", "selenium"}
BROWSER_EVAL = re.compile(
    r"\b(?:page|frame|window|document)\.(?:eval|evaluate)\b|\bevaluate[_\s]?script\b|\bexecute\s+javascript\b",
    re.IGNORECASE,
)

SECRET_PARAM_WORDS = {"password", "passwd", "secret", "apikey", "credential", "credentials", "passphrase"}
SECRET_PARAM_NAMES = {
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "refresh_token",
    "bearer",
    "private_key",
    "client_secret",
    "secret_key",
    "session_token",
    "password",
    "passwd",
    "secret",
    "credentials",
    "credential",
    "pat",
}
NOT_SECRET_PARAMS = {
    "page_token",
    "pagetoken",
    "next_token",
    "nexttoken",
    "cursor",
    "next_cursor",
    "continuation_token",
    "sync_token",
    "resume_token",
    "max_tokens",
    "token_count",
    "tokens",
    "num_tokens",
    "token_limit",
    "csrf_token",
}


def is_free_text(schema: dict[str, Any]) -> bool:
    """True when a parameter accepts any text. An enum or a strict pattern limits it."""
    if "enum" in schema or "const" in schema:
        return False
    types = schema.get("type")
    if types not in (None, "string") and not (isinstance(types, list) and "string" in types):
        return False
    pattern = schema.get("pattern")
    return not (isinstance(pattern, str) and pattern.startswith("^") and len(pattern) < 40)


def is_secret_param(name: str) -> bool:
    lower = name.lower()
    if lower in NOT_SECRET_PARAMS or lower.endswith(("_count", "_limit", "_tokens")):
        return False
    if lower in SECRET_PARAM_NAMES:
        return True
    words = set(split_words(name))
    return (
        bool(words & SECRET_PARAM_WORDS)
        or ("api" in words and "key" in words)
        or (
            "token" in words
            and not words & {"page", "next", "max", "count", "limit", "sync", "resume", "continuation", "csrf"}
        )
    )


def _desc_signal(caps: ToolCapabilities, cap: Capability, regex: re.Pattern[str], text: str, where: str) -> None:
    for match in regex.finditer(text):
        if is_negated(text, match.start()):
            continue
        caps.add(cap, Signal(f"description says '{match.group(0).strip()}'", False, where, match.group(0)))
        return


def analyze_tool(tool: ToolInfo) -> ToolCapabilities:
    caps = ToolCapabilities(tool.name)
    name_words = set(split_words(tool.name))
    desc = tool.description or ""
    where_name = f"tool {tool.name} > name"
    where_desc = f"tool {tool.name} > description"
    _from_params(caps, tool, name_words)
    _from_name(caps, tool.name, name_words, where_name)
    _desc_signal(caps, Capability.EXEC, EXEC_DESC, desc, where_desc)
    _desc_signal(caps, Capability.FS_WRITE, FS_WRITE_DESC, desc, where_desc)
    _desc_signal(caps, Capability.FS_READ, FS_READ_DESC, desc, where_desc)
    _desc_signal(caps, Capability.NETWORK, NET_DESC, desc, where_desc)
    _desc_signal(caps, Capability.BROWSER, BROWSER_EVAL, f"{tool.name} {desc}", where_desc)
    if DB_DESC.search(desc) and (name_words & {"query", "sql", "execute", "run"} or caps.has(Capability.DATABASE)):
        caps.add(Capability.DATABASE, Signal("description mentions a database", False, where_desc))
    return caps


def _from_params(caps: ToolCapabilities, tool: ToolInfo, name_words: set[str]) -> None:
    for pname, schema in tool.properties().items():
        lower = pname.lower()
        where = f"tool {tool.name} > param {pname}"
        free = is_free_text(schema)
        if lower in EXEC_PARAMS and free:
            caps.add(Capability.EXEC, Signal(f"free text parameter '{pname}'", True, where))
        if lower in PATH_PARAMS:
            if name_words & WRITE_VERBS:
                caps.add(Capability.FS_WRITE, Signal(f"path parameter '{pname}' on a write style tool", True, where))
            elif name_words & (FILE_WORDS | READ_VERBS):
                caps.add(Capability.FS_READ, Signal(f"path parameter '{pname}'", True, where))
            else:
                # For example 'filename' on a screenshot tool: where to save output, not a file to read.
                caps.add(
                    Capability.FS_READ,
                    Signal(f"path parameter '{pname}' on a tool that is not about files", False, where),
                )
        if (lower in URL_PARAMS or schema.get("format") in ("uri", "url")) and free:
            caps.add(Capability.NETWORK, Signal(f"free text URL parameter '{pname}'", True, where))
        elif lower in HOST_PARAMS and free and name_words & NET_NAME_WORDS:
            caps.add(Capability.NETWORK, Signal(f"free text host parameter '{pname}'", True, where))
        if lower in DB_PARAMS and free:
            caps.add(Capability.DATABASE, Signal(f"free text SQL parameter '{pname}'", True, where))
        if lower == "query" and free and name_words & {"sql", "db", "database", "execute"}:
            caps.add(
                Capability.DATABASE, Signal(f"free text query parameter '{pname}' on a database tool", True, where)
            )
        if lower in MSG_PARAMS and name_words & MSG_NAME_WORDS:
            caps.add(Capability.MESSAGING, Signal(f"recipient parameter '{pname}'", True, where))
        if is_secret_param(pname):
            caps.add(Capability.SECRETS, Signal(f"parameter '{pname}' looks like a secret", True, where))


def _from_name(caps: ToolCapabilities, name: str, words: set[str], where: str) -> None:
    if words & EXEC_NAME_WORDS or {"run", "command"} <= words or {"run", "script"} <= words or {"run", "code"} <= words:
        caps.add(Capability.EXEC, Signal(f"tool name '{name}' suggests running commands or code", False, where))
    if words & WRITE_VERBS and words & FILE_WORDS:
        caps.add(Capability.FS_WRITE, Signal(f"tool name '{name}' suggests changing files", False, where))
    elif words & READ_VERBS and words & FILE_WORDS:
        caps.add(Capability.FS_READ, Signal(f"tool name '{name}' suggests reading files", False, where))
    if words & NET_NAME_WORDS:
        caps.add(Capability.NETWORK, Signal(f"tool name '{name}' suggests web requests", False, where))
    if words & {"sql", "database", "db"}:
        caps.add(Capability.DATABASE, Signal(f"tool name '{name}' suggests database access", False, where))
    if words & {"send", "post", "publish", "reply", "forward"} and words & (
        MSG_NAME_WORDS - {"send", "post", "publish", "reply", "forward"}
    ):
        caps.add(Capability.MESSAGING, Signal(f"tool name '{name}' suggests sending messages", False, where))
    if words & BROWSER_NAME_WORDS:
        caps.add(Capability.BROWSER, Signal(f"tool name '{name}' suggests browser control", False, where))


def analyze_inventory(tools: list[ToolInfo]) -> dict[str, ToolCapabilities]:
    return {tool.name: analyze_tool(tool) for tool in tools}
