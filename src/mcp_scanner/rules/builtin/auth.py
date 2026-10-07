# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Authentication and transport security for remote servers."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlparse

from mcp_scanner.analyzers.capabilities import Capability
from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import Rule
from mcp_scanner.scanner.context import ScanContext
from mcp_scanner.utils.secrets import mask, name_looks_secret

AUTH_HEADER_WORDS = ("authorization", "api-key", "apikey", "x-api-key", "token", "cookie", "secret", "auth")
AUTH_REFS = ("https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",)


def is_local_host(host: str | None) -> bool:
    if not host:
        return False
    if host in ("localhost", "host.docker.internal") or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


class PlainHttp(Rule):
    id = "MCP-AUTH-001"
    title = "Remote server uses plain HTTP"
    category = Category.AUTHENTICATION
    severity = Severity.HIGH
    description = "The server URL uses http:// on a non-local host, so traffic is not encrypted."
    why_it_matters = (
        "Anyone on the network path can read tokens and tool results, and change tool definitions in transit."
    )
    attack_scenario = "On public Wi-Fi, an attacker rewrites the tools/list answer to add a poisoned description."
    recommendation = "Use https:// for every remote MCP server."
    references = AUTH_REFS

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        if not ctx.spec.is_remote or not ctx.spec.url:
            return
        parsed = urlparse(ctx.spec.url)
        if parsed.scheme == "http" and not is_local_host(parsed.hostname):
            yield self.finding(
                TargetKind.CONFIG,
                ctx.spec.name,
                f"The server at {parsed.hostname} is reached over plain HTTP.",
                [Evidence.make("config", "server url", _safe_url(ctx.spec.url), "http scheme")],
                confidence=Confidence.HIGH,
            )


class NoAuthentication(Rule):
    id = "MCP-AUTH-002"
    title = "Remote server with powerful tools needs no login"
    category = Category.AUTHENTICATION
    severity = Severity.HIGH
    description = "The scanner connected without any credentials, and the server offers tools that run commands, change files, or query data."
    why_it_matters = "Anyone who can reach the URL can use these tools. Local servers can also be reached by web pages (DNS rebinding)."
    attack_scenario = (
        "A server on 0.0.0.0:8000 with a 'run_command' tool is found by an internet scan and used by strangers."
    )
    recommendation = "Require OAuth or a token, and bind local servers to 127.0.0.1 only."
    references = AUTH_REFS

    POWERFUL = (Capability.EXEC, Capability.FS_WRITE, Capability.DATABASE, Capability.FS_READ)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        spec = ctx.spec
        if not spec.is_remote or not ctx.connected or not spec.url:
            return
        if any(any(w in k.lower() for w in AUTH_HEADER_WORDS) for k in spec.headers):
            return
        parsed = urlparse(spec.url)
        if parsed.password or any(name_looks_secret(k) for k, _ in parse_qsl(parsed.query)):
            return
        powerful = sorted({t for t, caps in ctx.capabilities.items() for c in self.POWERFUL if caps.strong(c)})
        if not powerful:
            return
        local = is_local_host(parsed.hostname)
        yield self.finding(
            TargetKind.SERVER,
            spec.name,
            f"No credentials were needed to use {len(powerful)} powerful tools ({', '.join(powerful[:5])})"
            + (" on a local address." if local else "."),
            [Evidence.make("dynamic", "server url", _safe_url(spec.url), "connected without credentials")],
            confidence=Confidence.LOW if local else Confidence.MEDIUM,
            severity=Severity.MEDIUM if local else Severity.HIGH,
        )


class CredentialsInUrl(Rule):
    id = "MCP-AUTH-003"
    title = "Credentials in the server URL"
    category = Category.AUTHENTICATION
    severity = Severity.MEDIUM
    description = "The server URL carries a password or token in the address itself."
    why_it_matters = "URLs end up in logs, browser history, proxy logs, and error messages."
    attack_scenario = "A proxy log stores https://mcp.example.com/mcp?api_key=... and an admin reads it."
    recommendation = "Send credentials in an Authorization header instead."
    references = AUTH_REFS

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        if not ctx.spec.url:
            return
        parsed = urlparse(ctx.spec.url)
        names = [k for k, v in parse_qsl(parsed.query) if name_looks_secret(k) and v and not v.startswith("${")]
        if parsed.password and not parsed.password.startswith("${"):
            names.insert(0, "password")
        if names:
            yield self.finding(
                TargetKind.CONFIG,
                ctx.spec.name,
                f"The URL contains credentials ({', '.join(names)}).",
                [Evidence.make("config", "server url", _safe_url(ctx.spec.url), "credentials in URL")],
                confidence=Confidence.HIGH,
            )


def _safe_url(url: str) -> str:
    """The URL with secret values hidden."""
    parsed = urlparse(url)
    netloc = parsed.netloc
    if parsed.password:
        netloc = netloc.replace(parsed.password, "****")
    query = "&".join(f"{k}={mask(v) if name_looks_secret(k) else v}" for k, v in parse_qsl(parsed.query))
    return parsed._replace(netloc=netloc, query=query).geturl()
