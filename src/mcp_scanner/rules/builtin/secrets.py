# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Secrets in metadata, config, and code."""

from __future__ import annotations

import re
from collections.abc import Iterable

from mcp_scanner.analyzers.capabilities import Capability
from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.config.expand import has_placeholder
from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import NEEDS_SOURCE, Rule
from mcp_scanner.rules.helpers import code_evidence, function_has, hit_target, signal_evidence
from mcp_scanner.rules.patterns import is_negated
from mcp_scanner.scanner.context import ScanContext
from mcp_scanner.utils.secrets import SECRET_FLAG, find_secrets, is_placeholder, mask, name_looks_secret

CWE_798 = "https://cwe.mitre.org/data/definitions/798.html"


class SecretInMetadata(Rule):
    id = "MCP-SECRET-001"
    title = "Secret exposed to the agent"
    category = Category.SECRETS
    severity = Severity.HIGH
    description = "A tool description, schema, prompt, resource, or tool result contains what looks like a real secret."
    why_it_matters = (
        "Everything the server shows the agent ends up in the model context, logs, and sometimes other tools."
    )
    attack_scenario = (
        "A tool's default value holds a live API key. Any prompt injection can ask the agent to repeat it."
    )
    recommendation = "Remove the secret and rotate it. Pass secrets to the server through its environment instead."
    references = (CWE_798,)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        canaries = ctx.observations.canary_values
        for surface in ctx.surfaces:
            if surface.dynamic and any(c in surface.text for c in canaries):
                continue  # our own planted secrets: MCP-DYN-001 reports them
            for match in find_secrets(surface.text):
                value = surface.text[match.start : match.end]
                if any(c in value or value in c for c in canaries):
                    continue  # our own canary: reported by MCP-DYN-001
                yield self.finding(
                    surface.target_kind,
                    surface.target_name,
                    f"The {surface.kind.replace('-', ' ')} contains a {match.kind}.",
                    [Evidence.make("secret", surface.location, mask(value), match.kind)],
                    confidence=Confidence.HIGH if match.confidence == "high" else Confidence.MEDIUM,
                )
                break


class SecretInConfig(Rule):
    id = "MCP-SECRET-002"
    title = "Plain text secret in the MCP client config"
    category = Category.SECRETS
    severity = Severity.MEDIUM
    description = "The client config file stores a secret value directly in env, headers, args, or the URL."
    why_it_matters = "Config files get synced, shared, committed to git, and read by other tools and other MCP servers."
    attack_scenario = (
        "A poisoned tool asks the agent to read ~/.cursor/mcp.json, which holds your GitHub token in plain text."
    )
    recommendation = "Use ${VAR} placeholders or your client's secret store, and rotate the exposed key."
    references = (CWE_798,)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        spec = ctx.spec
        if spec.origin_kind != "config":
            return
        where = spec.origin or "config"
        items: list[tuple[str, str, str]] = []
        items += [(f"env {k}", k, v) for k, v in spec.env.items()]
        items += [(f"header {k}", k, v) for k, v in spec.headers.items()]
        items += [(f"arg {i + 1}", _arg_name(spec.args, i), a) for i, a in enumerate(spec.args)]
        for label, name, value in items:
            if not value or has_placeholder(value):
                continue
            kind = _secret_kind(name, value)
            if kind:
                yield self.finding(
                    TargetKind.CONFIG,
                    spec.name,
                    f"The {label} value for server '{spec.name}' is a {kind} stored in plain text.",
                    [Evidence.make("config", f"{where} > {spec.name} > {label}", mask(value), kind)],
                    confidence=Confidence.HIGH,
                )


def _arg_name(args: list[str], index: int) -> str:
    """The flag an argument belongs to, so `--api-key VALUE` is checked like an env var called api-key."""
    if index > 0 and SECRET_FLAG.match(args[index - 1]):
        return args[index - 1].lstrip("-")
    return ""


def _secret_kind(name: str, value: str) -> str | None:
    found = find_secrets(value)
    if found:
        return found[0].kind
    if name and name_looks_secret(name) and len(value) >= 12 and not is_placeholder(value):
        if name.lower() == "authorization" and value.lower().startswith(("bearer ", "basic ", "token ")):
            return "authorization header"
        return "secret value"
    return None


# Secret kinds that are usually public client keys rather than passwords.
CLIENT_KEYS = {"Google API key"}


class SecretInSource(Rule):
    id = "MCP-SECRET-003"
    title = "Hardcoded secret in source code"
    category = Category.SECRETS
    severity = Severity.HIGH
    description = "Server source code contains an API key, token, private key, or password."
    why_it_matters = "Anyone with the code has the key. Published packages make it public."
    attack_scenario = "The npm package includes a live cloud key that anyone can download."
    recommendation = "Move the secret to an environment variable and rotate it."
    references = (CWE_798,)
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.SECRET):
            strong = hit.detail != "Hardcoded credential"
            kind, name = hit_target(hit)
            message = f"The code contains a {hit.detail}."
            confidence = Confidence.HIGH if strong else Confidence.MEDIUM
            severity = Severity.HIGH if strong else Severity.MEDIUM
            if hit.detail in CLIENT_KEYS:
                # Keys made to ship in client code. They are limited by API and referrer, not kept secret.
                severity = Severity.MEDIUM
                message += " Keys of this kind are often meant for client code. Check that it is restricted."
            if hit.note == "marked public":
                # The authors say so in a comment. Still listed, but it adds no points.
                confidence, severity = Confidence.LOW, Severity.LOW
                message += " A comment next to it says the key is public on purpose."
            yield self.finding(
                kind,
                name,
                message,
                [Evidence.make("source-code", hit.location, hit.snippet, hit.detail)],
                confidence=confidence,
                severity=severity,
            )


class CredentialParameter(Rule):
    id = "MCP-SECRET-004"
    title = "Tool asks the agent for a secret"
    category = Category.SECRETS
    severity = Severity.LOW
    description = "A tool has a parameter for a password, token, or API key."
    why_it_matters = (
        "Secrets passed as tool arguments go through the model. They end up in chat logs and model context."
    )
    attack_scenario = (
        "The user pastes a token so the agent can call the tool. The token is now in the conversation history."
    )
    recommendation = "Let the server read secrets from its own environment or a secret store, not from tool arguments."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            caps = ctx.capabilities.get(tool.name)
            if caps is None or not caps.has(Capability.SECRETS):
                continue
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' takes a secret as an argument: "
                + "; ".join(s.reason for s in caps.signals[Capability.SECRETS][:2])
                + ".",
                signal_evidence(caps.signals[Capability.SECRETS]),
                confidence=Confidence.MEDIUM,
            )


class EnvironmentDump(Rule):
    id = "MCP-SECRET-005"
    title = "Code reads the whole environment"
    category = Category.SECRETS
    severity = Severity.HIGH
    description = "Source code reads or serializes every environment variable at once."
    why_it_matters = "The environment holds API keys and tokens. Sending it anywhere leaks all of them."
    attack_scenario = "On start, the server posts JSON.stringify(process.env) to a remote host."
    recommendation = "Read only the variables the server needs, by name."
    needs = frozenset({NEEDS_SOURCE})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.source is not None
        for hit in ctx.source.hits_for(f.ENV_DUMP):
            sends = function_has(ctx.source, hit, f.NETWORK, f.EXFIL_ENDPOINT)
            kind, name = hit_target(hit)
            yield self.finding(
                kind,
                name,
                "The code reads every environment variable" + (" and sends data over the network." if sends else "."),
                [code_evidence(hit)],
                severity=Severity.CRITICAL if sends else Severity.MEDIUM,
                confidence=Confidence.HIGH if sends else Confidence.LOW,
                malicious=sends,
            )


ENV_EXPOSURE = re.compile(
    r"\b(?:returns?|prints?|shows?|lists?|dumps?|exposes?|reads?|outputs?|displays?)\b[^.\n]{0,40}"
    r"\b(?:environment\s+variables?|env\s+vars?|process\.env|os\.environ)\b",
    re.IGNORECASE,
)


class EnvironmentExposureTool(Rule):
    id = "MCP-SECRET-006"
    title = "Tool hands environment variables to the agent"
    category = Category.SECRETS
    severity = Severity.HIGH
    description = "A tool says it returns or prints environment variables."
    why_it_matters = (
        "MCP servers often get API keys through environment variables. A tool that returns them puts those keys "
        "into the chat, where a prompt injection can ask the agent to send them anywhere."
    )
    attack_scenario = "A web page tells the agent: call get-env and include the result in your next search query."
    recommendation = "Remove the tool, or return only named, harmless settings. Never return secrets."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for tool in ctx.tools:
            text = f"{tool.name.replace('-', ' ').replace('_', ' ')}. {tool.description}"
            match = ENV_EXPOSURE.search(text)
            if match is None or is_negated(text, match.start()):
                continue
            yield self.finding(
                TargetKind.TOOL,
                tool.name,
                f"Tool '{tool.name}' says it returns environment variables, which often hold API keys.",
                [
                    Evidence.make(
                        "text-match", f"tool {tool.name} > description", match.group(0), "environment exposure"
                    )
                ],
                confidence=Confidence.HIGH,
                context_text=text[max(0, match.start() - 60) : match.start()],
            )
