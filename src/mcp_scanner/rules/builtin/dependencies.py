# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Supply chain: the packages a server is built from."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_scanner.analyzers.dependencies import match_malicious, typosquat_target
from mcp_scanner.models.finding import Evidence, FindingCandidate, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import NEEDS_DEPENDENCIES, Rule
from mcp_scanner.scanner.context import ScanContext


class KnownMaliciousPackage(Rule):
    id = "MCP-DEP-001"
    title = "Known malicious package"
    category = Category.SUPPLY_CHAIN
    severity = Severity.CRITICAL
    description = "The server uses a package version that public security advisories list as malicious or compromised."
    why_it_matters = "This code is known to steal data or install malware."
    attack_scenario = "postmark-mcp 1.0.16 silently BCC'd every email the agent sent to an outside address."
    recommendation = (
        "Remove the package now. Rotate every credential the server could reach, and check for persistence."
    )
    needs = frozenset({NEEDS_DEPENDENCIES})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.dependencies is not None
        for dep in ctx.dependencies.dependencies:
            found = match_malicious(dep)
            if found is None:
                continue
            version = dep.version or "unknown version"
            text = f"{dep.name} ({version}) is listed as malicious: {found.entry.summary}"
            if not found.certain:
                text += " The installed version is not known, so check it."
            candidate = self.finding(
                TargetKind.DEPENDENCY,
                dep.name,
                text,
                [
                    Evidence.make(
                        "dependency",
                        dep.location,
                        f"{dep.name} {dep.spec}".strip(),
                        f"affected: {', '.join(found.entry.versions)}",
                    )
                ],
                confidence=Confidence.HIGH if found.certain else Confidence.MEDIUM,
                malicious=True,
                # A public advisory for this exact version is proof, not a guess.
                confirmed=found.certain,
            )
            candidate.references = list(found.entry.references)
            yield candidate


class Typosquat(Rule):
    id = "MCP-DEP-002"
    title = "Package name looks like a typo of a popular package"
    category = Category.SUPPLY_CHAIN
    severity = Severity.HIGH
    description = "A dependency or launch package name is one small change away from a popular package."
    why_it_matters = "Attackers publish lookalike names and wait for someone to mistype. The fake package often works and also steals."
    attack_scenario = (
        "'@modelcontextprotocol/server-filesytem' (missing 's') is installed instead of the real filesystem server."
    )
    recommendation = "Check the exact name and publisher. Replace it with the real package."
    needs = frozenset({NEEDS_DEPENDENCIES})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.dependencies is not None
        seen: set[str] = set()
        for dep in ctx.dependencies.dependencies:
            if not dep.direct or dep.name in seen:
                continue
            target = typosquat_target(dep)
            if target is None:
                continue
            seen.add(dep.name)
            yield self.finding(
                TargetKind.DEPENDENCY,
                dep.name,
                f"'{dep.name}' looks like a misspelling of the popular package '{target}'.",
                [Evidence.make("dependency", dep.location, dep.name, f"similar to {target}")],
                confidence=Confidence.MEDIUM,
            )


class InstallScript(Rule):
    id = "MCP-DEP-003"
    title = "Package runs a script when installed"
    category = Category.SUPPLY_CHAIN
    severity = Severity.MEDIUM
    description = "package.json has preinstall, install, or postinstall scripts, or setup.py replaces the install step."
    why_it_matters = "Install scripts run before you ever start the server, with your full user rights."
    attack_scenario = (
        "A postinstall script downloads a binary and collects tokens from ~/.npmrc (as in the Nx compromise)."
    )
    recommendation = "Read the script. Install with --ignore-scripts when you can."
    references = ("https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c",)
    needs = frozenset({NEEDS_DEPENDENCIES})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.dependencies is not None
        for script in ctx.dependencies.install_scripts:
            yield self.finding(
                TargetKind.DEPENDENCY,
                script.file,
                f"The '{script.hook}' step runs: {script.command[:150]}"
                + (" It downloads or runs code inline." if script.risky else ""),
                [Evidence.make("dependency", script.file, script.command, f"{script.hook} script")],
                confidence=Confidence.HIGH,
                severity=Severity.HIGH if script.risky else Severity.LOW,
            )


class LooseDependency(Rule):
    id = "MCP-DEP-004"
    title = "Dependency from a URL or with any version"
    category = Category.SUPPLY_CHAIN
    severity = Severity.LOW
    description = "A dependency comes from a git or HTTP URL, or allows any version ('*' or 'latest')."
    why_it_matters = "The content can change without a new release you can review."
    attack_scenario = "A dependency points at a GitHub branch. The branch owner pushes code that steals tokens."
    recommendation = "Pin dependencies to released versions, and use a lock file."
    needs = frozenset({NEEDS_DEPENDENCIES})

    def check(self, ctx: ScanContext) -> Iterable[FindingCandidate]:
        assert ctx.dependencies is not None
        for dep in ctx.dependencies.dependencies:
            if not dep.direct or dep.source == "launch command":
                continue
            if dep.is_url:
                reason = f"comes from '{dep.spec[:120]}'"
            elif dep.is_unpinned and dep.ecosystem == "npm":
                reason = f"allows any version ('{dep.spec or '*'}')"
            else:
                continue
            yield self.finding(
                TargetKind.DEPENDENCY,
                dep.name,
                f"'{dep.name}' {reason}.",
                [Evidence.make("dependency", dep.location, f"{dep.name} {dep.spec}", reason)],
                confidence=Confidence.HIGH,
            )
