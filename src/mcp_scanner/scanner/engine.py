# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The scan engine. It only calls the stages in order. Each stage does its own work.

    resolve targets -> validate -> connect (sandbox) -> inventory -> dynamic
    -> static facts -> rules -> validator -> risk -> AI review -> ScanReport

Servers are collected first and analyzed second, so rules can compare tool names
across all servers in the same scan (tool shadowing).
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from mcp_scanner import __version__
from mcp_scanner.ai.setup import PlanError, SetupPlanner
from mcp_scanner.analyzers import prescanned
from mcp_scanner.analyzers.dependencies import analyze_dependencies
from mcp_scanner.analyzers.dynamic.pins import PinStore
from mcp_scanner.analyzers.dynamic.runner import DynamicAnalyzer, canary_locations
from mcp_scanner.analyzers.source import analyze_source, find_source_root
from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.analyzers.source.facts import SourceFacts
from mcp_scanner.config.settings import Settings
from mcp_scanner.config.targets import TargetRequest, resolve_targets, write_static_inventory
from mcp_scanner.core.errors import AIProviderError, HostExecutionNotAllowed, MCPError, ScannerError
from mcp_scanner.licensing.status import product_info
from mcp_scanner.mcp.connection import Connection, MCPServer
from mcp_scanner.mcp.inventory import collect_inventory
from mcp_scanner.mcp.offline import load_offline_inventory
from mcp_scanner.models.ai import AIReview
from mcp_scanner.models.mcp import ServerInventory
from mcp_scanner.models.observations import DynamicObservations
from mcp_scanner.models.result import (
    ScanError,
    ScanOptionsSummary,
    ScanReport,
    ScanStatus,
    ServerResult,
    utc_now,
)
from mcp_scanner.models.server import ServerSpec, SetupPlan, TransportType
from mcp_scanner.models.severity import Severity
from mcp_scanner.risk.engine import score_findings
from mcp_scanner.rules.base import Rule
from mcp_scanner.rules.registry import RuleRegistry
from mcp_scanner.sandbox.canary import CanarySet
from mcp_scanner.sandbox.launcher import HostConfirm, HostPolicy
from mcp_scanner.scanner.context import ScanContext
from mcp_scanner.scanner.validate import validate_spec
from mcp_scanner.utils.secrets import is_key_name, mask_command_line, redact
from mcp_scanner.utils.timing import Deadline, stage_timer
from mcp_scanner.validators.finding_validator import FindingValidator

log = logging.getLogger(__name__)
# Errors in these stages do not make a scan "partial". They are noted only.
SOFT_STAGES = {"source", "dependencies", "pins", "config-check", "setup"}
# Given to a server for API keys the AI setup plan says it needs but you did not pass with --env.
PLACEHOLDER_KEY = "aevrin-placeholder-not-a-real-key"


class AIReviewer(Protocol):
    def review(self, result: ServerResult) -> AIReview: ...


@dataclass
class ScanRequest:
    target: TargetRequest = field(default_factory=TargetRequest)
    rules_dirs: list[str] = field(default_factory=list)
    host_confirm: HostConfirm | None = None
    use_pins: bool = True
    update_pins: bool = False
    progress: Callable[[str], None] | None = None


@dataclass
class CollectedServer:
    spec: ServerSpec
    inventory: ServerInventory = field(default_factory=ServerInventory)
    observations: DynamicObservations = field(default_factory=DynamicObservations)
    errors: list[ScanError] = field(default_factory=list)
    stage_seconds: dict[str, float] = field(default_factory=dict)
    connected: bool = False
    got_inventory: bool = False
    connect_skipped: bool = False
    source_root: Path | None = None
    source: SourceFacts | None = None
    started: float = field(default_factory=time.perf_counter)
    network_on: bool = False  # the run container had the network
    # With --network auto: an AI plan that only advises (network, key names). Automatic setup still starts it.
    advice: SetupPlan | None = None
    notes: list[str] = field(default_factory=list)  # extra notes for the risk summary


class ScanEngine:
    def __init__(
        self,
        settings: Settings,
        registry: RuleRegistry | None = None,
        ai_reviewer: AIReviewer | None = None,
        setup_planner: SetupPlanner | None = None,
    ) -> None:
        self.settings = settings
        self._registry = registry
        self.ai_reviewer = ai_reviewer
        self.setup_planner = setup_planner if settings.ai.setup != "never" else None

    def registry(self, extra_dirs: list[str] | None = None) -> RuleRegistry:
        if self._registry is None:
            self._registry = RuleRegistry.load(self.settings.rules, extra_dirs or [])
        return self._registry

    # ---- public entry points ------------------------------------------------

    def run(self, request: ScanRequest) -> ScanReport:
        """Resolve targets and scan them. Raises TargetError when nothing can be scanned."""
        request.target.ai_setup = self.setup_planner is not None
        specs = resolve_targets(request.target, self.settings)
        return self.scan_specs(specs, request)

    def scan_specs(self, specs: list[ServerSpec], request: ScanRequest) -> ScanReport:
        report = ScanReport(
            scanner_version=__version__, scan_id=uuid.uuid4().hex[:12], options=self._options(), product=product_info()
        )
        start = time.perf_counter()
        rules = self.registry(request.rules_dirs).select(self.settings.rules.enabled, self.settings.rules.disabled)
        pins = self._pin_store(report) if request.use_pins else None
        collected = []
        for spec in specs:
            self._say(request, f"Scanning {spec.name} ({spec.transport.value}) ...")
            collected.append(self._collect(spec, request, pins))
        for item in collected:
            peers = {t.name: other.spec.name for other in collected if other is not item for t in other.inventory.tools}
            result = self._analyze(item, peers, rules)
            if self.settings.scan.prescanned_fallback and (
                result.status != ScanStatus.COMPLETED or not result.inventory.tools
            ):
                self._add_prescanned(item.spec, result)
            if self.ai_reviewer is not None and self.settings.ai.enabled:
                self._say(request, f"AI review of {item.spec.name} ...")
                with stage_timer(result.stage_seconds, "ai"):
                    result.ai = self.ai_reviewer.review(result)
                report.ai_usage.add(result.ai.usage)
                report.ai_usage.provider = result.ai.provider or report.ai_usage.provider
                report.ai_usage.model = result.ai.model or report.ai_usage.model
            result.duration_seconds = round(time.perf_counter() - item.started, 3)
            report.servers.append(result)
        planner = self.setup_planner
        if planner is not None and planner.usage.calls:
            report.ai_usage.add(planner.usage)
            report.ai_usage.provider = report.ai_usage.provider or planner.usage.provider
            report.ai_usage.model = report.ai_usage.model or planner.usage.model
        if pins is not None:
            try:
                pins.save()
            except OSError as exc:
                report.errors.append(
                    ScanError(stage="pins", message=f"Could not save tool pins: {exc.strerror or exc}")
                )
        report.finished_at = utc_now()
        report.duration_seconds = round(time.perf_counter() - start, 3)
        return report

    # ---- stage 1: collect ---------------------------------------------------

    def _collect(self, spec: ServerSpec, request: ScanRequest, pins: PinStore | None) -> CollectedServer:
        item = CollectedServer(spec=spec)
        # Source facts come first: dynamic analysis must not call tools whose code is dangerous.
        item.source_root = find_source_root(spec)
        if item.source_root is not None:
            with stage_timer(item.stage_seconds, "source"):
                item.source = analyze_source(item.source_root, repo_root(spec))
        problems = validate_spec(spec, self.settings)
        if not self.settings.scan.connect and spec.transport != TransportType.OFFLINE:
            # Nothing will run, so a missing command is worth a note, not a failed scan.
            item.connect_skipped = True
            item.errors += [ScanError(stage="config-check", message=p) for p in problems]
        elif problems:
            item.errors += [ScanError(stage="validate", message=p, fatal=True) for p in problems]
        elif spec.transport == TransportType.OFFLINE:
            self._collect_offline(item)
        else:
            self._collect_live(item, request)
        if pins is not None and item.inventory.tools:
            self._check_pins(item, pins, request)
        return item

    def _collect_offline(self, item: CollectedServer) -> None:
        with stage_timer(item.stage_seconds, "inventory"):
            try:
                item.inventory = load_offline_inventory(item.spec.tools_file or "")
                item.got_inventory = True
            except ScannerError as exc:
                item.errors.append(ScanError(stage="inventory", message=str(exc), fatal=True))

    def _collect_live(self, item: CollectedServer, request: ScanRequest) -> None:
        automatic = spec = item.spec
        planner = self.setup_planner if spec.repo is not None else None
        use = self._plan_first(spec) if planner is not None else None
        if planner is not None and use == "plan":
            planned = self._with_plan(item, request, planner, spec, failure=None)
            if planned is None and not (spec.repo and spec.repo.entry):
                return  # no plan and nothing found automatically: nothing to start
            spec = planned or spec
        elif planner is not None and use == "advice":
            # Automatic setup found a start command, so it still installs and starts the server.
            # The plan only says if the server needs the internet and which keys it expects.
            advised = self._with_plan(item, request, planner, spec, failure=None, advice=True)
            if advised is not None and advised.repo is not None:
                item.advice = advised.repo.setup
                automatic = spec = spec.model_copy(update={"env": advised.env})
        tried_automatic = spec.repo is None or spec.repo.setup is None
        failure = self._attempt_live(item, request, spec)
        if failure and planner is not None and spec.repo is not None and planner.unavailable_reason is None:
            # Automatic setup (or the first plan) did not start the server. Ask the AI once
            # more, with the error, before giving up.
            if spec.repo.setup is not None and spec.repo.setup.source == "cache":
                planner.forget(spec.repo)
            retry = self._with_plan(item, request, planner, spec, failure=failure)
            if retry is not None:
                first = "the AI setup plan" if spec.repo.setup else "automatic setup"
                self._restart(item, f"Starting with {first} failed, so the AI planned again: {_first_line(failure)}")
                spec = retry
                failure = self._attempt_live(item, request, spec)
        if failure and not tried_automatic and automatic.repo is not None and automatic.repo.entry:
            # The AI plans did not work, but automatic setup found a start command. Use that.
            self._restart(item, f"The AI setup plan failed, so automatic setup was used: {_first_line(failure)}")
            if PLACEHOLDER_KEY not in automatic.env.values():
                item.notes = [n for n in item.notes if not n.startswith("The server expects")]
            spec = automatic
            self._attempt_live(item, request, spec)
        if item.got_inventory and planner is not None and spec.repo is not None and spec.repo.setup is not None:
            planner.remember(spec.repo, spec.repo.setup)
        item.spec = spec
        if not item.got_inventory and spec.repo is not None:
            self._static_fallback(item)

    def _static_fallback(self, item: CollectedServer) -> None:
        """The server did not start. Read its tools without running it, so the tool rules still run."""
        repo = item.spec.repo
        assert repo is not None
        repo_dir = Path(repo.local_dir)
        source = Path(item.spec.source_path) if item.spec.source_path else repo_dir
        try:
            tools_file, _, found_by = write_static_inventory(source if source.exists() else repo_dir, repo_dir)
            inventory = load_offline_inventory(tools_file)
        except (ScannerError, OSError) as exc:
            log.debug("Static fallback failed: %s", exc)
            return
        if not inventory.tools:
            return
        item.inventory, item.got_inventory = inventory, True
        # The start error stays in the report. The scan is now partial instead of failed.
        item.errors = [e.model_copy(update={"fatal": False}) for e in item.errors]
        item.notes.append(
            f"The server did not start, so its {len(inventory.tools)} tools were read from {found_by} instead. "
            "Runtime checks did not run."
        )

    def _add_prescanned(self, spec: ServerSpec, result: ServerResult) -> None:
        """This scan could not finish. Show a public report from an earlier scan, apart from the result."""
        report = prescanned.lookup(spec, self.settings.scan)
        if report is None:
            return  # nothing found: the real errors above stay the answer
        result.prescanned = report
        when = f" on {report.scanned_at}" if report.scanned_at else ""
        version = f" (version {report.version})" if report.version else ""
        result.risk.notes.append(
            f"This scan did not finish. A public report from an earlier scan of this server{version}{when} is "
            "shown below for reference. It was not made by this scan and is not part of this score."
        )

    @staticmethod
    def _restart(item: CollectedServer, note: str) -> None:
        """Forget a failed start before the next try. Its fatal errors become one setup note."""
        item.errors = [e for e in item.errors if not e.fatal] + [ScanError(stage="setup", message=note)]
        item.observations, item.inventory, item.connected = DynamicObservations(), ServerInventory(), False

    def _plan_first(self, spec: ServerSpec) -> Literal["plan", "advice"] | None:
        """Ask the AI before the first start: "plan" to start the server its way, "advice" only to
        learn whether it needs the internet. None: ask only after automatic setup fails."""
        repo = spec.repo
        if repo is None or not spec.is_local_process or repo.setup is not None:
            return None
        if self.settings.ai.setup == "always" or not repo.entry:
            return "plan"
        return "advice" if self.settings.sandbox.network == "auto" else None

    def _with_plan(
        self,
        item: CollectedServer,
        request: ScanRequest,
        planner: SetupPlanner,
        spec: ServerSpec,
        failure: str | None,
        advice: bool = False,
    ) -> ServerSpec | None:
        """A copy of the spec that starts the way an AI setup plan says. None when no plan was made."""
        repo = spec.repo
        assert repo is not None
        plan: SetupPlan | None = None if failure else planner.cached(repo)
        if plan is None:
            if failure:
                doing = f"{spec.name} did not start, planning again with the error"
            elif advice:
                doing = f"checking if {spec.name} needs the internet or API keys"
            else:
                doing = f"working out how to start {spec.name}"
            self._say(request, f"AI setup: {doing} ...")
            try:
                with stage_timer(item.stage_seconds, "setup"):
                    try:
                        plan = planner.plan(repo, failure=failure, previous=repo.setup)
                    except PlanError as rejected:
                        # The plan broke a rule (for example it started the published package).
                        # Tell the AI why, once, so it can fix the plan.
                        reason = f"Your last plan was rejected: {rejected}"
                        plan = planner.plan(repo, failure=f"{reason}\n{failure}" if failure else reason)
            except (AIProviderError, PlanError) as exc:
                # A server with no start command cannot run without a plan. Otherwise the
                # error from automatic setup stays the main error, and this is only a note.
                fatal = not repo.entry and failure is None
                item.errors.append(ScanError(stage="connect" if fatal else "setup", message=str(exc), fatal=fatal))
                return None
        env = dict(spec.env)
        missing = [name for name in plan.required_env if name not in env]
        for name in missing:
            env[name] = PLACEHOLDER_KEY
        item.notes = [n for n in item.notes if not n.startswith("The server expects")]
        if missing:
            item.notes.append(
                f"The server expects {', '.join(missing)}. The scan gave it placeholder values, so tools that "
                "need them can fail. Pass real keys with --env NAME=value to test those tools."
            )
        return spec.model_copy(
            update={
                "repo": repo.model_copy(update={"setup": plan, "kind": plan.kind}),
                "command": "python" if plan.kind == "python" else "node",
                "args": [],
                "env": env,
            }
        )

    def _run_settings(self, item: CollectedServer, spec: ServerSpec) -> Settings:
        """The settings for one server. Here `--network auto` becomes on or off."""
        if self.settings.sandbox.network != "auto":
            item.network_on = self.settings.sandbox.network == "allow"
            return self.settings
        plan = (spec.repo.setup if spec.repo is not None else None) or item.advice
        if plan is not None:
            item.network_on = plan.needs_network
            why = (
                "the AI setup plan says its tools call an online service"
                if plan.needs_network
                else "the AI setup plan says it works offline"
            )
        else:
            item.network_on = bool(item.source and item.source.hits_for(f.NETWORK))
            why = f"its source code {'makes' if item.network_on else 'makes no'} network calls"
        item.notes = [n for n in item.notes if not n.startswith("--network auto")]
        item.notes.append(f"--network auto: the network was {'on' if item.network_on else 'off'}, because {why}.")
        settings = self.settings.model_copy(deep=True)
        settings.sandbox.network = "allow" if item.network_on else "none"
        return settings

    def _attempt_live(self, item: CollectedServer, request: ScanRequest, spec: ServerSpec) -> str | None:
        """Start the server and collect from it. Returns a failure text when it did not start."""
        settings = self._run_settings(item, spec)
        failure: str | None = None
        deadline = Deadline(settings.timeouts.server_total)
        canary = CanarySet()
        policy = HostPolicy(allow_host=settings.sandbox.allow_host, confirm=request.host_confirm)
        connection: Connection | None = None
        server: MCPServer | None = None
        stage = "connect"
        try:
            server = MCPServer(spec, settings, policy, canary)
            with stage_timer(item.stage_seconds, "session"), server.connect() as connection:
                item.connected = True
                stage = "inventory"
                with stage_timer(item.stage_seconds, "inventory"):
                    item.inventory, errors = collect_inventory(connection.session)
                item.got_inventory = True
                item.errors.extend(errors)
                if settings.dynamic.enabled:
                    stage = "dynamic"
                    self._say(request, f"Dynamic analysis of {item.spec.name} ...")
                    with stage_timer(item.stage_seconds, "dynamic"):
                        analyzer = DynamicAnalyzer(settings, deadline, unsafe_tools_from_source(item.source))
                        item.observations = analyzer.run(connection, item.inventory)
                        item.errors.extend(analyzer.errors)
                item.observations.protocol_events = list(connection.session.transport.events)
        except HostExecutionNotAllowed as exc:
            item.errors.append(ScanError(stage="sandbox", message=str(exc), fatal=True))
        except (ScannerError, MCPError, OSError) as exc:
            message = _short(exc) + network_hint(str(exc), settings)
            item.errors.append(ScanError(stage=stage, message=message, fatal=not item.got_inventory))
            if not item.got_inventory:
                failure = _short(exc)
                log = getattr(exc, "log", "")
                if log:
                    failure += "\nInstall output (last lines):\n" + mask_command_line(log[-6000:])
        finally:
            if connection is not None:
                item.observations.sandbox = connection.sandbox_observations
                if not item.observations.protocol_events:
                    item.observations.protocol_events = list(connection.session.transport.events)
            elif server is not None and server.last_observations is not None:
                # The server failed before the session was ready. Keep what the sandbox saw.
                item.observations.sandbox = server.last_observations
        if failure and item.observations.sandbox.stderr_tail:
            failure += "\nServer output:\n" + item.observations.sandbox.stderr_tail[-3000:]
        if spec.is_local_process:
            item.observations.canary_values = canary.secret_values()
            for location in canary_locations(
                item.observations.canary_values, item.inventory, item.observations.tool_calls
            ):
                if location not in item.observations.canary_hits:
                    item.observations.canary_hits.append(location)
        return failure

    def _check_pins(self, item: CollectedServer, pins: PinStore, request: ScanRequest) -> None:
        item.observations.tool_changes.extend(pins.check(item.spec, item.inventory.tools))
        if self._status(item.errors, item.got_inventory) == ScanStatus.COMPLETED:
            pins.record(item.spec, item.inventory.tools, overwrite=request.update_pins)

    # ---- stage 2: analyze ---------------------------------------------------

    def _analyze(self, item: CollectedServer, peers: dict[str, str], rules: list[Rule]) -> ServerResult:
        spec = item.spec
        times = item.stage_seconds
        errors = list(item.errors)
        source, source_root = item.source, item.source_root
        if source is not None:
            errors += [ScanError(stage="source", message=e) for e in source.errors[:20]]
        with stage_timer(times, "dependencies"):
            deps = analyze_dependencies(spec, source_root, repo_root(spec))
        errors += [ScanError(stage="dependencies", message=e) for e in deps.errors]
        ctx = ScanContext(
            spec=spec,
            inventory=item.inventory,
            settings=self.settings,
            observations=item.observations,
            source=source,
            dependencies=deps,
            peer_tools=peers,
            connected=item.connected,
        )
        with stage_timer(times, "rules"):
            run = self.registry().run(ctx, rules, self.settings.rules)
        errors += run.errors
        # Rules saw the raw text. The report gets a scrubbed copy without secrets or canaries.
        scrub_runtime_text(item.inventory, item.observations)
        with stage_timer(times, "validate"):
            findings = FindingValidator(self.settings.suppressions).validate(spec.name, run.candidates)
        minimum = self.settings.scan.min_severity
        findings = [f for f in findings if f.severity.at_least(minimum)]
        status = self._status(errors, item.got_inventory or item.connect_skipped)
        risk = score_findings(findings, status)
        if item.connect_skipped:
            risk.notes.append(
                "The server was not started (--no-connect). Only config, source, and dependency checks ran."
            )
        risk.notes += item.notes
        if source is not None and spec.is_local_process:
            # Keys the code reads by name that you did not pass (placeholders are noted above).
            unset = [name for name in source.env_reads if is_key_name(name) and name not in spec.env]
            if unset:
                risk.notes.append(
                    f"The code reads these keys from its environment: {', '.join(unset[:6])}. They were not "
                    "passed, so tools that need them can fail. Pass them with --env NAME=value to test those tools."
                )
        if source is not None and source.minified_files:
            shown = ", ".join(source.minified_files[:3])
            risk.notes.append(
                f"Minified code or very long lines in {len(source.minified_files)} file(s) were only checked for "
                f"secrets, not for code patterns ({shown})."
            )
        offline = offline_tool_failures(item.observations, item.network_on)
        if offline:
            risk.notes.append(
                f"{len(offline)} tool call(s) failed only because the sandbox has no internet ({', '.join(offline[:5])}). "
                "To test them, rerun with --network allow (or --network auto) and give the server its API key "
                "with --env NAME=value."
            )
        timed_out = [c.tool for c in item.observations.tool_calls if c.timed_out]
        if timed_out:
            risk.notes.append(
                f"{len(timed_out)} tool call(s) timed out ({', '.join(timed_out[:5])}). The server likely waits for "
                "an app or service that is not in the sandbox, so the remaining calls were skipped."
            )
        if spec.repo is not None and spec.transport == TransportType.OFFLINE:
            hint = f" The repository says to start it with: {spec.repo.launch_hint}." if spec.repo.launch_hint else ""
            risk.notes.append(
                "Tools were read from the source code. Nothing from the repository was run, so runtime "
                f"checks did not happen. Add --run to install and start it in the Docker sandbox.{hint}"
            )
        return ServerResult(
            server=spec.public_summary(),
            status=status,
            inventory=item.inventory,
            findings=findings,
            risk=risk,
            errors=errors,
            rules_run=run.rules_run,
            observations=item.observations,
            stage_seconds=times,
        )

    @staticmethod
    def _status(errors: list[ScanError], got_inventory: bool) -> ScanStatus:
        if not got_inventory:
            return ScanStatus.FAILED
        if any(e.stage not in SOFT_STAGES for e in errors):
            return ScanStatus.PARTIAL
        return ScanStatus.COMPLETED

    # ---- helpers ------------------------------------------------------------

    def _pin_store(self, report: ScanReport) -> PinStore | None:
        try:
            return PinStore(self.settings.scan.pins_file)
        except OSError as exc:
            report.errors.append(ScanError(stage="pins", message=f"Could not open the pin file: {exc}"))
            return None

    def _options(self) -> ScanOptionsSummary:
        s = self.settings
        return ScanOptionsSummary(
            dynamic=s.dynamic.enabled,
            sandbox_mode=s.sandbox.mode,
            ai_enabled=s.ai.enabled,
            ai_provider=s.ai.provider if s.ai.enabled else None,
            ai_model=s.ai.model if s.ai.enabled else None,
            min_severity=s.scan.min_severity.value,
            rules_selected=s.rules.enabled,
            source_path=s.scan.source_path,
        )

    @staticmethod
    def _say(request: ScanRequest, message: str) -> None:
        if request.progress:
            request.progress(message)
        log.info(message)


UNSAFE_CODE = {
    f.COMMAND: "runs system commands",
    f.CODE_EVAL: "runs dynamic code",
    f.OBFUSCATED_EXEC: "runs hidden code",
    f.FILE_WRITE: "writes files",
    f.NETWORK: "makes network requests",
    f.DESERIALIZATION: "loads unsafe data formats",
    f.REVERSE_SHELL: "opens a reverse shell",
}


def repo_root(spec: ServerSpec) -> Path | None:
    return Path(spec.repo.local_dir) if spec.repo and spec.repo.local_dir else None


def scrub_runtime_text(inventory: ServerInventory, observations: DynamicObservations) -> None:
    """Remove secrets and planted canary values from text the server returned at run time."""
    canaries = [v for v in observations.canary_values if v]

    def scrub(text: str | None) -> str | None:
        if not text:
            return text
        for value in canaries:
            text = text.replace(value, "[canary secret]")
        return redact(text)

    for call in observations.tool_calls:
        call.output_text = scrub(call.output_text) or ""
        call.error = scrub(call.error)
    for prompt in inventory.prompts:
        prompt.rendered_text = scrub(prompt.rendered_text)
    for resource in inventory.resources:
        resource.text = scrub(resource.text)
    # Child process command lines and server output can carry keys (for example --api-key VALUE).
    for process in observations.sandbox.child_processes:
        process.cmdline = mask_command_line(process.cmdline)
    observations.sandbox.stderr_tail = mask_command_line(observations.sandbox.stderr_tail)
    observations.changed_tool_definitions = [
        json.loads(scrub(json.dumps(d)) or "{}") for d in observations.changed_tool_definitions
    ]


def unsafe_tools_from_source(source: SourceFacts | None) -> dict[str, str]:
    """Tools whose code does something dangerous, so dynamic analysis will not call them."""
    unsafe: dict[str, str] = {}
    for hit in source.hits if source else []:
        if hit.tool and hit.category in UNSAFE_CODE and hit.tool not in unsafe:
            unsafe[hit.tool] = UNSAFE_CODE[hit.category]
    return unsafe


_DNS_ERRORS = ("EAI_AGAIN", "ENOTFOUND", "getaddrinfo", "Could not resolve", "Temporary failure in name resolution")


def network_hint(message: str, settings: Settings) -> str:
    """A next step for common start failures."""
    if "No answer to 'initialize'" in message:
        return (
            " Hint: the program started but never answered the MCP handshake. It may be a helper rather than "
            "an MCP server, it may wait for a desktop app or an account, or it may need a longer --startup-timeout."
        )
    sandbox = settings.sandbox
    if sandbox.mode == "process" or sandbox.network == "allow":
        return ""
    if any(word in message for word in _DNS_ERRORS):
        return (
            " Hint: the server tried to reach the internet while starting, and the Docker sandbox has no network. "
            "Add --network allow (or --network auto with an AI provider) if it needs an online service."
        )
    return ""


# Tool results that only mean "this sandbox is offline", not "this tool is broken".
_OFFLINE_ERRORS = re.compile(
    r"fetch failed|ENOTFOUND|EAI_AGAIN|getaddrinfo|Name or service not known|Temporary failure in name resolution|"
    r"Network is unreachable|Failed to establish a new connection|ConnectError|Could not resolve host",
    re.IGNORECASE,
)


def offline_tool_failures(observations: DynamicObservations, network_on: bool) -> list[str]:
    """Tools whose calls failed only because the sandbox had no internet."""
    if network_on or observations.sandbox.sandbox_mode != "docker":
        return []
    return [
        call.tool
        for call in observations.tool_calls
        if _OFFLINE_ERRORS.search(f"{call.output_text} {call.error or ''}")
    ]


def _first_line(text: str) -> str:
    return text.splitlines()[0][:300] if text else ""


def _short(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    # Errors can quote server output or a command line, so keys are masked here too.
    return mask_command_line(text)[:600]


def exit_code(report: ScanReport, fail_on: Severity | None) -> int:
    """0 clean, 1 findings at or above fail_on, 2 scan error."""
    if report.status == ScanStatus.FAILED:
        return 2
    worst = report.worst_severity()
    if fail_on is not None and worst is not None and worst.at_least(fail_on):
        return 1
    if report.status == ScanStatus.PARTIAL:
        return 2
    return 0


def report_path(directory: str | None, scan_id: str, ext: str) -> Path:
    base = Path(directory or ".").expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return base / f"mcp-scan-{scan_id}.{ext}"
