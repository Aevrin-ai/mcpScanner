# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Choose a sandbox and start a local MCP server in it."""

from __future__ import annotations

import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from mcp_scanner.config.settings import SandboxSettings
from mcp_scanner.core.errors import HostExecutionNotAllowed, SandboxError
from mcp_scanner.models.server import ServerSpec
from mcp_scanner.sandbox import docker, prepare
from mcp_scanner.sandbox.canary import CanarySet
from mcp_scanner.sandbox.environment import build_server_env, scanner_cache_dir
from mcp_scanner.sandbox.process import ProcessLimits, SandboxedProcess
from mcp_scanner.sandbox.workspace import Workspace

log = logging.getLogger(__name__)

# Asked before a server runs directly on this machine. Returns True to allow.
HostConfirm = Callable[[ServerSpec], bool]


@dataclass
class HostPolicy:
    """Decides if a server may run on this machine without Docker."""

    allow_host: bool = False
    confirm: HostConfirm | None = None

    def check(self, spec: ServerSpec) -> None:
        if self.allow_host:
            return
        if self.confirm is not None and self.confirm(spec):
            return
        raise HostExecutionNotAllowed(
            f"Server '{spec.name}' would run on this machine without Docker. "
            "Start Docker, or pass --allow-host if you trust this server."
        )


def resolve_mode(spec: ServerSpec, settings: SandboxSettings) -> str:
    """Pick 'docker' or 'process' for this server."""
    command = spec.command or ""
    if settings.mode == "docker":
        if not docker.docker_available():
            raise SandboxError("Sandbox mode is 'docker' but Docker is not running")
        if not docker.supports_command(command, settings):
            raise SandboxError(f"The Docker sandbox cannot run '{command}'. Set sandbox.docker_image.")
        return "docker"
    if settings.mode == "process":
        return "process"
    if docker.supports_command(command, settings) and docker.docker_available():
        return "docker"
    return "process"


def absolutize_args(args: list[str], base: Path) -> list[str]:
    """Make relative file paths absolute, because the server runs in a different folder."""
    result = []
    for arg in args:
        if arg.startswith("-") or Path(arg).is_absolute():
            result.append(arg)
            continue
        candidate = base / arg
        result.append(str(candidate.resolve()) if candidate.exists() else arg)
    return result


def launch(
    spec: ServerSpec,
    settings: SandboxSettings,
    workspace: Workspace,
    canary: CanarySet,
    host_policy: HostPolicy,
    install_timeout: float = 600.0,
) -> SandboxedProcess:
    """Start the server. The caller must call stop() on the result."""
    if not spec.command:
        raise SandboxError(f"Server '{spec.name}' has no command")
    mode = resolve_mode(spec, settings)
    if spec.repo is not None and mode != "docker":
        # Installing a repository runs its build and install scripts. That only happens in Docker.
        raise SandboxError(
            "Starting a server from a repository (--run) needs the Docker sandbox. "
            "Start Docker, or scan without --run to check the code without running it."
        )
    limits = ProcessLimits(
        memory_mb=settings.memory_mb,
        max_processes=settings.max_processes,
        cpu_seconds=settings.cpu_seconds,
        max_line_bytes=settings.max_message_mb * 1024 * 1024,
    )
    base_dir = Path(spec.cwd).expanduser() if spec.cwd else Path.cwd()
    args = absolutize_args(spec.args, base_dir)
    if mode == "docker":
        return _launch_docker(spec, args, settings, workspace, canary, limits, install_timeout)
    host_policy.check(spec)
    return _launch_process(spec, args, settings, workspace, canary, limits)


def _launch_process(
    spec: ServerSpec,
    args: list[str],
    settings: SandboxSettings,
    workspace: Workspace,
    canary: CanarySet,
    limits: ProcessLimits,
) -> SandboxedProcess:
    env = build_server_env(spec.env, settings, workspace, canary)
    exe = shutil.which(spec.command or "", path=env.get("PATH"))
    if exe is None:
        raise SandboxError(f"Command not found: '{spec.command}'. Is it installed and on PATH?")
    cwd = str(Path(spec.cwd).expanduser()) if spec.cwd else str(workspace.work)
    log.info("Starting server %s in process sandbox", spec.name)
    proc = SandboxedProcess([exe, *args], env, cwd, limits, sandbox_mode="process")
    proc.observations.limits_note = (
        "Process sandbox: clean environment, fake home folder, time, memory and process limits. "
        "It is not a security boundary."
    )
    return proc


def _prepared_plan(
    spec: ServerSpec,
    prep: prepare.Preparation,
    server_env: dict[str, str],
    settings: SandboxSettings,
    workspace: Workspace,
    install_timeout: float,
) -> tuple[docker.DockerPlan, str]:
    """Install first (network on, no secrets), then plan the locked run container.

    Returns the plan and the name of the Docker volume that holds the install.
    The caller removes the volume when the server stops.
    """
    repo_mount = [f"{prep.mount_repo}:{prepare.SRC}:ro"] if prep.mount_repo else []
    docker.ensure_image(prep.image)
    if prep.install_image:
        docker.ensure_image(prep.install_image)
    volume = docker.create_volume(prep.image)
    try:
        plan = _install_and_plan(spec, prep, server_env, settings, workspace, install_timeout, volume, repo_mount)
    except BaseException:
        docker.remove_volume(volume)
        raise
    return plan, volume


def _install_and_plan(
    spec: ServerSpec,
    prep: prepare.Preparation,
    server_env: dict[str, str],
    settings: SandboxSettings,
    workspace: Workspace,
    install_timeout: float,
    volume: str,
    repo_mount: list[str],
) -> docker.DockerPlan:
    log.info("Installing server %s: %s", spec.name, prep.summary)
    # A shared npm download cache, mounted only into the install container. npm checks every
    # package against its sha512 integrity hash when it reads the cache, so a hostile install
    # cannot plant a changed package for later scans. (uv does not check this way, so no uv cache.)
    npm_cache = scanner_cache_dir() / "docker-npm"
    npm_cache.mkdir(parents=True, exist_ok=True)
    npm_cache.chmod(0o777)  # the container runs as an unprivileged user
    mounts = [f"{volume}:{prepare.DEPS}:rw", f"{npm_cache}:{prepare.NPM_CACHE}:rw", *repo_mount]
    # No canary or server env here: install scripts get nothing worth stealing.
    output = docker.run_install(
        prep.install_image or prep.image,
        prep.script,
        settings,
        workspace,
        mounts,
        # pnpm keeps its own store. It checks file integrity before linking, like npm.
        {**prep.env, "npm_config_cache": prepare.NPM_CACHE, "npm_config_store_dir": f"{prepare.NPM_CACHE}/pnpm-store"},
        install_timeout,
    )
    command, args = prep.finish(output)
    return docker.build_docker_plan(
        command,
        args,
        {**server_env, **prep.env},
        settings,
        workspace,
        image=prep.image,
        prepared=True,
        extra_mounts=[f"{volume}:{prepare.DEPS}:{'rw' if prep.writable else 'ro'}", *repo_mount],
        workdir=prep.workdir,
    )


def _launch_docker(
    spec: ServerSpec,
    args: list[str],
    settings: SandboxSettings,
    workspace: Workspace,
    canary: CanarySet,
    limits: ProcessLimits,
    install_timeout: float = 600.0,
) -> SandboxedProcess:
    from mcp_scanner.config.expand import expand_mapping
    from mcp_scanner.sandbox.canary import CANARY_ENV_NAME

    server_env = {CANARY_ENV_NAME: canary.env_value, **expand_mapping(spec.env)}
    prep = prepare.plan(spec, args, settings)
    volume: str | None = None
    if prep is not None:
        plan, volume = _prepared_plan(spec, prep, server_env, settings, workspace, install_timeout)
    else:
        if spec.repo is not None:
            raise SandboxError(f"Could not work out how to install {spec.repo.url}")
        plan = docker.build_docker_plan(spec.command or "", args, server_env, settings, workspace)
        docker.ensure_image(plan.image)
    log.info("Starting server %s in Docker sandbox (%s)", spec.name, plan.container_name)
    # The watchdog cannot see inside the container, so Docker enforces the limits.
    limits.watch_network = False

    def cleanup() -> None:
        docker.remove_container(plan.container_name)
        if volume:
            docker.remove_volume(volume)

    try:
        proc = SandboxedProcess(
            plan.argv,
            plan.cli_env,
            str(workspace.work),
            limits,
            sandbox_mode="docker",
            watch_tree=False,
            on_stop=cleanup,
        )
    except BaseException:
        # Any failure while starting, also Ctrl+C, must not leave the container or the volume behind.
        cleanup()
        raise
    network = "network allowed" if settings.network == "allow" else "no network"
    proc.observations.limits_note = (
        f"Docker sandbox: {network}, read only image, no capabilities, non-root user, "
        f"{settings.memory_mb} MB memory, {settings.max_processes} processes."
    )
    return proc
