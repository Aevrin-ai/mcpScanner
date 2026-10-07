# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Run a local MCP server inside a locked Docker container.

The container gets:
  --network none        no network (unless you allow it)
  --read-only           the image files cannot be changed
  --cap-drop ALL        no special Linux powers
  --security-opt no-new-privileges
  --pids-limit, --memory, --cpus
  --user 65534          a nobody user, not root
  a fake home folder from our workspace (with decoy secrets), and a temp folder

Local files named in the command (like a server script) are mounted read only.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath

from mcp_scanner.config.settings import SandboxSettings
from mcp_scanner.core.errors import SandboxError
from mcp_scanner.sandbox.workspace import Workspace

log = logging.getLogger(__name__)

_NODE_COMMANDS = {"node", "npx", "npm", "pnpm", "yarn", "bun", "bunx"}
_PYTHON_COMMANDS = {"python", "python3", "uv", "uvx", "pip", "pipx"}
CONTAINER_HOME = "/home/sandbox"
CONTAINER_TMP = "/tmp"


_DOCKER_SEEN = False


def docker_available() -> bool:
    """True when the docker command exists and the daemon answers.

    Docker Desktop can sleep ("Resource Saver") and take many seconds to wake up, so we
    wait up to 30 seconds. Only a yes is remembered: a no is checked again next time,
    so a slow first answer never silently moves every server to the process sandbox.
    """
    global _DOCKER_SEEN
    if _DOCKER_SEEN:
        return True
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        result = subprocess.run(
            [exe, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    _DOCKER_SEEN = result.returncode == 0 and bool(result.stdout.strip())
    return _DOCKER_SEEN


def command_basename(command: str) -> str:
    name = Path(command).name.lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def pick_image(command: str, settings: SandboxSettings) -> str | None:
    if settings.docker_image:
        return settings.docker_image
    base = command_basename(command)
    if base in _NODE_COMMANDS:
        return settings.docker_image_node
    if base in _PYTHON_COMMANDS:
        return settings.docker_image_python
    return None


def supports_command(command: str, settings: SandboxSettings) -> bool:
    return command_basename(command) != "docker" and pick_image(command, settings) is not None


@dataclass
class DockerPlan:
    argv: list[str]
    container_name: str
    cli_env: dict[str, str]
    mounts: list[str] = field(default_factory=list)
    image: str = ""


def build_docker_plan(
    command: str,
    args: list[str],
    server_env: dict[str, str],
    settings: SandboxSettings,
    workspace: Workspace,
    *,
    image: str | None = None,
    prepared: bool = False,
    extra_mounts: list[str] | None = None,
    workdir: str | None = None,
    network: str | None = None,
    interactive: bool = True,
) -> DockerPlan:
    """The docker run command for a server.

    With `prepared`, `command` and `args` are already paths inside the container
    (from the install step), so local paths are not rewritten.
    """
    image = image or pick_image(command, settings)
    if image is None:
        raise SandboxError(
            f"No Docker sandbox image is known for '{command}'. "
            "Set sandbox.docker_image, or use --sandbox process with --allow-host."
        )
    exe = shutil.which("docker")
    if not exe:
        raise SandboxError("Docker is not installed")
    name = "aevrin-scan-" + secrets.token_hex(6)
    mounts: list[str] = list(extra_mounts or [])
    new_args = list(args) if prepared else [_rewrite_path_arg(arg, i, mounts) for i, arg in enumerate(args)]
    # "auto" is settled per server before launch (scanner/engine.py). Anything but "allow" stays offline.
    net = network or ("bridge" if settings.network == "allow" else "none")
    argv = [
        exe,
        "run",
        "--rm",
        *(["-i"] if interactive else []),
        "--init",
        "--name",
        name,
        "--network",
        net,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(max(settings.max_processes, 8)),
        "--memory",
        f"{settings.memory_mb}m",
        "--cpus",
        "1",
        "--user",
        "65534:65534",
        "--workdir",
        workdir or CONTAINER_HOME,
        "-v",
        f"{workspace.home}:{CONTAINER_HOME}:rw",
        "-v",
        f"{workspace.tmp}:{CONTAINER_TMP}:rw",
    ]
    for mount in mounts:
        argv += ["-v", mount]
    container_env = {
        # Cache folders can be changed by the caller (the install step uses a shared npm cache).
        "npm_config_cache": f"{CONTAINER_HOME}/.npm",
        "UV_CACHE_DIR": f"{CONTAINER_HOME}/.cache/uv",
        "NO_UPDATE_NOTIFIER": "1",
        **{k: v for k, v in server_env.items() if k.upper() != "PATH" or prepared},
        "HOME": CONTAINER_HOME,
        "TMPDIR": CONTAINER_TMP,
    }
    # Pass env by name only. The values travel through the docker CLI's own
    # environment, so they never show up in the process list.
    for key in sorted(container_env):
        argv += ["-e", key]
    argv += [image, command if prepared else command_basename(command), *new_args]
    cli_env = _docker_cli_env()
    cli_env.update(container_env)
    # HOME now points into the container. Tell the docker CLI where its own config is.
    cli_env["DOCKER_CONFIG"] = os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))
    return DockerPlan(argv=argv, container_name=name, cli_env=cli_env, mounts=mounts, image=image)


def _rewrite_path_arg(arg: str, index: int, mounts: list[str]) -> str:
    """If an argument is a local file or folder, mount it read only and point to the mount."""
    if arg.startswith("-") or len(arg) < 2:
        return arg
    path = Path(arg).expanduser()
    try:
        exists = path.exists()
    except OSError:
        exists = False
    if not exists:
        return arg
    path = path.resolve()
    target_dir = PurePosixPath(f"/mnt/arg{index}")
    if path.is_dir():
        mounts.append(f"{path}:{target_dir}:ro")
        return str(target_dir)
    mounts.append(f"{path.parent}:{target_dir}:ro")
    return str(target_dir / path.name)


def _docker_cli_env() -> dict[str, str]:
    """The docker command itself needs a few host variables to find its config."""
    keep = (
        "PATH",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "ProgramFiles",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "TMP",
        "TEMP",
    )
    return {key: os.environ[key] for key in keep if key in os.environ}


def run_install(
    image: str,
    script: str,
    settings: SandboxSettings,
    workspace: Workspace,
    mounts: list[str],
    env: dict[str, str],
    timeout: float,
) -> str:
    """Run an install script in its own container, with the network on and no secrets.

    It can only write to the scan's workspace (home, tmp, and the deps folder in `mounts`).
    """
    # Package managers use many threads, and Docker counts threads as processes.
    memory = max(settings.memory_mb, settings.install_memory_mb)
    roomy = settings.model_copy(update={"max_processes": 512, "memory_mb": memory})
    # Big TypeScript builds run out of Node's default heap long before the container limit.
    env = {"NODE_OPTIONS": f"--max-old-space-size={memory * 3 // 4}", **env}
    plan = build_docker_plan(
        "sh",
        ["-c", script],
        dict(env),
        roomy,
        workspace,
        image=image,
        prepared=True,
        extra_mounts=mounts,
        network="bridge",
        interactive=False,
    )
    log.info("Installing server in Docker (%s)", plan.container_name)
    try:
        result = subprocess.run(plan.argv, env=plan.cli_env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        remove_container(plan.container_name)
        raise SandboxError(
            f"Installing the server took longer than {timeout:.0f}s. Raise timeouts.install if your connection is slow."
        ) from exc
    if result.returncode != 0:
        output = (
            result.stdout.decode("utf-8", errors="replace") + "\n" + result.stderr.decode("utf-8", errors="replace")
        )
        error = SandboxError("Installing the server failed: " + " | ".join(install_error_lines(output)))
        error.log = "\n".join(output.strip().splitlines()[-150:])  # the AI setup retry reads this
        raise error
    return result.stdout.decode("utf-8", errors="replace")


# Install output lines that say what went wrong (npm, pip, uv, tsc, node).
_ERROR_LINE = re.compile(
    r"\bERR!|\berror\b|\bError:|\bERR_[A-Z_]+|\bfailed\b|not found|cannot find|No such file|exit code|TS\d{4}:",
    re.IGNORECASE,
)


def install_error_lines(output: str, limit: int = 6) -> list[str]:
    """The lines that explain an install failure. Without any, the last lines."""
    lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
    errors = [line for line in lines if _ERROR_LINE.search(line)]
    chosen = (errors or lines)[-limit:]
    return [line[:200] for line in chosen]


def create_volume(image: str) -> str:
    """A fresh Docker volume for one scan's installed files, writable by the sandbox user.

    A volume is much faster than a folder shared from this machine. On Windows and macOS,
    npm writes thousands of small files, and a shared folder made that 10 times slower.
    """
    exe = shutil.which("docker")
    if not exe:
        raise SandboxError("Docker is not installed")
    remove_stale_volumes()
    name = VOLUME_PREFIX + secrets.token_hex(6)
    created = subprocess.run([exe, "volume", "create", name], capture_output=True, timeout=60, check=False)
    if created.returncode != 0:
        raise SandboxError("Could not create a Docker volume for the install step")
    # A new volume belongs to root. Hand it to the sandbox user. This tiny container may
    # only change file owners, nothing else.
    chown = [exe, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN",
             "--security-opt", "no-new-privileges", "--user", "0:0", "-v", f"{name}:/opt/deps",
             image, "chown", "65534:65534", "/opt/deps"]  # fmt: skip
    owned = subprocess.run(chown, capture_output=True, timeout=120, check=False)
    if owned.returncode != 0:
        remove_volume(name)
        raise SandboxError("Could not prepare the Docker volume for the install step")
    return name


VOLUME_PREFIX = "aevrin-deps-"
# A scan's volume older than this, with no container using it, was left by a scan that was killed.
STALE_VOLUME_SECONDS = 3600


def remove_stale_volumes(now: float | None = None) -> list[str]:
    """Remove install volumes that killed scans left behind. Volumes in use are never touched."""
    exe = shutil.which("docker")
    if not exe:
        return []
    try:
        listed = subprocess.run(
            [exe, "volume", "ls", "-q", "--filter", f"name={VOLUME_PREFIX}"],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
        names = [n for n in listed.stdout.split() if n.startswith(VOLUME_PREFIX)]
        if not names:
            return []
        inspected = subprocess.run(
            [exe, "volume", "inspect", "--format", "{{.Name}} {{.CreatedAt}}", *names],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return []
    removed = []
    current = now if now is not None else time.time()
    for line in inspected.stdout.splitlines():
        name, _, created = line.partition(" ")
        age = current - _docker_time(created)
        if age < STALE_VOLUME_SECONDS or _volume_in_use(exe, name):
            continue
        remove_volume(name)
        removed.append(name)
    return removed


def _docker_time(text: str) -> float:
    """Docker's "2026-10-06T10:05:37Z" (or with an offset) as a Unix time. Unknown means now."""
    try:
        return datetime.fromisoformat(text.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def _volume_in_use(exe: str, name: str) -> bool:
    try:
        users = subprocess.run(
            [exe, "ps", "-a", "-q", "--filter", f"volume={name}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return True  # when unsure, keep it
    return bool(users.stdout.strip()) or users.returncode != 0


def remove_volume(name: str) -> None:
    exe = shutil.which("docker")
    if not exe:
        return
    try:
        subprocess.run([exe, "volume", "rm", "-f", name], capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        log.warning("Could not remove Docker volume %s", name)


def with_tag(image: str) -> str:
    """'name' -> 'name:latest'. `docker run` assumes the latest tag, but on newer Docker
    versions `docker image inspect` does not, and reports a local image as missing."""
    last = image.rsplit("/", 1)[-1]
    return image if "@" in image or ":" in last else f"{image}:latest"


def image_exists(image: str) -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    found = subprocess.run([exe, "image", "inspect", with_tag(image)], capture_output=True, timeout=30, check=False)
    return found.returncode == 0


def ensure_image(image: str, timeout: float = 900.0) -> None:
    """Pull the sandbox image if it is missing.

    This runs before the server starts, so a slow first download never counts
    against the server's startup time limit.
    """
    exe = shutil.which("docker")
    if not exe:
        raise SandboxError("Docker is not installed")
    try:
        if image_exists(image):
            return
        log.warning("Pulling Docker sandbox image %s (first use, this can take a few minutes)", image)
        pulled = subprocess.run([exe, "pull", image], capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"Pulling Docker image '{image}' took longer than {timeout:.0f}s") from exc
    if pulled.returncode != 0:
        detail = pulled.stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["unknown error"]
        raise SandboxError(f"Could not pull Docker image '{image}': {detail[0][:200]}")


def remove_container(name: str) -> None:
    exe = shutil.which("docker")
    if not exe:
        return
    try:
        subprocess.run([exe, "rm", "-f", name], capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        log.warning("Could not remove container %s", name)
