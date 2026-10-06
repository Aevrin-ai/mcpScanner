# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Install a server before it starts, in a separate container (Docker sandbox only).

Why: `npx` and `uvx` download the server when it starts. That needs the network,
and on a slow connection it can take longer than the startup time limit. So we
split the work in two containers:

  1. install  network on, no secrets, no canaries, its own time limit.
              It writes only into a fresh folder (/opt/deps) of this scan's workspace.
  2. run      the normal locked container. /opt/deps is mounted read only, and the
              network is off unless you allowed it (--network allow).

The same two steps start servers from a repository (`--run`): the repository is
copied into /opt/deps/app, its dependencies are installed there, and the entry
file is started from there.

Package specs from the command line are passed to the shell with shlex.quote.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mcp_scanner.config.settings import SandboxSettings
from mcp_scanner.core.errors import SandboxError
from mcp_scanner.models.server import ServerSpec
from mcp_scanner.sandbox.docker import command_basename, pick_image

DEPS = "/opt/deps"
SRC = "/src"
NPM_CACHE = "/npm-cache"
MARK = "@@AEVRIN-INSTALL-REPORT@@"
# The usual PATH of the sandbox images, used when a run needs extra folders in front.
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
UVX_VALUE_FLAGS = {
    "--from",
    "--with",
    "--python",
    "-p",
    "--index-url",
    "--index",
    "--extra-index-url",
    "-i",
    "--with-requirements",
    "--constraint",
    "-c",
}
NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--registry", "--cache"}


@dataclass
class Preparation:
    image: str
    script: str  # shell script for the install container
    finish: Callable[[str], tuple[str, list[str]]]  # install output -> (command, args) inside the container
    workdir: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    mount_repo: str | None = None  # a repository folder to mount read only at /src
    # Repository servers often write logs or caches next to their own code. The install volume
    # belongs to this scan only and is deleted afterwards, so it may stay writable for them.
    writable: bool = False
    summary: str = ""
    # The image for the install container, when it differs from the run image (repositories).
    install_image: str | None = None


def plan(spec: ServerSpec, args: list[str], settings: SandboxSettings) -> Preparation | None:
    """A preparation for this server, or None when it can start as it is."""
    if spec.repo is not None and spec.repo.setup is not None:
        return _setup_plan(spec, settings)
    if spec.repo is not None and spec.repo.entry:
        return _repository(spec, settings)
    base = command_basename(spec.command or "")
    image = pick_image(spec.command or "", settings)
    if image is None:
        return None
    if base in ("npx", "bunx", "pnpx") or (base in ("pnpm", "yarn", "npm") and args[:1] in (["dlx"], ["exec"], ["x"])):
        return _npx(args[1:] if base in ("pnpm", "yarn", "npm") else args, image)
    if base == "uvx":
        return _uvx(args, image)
    if base == "pipx" and args[:1] == ["run"]:
        return _uvx(args[1:], image, pipx=True)
    return None


# ---- npx -----------------------------------------------------------------------


def split_npx(args: list[str]) -> tuple[list[str], str | None, list[str]] | None:
    """(packages to install, command name or None, arguments for the server)."""
    packages: list[str] = []
    rest = list(args)
    position = 0
    while position < len(rest):
        arg = rest[position]
        if arg in ("-p", "--package") and position + 1 < len(rest):
            packages.append(rest[position + 1])
            position += 2
        elif arg.startswith("--package="):
            packages.append(arg.split("=", 1)[1])
            position += 1
        elif arg in NPX_VALUE_FLAGS:
            return None  # an option we do not handle (for example -c "a script")
        elif arg.startswith("-"):
            position += 1  # -y, --yes, -q, --no-install, ...
        else:
            break
    if position >= len(rest):
        return None
    first, server_args = rest[position], rest[position + 1 :]
    if packages:
        return packages, first, server_args
    return [first], None, server_args


def package_name(spec: str) -> str:
    """'@scope/name@1.2.3' -> '@scope/name'."""
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def _npx(args: list[str], image: str) -> Preparation | None:
    parts = split_npx(args)
    if parts is None:
        return None
    packages, command_name, server_args = parts
    if any(p.startswith((".", "/", "file:")) for p in packages):
        return None  # a local path, nothing to download
    script = (
        f"mkdir -p {DEPS}/npx && cd {DEPS}/npx && "
        f"npm install --no-audit --no-fund --loglevel=error --prefix {DEPS}/npx "
        + " ".join(shlex.quote(p) for p in packages)
    )

    name = package_name(packages[0])
    # The container prints the package manifest, so we can find its program without
    # reading the install volume from this machine.
    script += f" && echo {MARK} && cat {DEPS}/npx/node_modules/{shlex.quote(name)}/package.json"

    def finish(output: str) -> tuple[str, list[str]]:
        try:
            doc = json.loads(report(output))
        except json.JSONDecodeError as exc:
            raise SandboxError("The installed package has no readable package.json") from exc
        bin_path = node_bin(doc, command_name or name.split("/")[-1])
        return "node", [f"{DEPS}/npx/node_modules/{name}/{bin_path}", *server_args]

    return Preparation(image=image, script=script, finish=finish, summary=f"npm install {' '.join(packages)}")


def report(output: str) -> str:
    """The part of the install output after the report marker."""
    if MARK not in output:
        raise SandboxError("The install step did not finish its report")
    return output.rsplit(MARK, 1)[1].strip()


def node_bin(doc: dict, wanted: str) -> str:
    """The program a package runs, as a path inside the package."""
    bins = doc.get("bin")
    if isinstance(bins, str):
        return bins.removeprefix("./")
    if isinstance(bins, dict) and bins:
        chosen = bins.get(wanted) or (next(iter(bins.values())) if len(bins) == 1 else None)
        if chosen is None:
            raise SandboxError(f"The package has several programs ({', '.join(bins)}). Use npx -p <package> <program>.")
        return str(chosen).removeprefix("./")
    if isinstance(doc.get("main"), str):
        return doc["main"].removeprefix("./")
    raise SandboxError("The installed package does not say which file to run (no bin or main)")


# ---- uvx and pipx run -------------------------------------------------------------


def split_uvx(args: list[str], pipx: bool = False) -> tuple[str, list[str], str, list[str]] | None:
    """(package spec to install, extra packages, command name, arguments for the server)."""
    source: str | None = None
    extras: list[str] = []
    position = 0
    flags = UVX_VALUE_FLAGS | ({"--spec"} if pipx else set())
    while position < len(args):
        arg = args[position]
        if arg in ("--from", "--spec") and position + 1 < len(args):
            source = args[position + 1]
            position += 2
        elif arg.startswith(("--from=", "--spec=")):
            source = arg.split("=", 1)[1]
            position += 1
        elif arg == "--with" and position + 1 < len(args):
            extras.append(args[position + 1])
            position += 2
        elif arg in flags:
            position += 2
        elif arg.startswith("-"):
            position += 1
        else:
            break
    if position >= len(args):
        return None
    first, server_args = args[position], args[position + 1 :]
    command = re.split(r"[@=<>!~\[;]", first, maxsplit=1)[0]
    spec = source or (first.replace("@", "==", 1) if "@" in first and "==" not in first else first)
    return spec, extras, command, server_args


def _uvx(args: list[str], image: str, pipx: bool = False) -> Preparation | None:
    parts = split_uvx(args, pipx)
    if parts is None:
        return None
    spec, extras, command, server_args = parts
    script = f"uv venv --quiet {DEPS}/venv && uv pip install --quiet --python {DEPS}/venv/bin/python " + " ".join(
        shlex.quote(p) for p in [spec, *extras]
    )

    script += f" && echo {MARK} && ls {DEPS}/venv/bin"

    def finish(output: str) -> tuple[str, list[str]]:
        if command not in report(output).split():
            raise SandboxError(f"The package installed, but it has no program called '{command}'")
        return f"{DEPS}/venv/bin/{command}", server_args

    return Preparation(
        image=image, script=script, finish=finish, env={"UV_LINK_MODE": "copy"}, summary=f"uv pip install {spec}"
    )


# ---- a repository (--run) ------------------------------------------------------------


def _repository(spec: ServerSpec, settings: SandboxSettings) -> Preparation:
    assert spec.repo is not None and spec.repo.entry
    repo_dir = Path(spec.repo.local_dir)
    entry = spec.repo.entry
    server_args = spec.args[1:]
    app = f"{DEPS}/app"
    copy = f"cp -r {SRC}/. {app}"
    if spec.repo.kind == "python":
        steps = [f"mkdir -p {app}", copy, f"uv venv --quiet {DEPS}/venv"]
        pip = f"uv pip install --quiet --python {DEPS}/venv/bin/python"
        if (repo_dir / "requirements.txt").is_file():
            steps.append(f"{pip} -r {app}/requirements.txt")
        installs_project = (repo_dir / "pyproject.toml").is_file() or (repo_dir / "setup.py").is_file()
        if installs_project:
            steps.append(f"{pip} {app}")
        image = settings.docker_image or settings.docker_image_python
        steps.append(f"echo {MARK}")

        program = spec.repo.program
        if program and installs_project:
            # Run the program the project installs (what `uvx <name>` would run). Servers
            # often start their own helpers by program name, which needs venv/bin on PATH.
            steps[-1] = f"echo {MARK} && ls {DEPS}/venv/bin"

        def finish_python(output: str) -> tuple[str, list[str]]:
            listed = report(output).split()
            if program and installs_project and program in listed:
                return f"{DEPS}/venv/bin/{program}", server_args
            return f"{DEPS}/venv/bin/python", [f"{app}/{entry}", *server_args]

        return Preparation(
            image=image,
            script=" && ".join(steps),
            finish=finish_python,
            workdir=app,
            env={"UV_LINK_MODE": "copy", "PYTHONPATH": app, "PATH": f"{DEPS}/venv/bin:{SYSTEM_PATH}"},
            mount_repo=str(repo_dir),
            writable=True,
            summary="copy the repository, install its Python dependencies",
            install_image=_install_image(settings, "python"),
        )
    steps = [f"mkdir -p {app}", copy, f"cd {app}"]
    if (repo_dir / "package.json").is_file():
        has_lock = (repo_dir / "package-lock.json").is_file()
        steps.append(
            "npm ci --no-audit --no-fund --loglevel=error"
            if has_lock
            else "npm install --no-audit --no-fund --loglevel=error"
        )
        if not (repo_dir / entry).is_file() and _has_build_script(repo_dir):
            steps.append("npm run build")
    image = settings.docker_image or settings.docker_image_node
    steps.append(f"echo {MARK} && (test -f {shlex.quote(f'{app}/{entry}')} && echo entry-ok || echo entry-missing)")

    def finish_node(output: str) -> tuple[str, list[str]]:
        if report(output) != "entry-ok":
            raise SandboxError(f"After install, the entry file {entry} still does not exist")
        return "node", [f"{app}/{entry}", *server_args]

    return Preparation(
        image=image,
        script=" && ".join(steps),
        finish=finish_node,
        workdir=app,
        env={"PATH": f"{app}/node_modules/.bin:{SYSTEM_PATH}"},
        mount_repo=str(repo_dir),
        writable=True,
        summary="copy the repository, install its npm dependencies",
        install_image=_install_image(settings, "node"),
    )


def _setup_plan(spec: ServerSpec, settings: SandboxSettings) -> Preparation:
    """Install and start a repository the way the AI setup plan says."""
    assert spec.repo is not None and spec.repo.setup is not None
    setup = spec.repo.setup
    app = f"{DEPS}/app"
    steps = [f"mkdir -p {app}", f"cp -r {SRC}/. {app}"]
    if setup.kind == "python":
        image = settings.docker_image or settings.docker_image_python
        steps.append(f"uv venv --quiet {DEPS}/venv")
        env = {
            "UV_LINK_MODE": "copy",
            "VIRTUAL_ENV": f"{DEPS}/venv",
            "PYTHONPATH": app,
            "PATH": f"{DEPS}/venv/bin:{app}/node_modules/.bin:{SYSTEM_PATH}",
        }
    else:
        image = settings.docker_image or settings.docker_image_node
        env = {"PATH": f"{app}/node_modules/.bin:{SYSTEM_PATH}"}
    steps.append(f"cd {app}")
    # Each step runs in its own subshell from the app folder, so one `cd` cannot confuse the next.
    steps += [f"(cd {app} && {step})" for step in setup.install]
    command = shlex.quote(setup.command)
    steps.append(f"echo {MARK} && (command -v {command} >/dev/null 2>&1 && echo command-ok || echo command-missing)")

    def finish_plan(output: str) -> tuple[str, list[str]]:
        if report(output) != "command-ok":
            raise SandboxError(f"After install, the start command '{setup.command}' does not exist")
        return setup.command, list(setup.args)

    return Preparation(
        image=image,
        script=" && ".join(steps),
        finish=finish_plan,
        workdir=app,
        env={**setup.env, **env},
        mount_repo=spec.repo.local_dir,
        writable=True,
        summary=f"AI setup plan: {'; '.join(setup.install) or 'no install steps'}",
        install_image=_install_image(settings, setup.kind),
    )


def _install_image(settings: SandboxSettings, kind: str) -> str | None:
    """The fuller image for a repository install, unless one image is forced for everything."""
    if settings.docker_image:
        return None
    return settings.docker_install_image_python if kind == "python" else settings.docker_install_image_node


def _has_build_script(repo_dir: Path) -> bool:
    try:
        doc = json.loads((repo_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(doc.get("scripts"), dict) and "build" in doc["scripts"]
