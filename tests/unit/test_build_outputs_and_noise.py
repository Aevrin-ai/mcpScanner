"""Fixes found on a TypeScript repository (a server that must be built before it runs):

- launches that point at build output are mapped back to their source
- helper programs next to a registered MCP server are skipped
- AI plans may not swap the repository for the published package
- keys a comment calls public, Google client keys, and minified bundles do not count as strong findings
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import make_context, run_rules
from mcp_scanner.ai.setup import PlanError, SetupPlanner, own_packages, validate_plan
from mcp_scanner.analyzers.source import analyze_source, is_minified
from mcp_scanner.config.repository import find_launches
from mcp_scanner.config.settings import AISettings, SandboxSettings
from mcp_scanner.models.server import RepoInfo, ServerSpec, SetupPlan, TransportType
from mcp_scanner.models.severity import Confidence, Severity
from mcp_scanner.reports.base import status_line
from mcp_scanner.sandbox import prepare
from mcp_scanner.sandbox.docker import install_error_lines

SERVER_TS = "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nconst server = new McpServer({});\n"


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def ts_repo(root: Path, registered: bool = True) -> None:
    doc = {
        "name": "demo-mcp",
        "bin": {"demo-mcp": "./build/src/bin/demo-mcp.js", "demo-cli": "./build/src/bin/demo-cli.js"},
        "main": "./build/src/index.js",
        "scripts": {"build": "tsc"},
    }
    if registered:
        doc["mcpName"] = "io.github.owner/demo-mcp"
    write(root, "package.json", json.dumps(doc))
    write(
        root,
        "tsconfig.json",
        '{\n  // comments are allowed here\n  "compilerOptions": {"outDir": "./build", "rootDir": "."}\n}',
    )
    write(root, "src/bin/demo-mcp.ts", "import '../index.js';\n")
    write(root, "src/bin/demo-cli.ts", "import '../index.js';\n")
    write(root, "src/index.ts", SERVER_TS)


# ---- launches -----------------------------------------------------------------------


def test_build_output_is_mapped_to_its_source(tmp_path: Path) -> None:
    ts_repo(tmp_path)
    launches = find_launches(tmp_path)
    assert [(x.entry, x.source, x.program) for x in launches] == [
        ("build/src/bin/demo-mcp.js", "src/bin/demo-mcp.ts", "demo-mcp")
    ]


def test_without_registry_metadata_every_program_is_kept(tmp_path: Path) -> None:
    ts_repo(tmp_path, registered=False)
    entries = [x.entry for x in find_launches(tmp_path)]
    # "main" is skipped because "bin" names the programs; raw .ts guesses are skipped because the project builds.
    assert entries == ["build/src/bin/demo-mcp.js", "build/src/bin/demo-cli.js"]


def test_dist_folder_without_tsconfig(tmp_path: Path) -> None:
    write(tmp_path, "package.json", json.dumps({"name": "x", "main": "dist/server.js", "scripts": {"build": "tsc"}}))
    write(tmp_path, "src/server.ts", SERVER_TS)
    launches = find_launches(tmp_path)
    assert [(x.entry, x.source) for x in launches] == [("dist/server.js", "src/server.ts")]


def test_built_repository_runs_the_build(tmp_path: Path) -> None:
    ts_repo(tmp_path)
    info = RepoInfo(url="u", clone_url="u", local_dir=str(tmp_path), entry="build/src/bin/demo-mcp.js", kind="node")
    spec = ServerSpec(name="s", transport=TransportType.STDIO, command="node", args=[info.entry or ""], repo=info)
    prep = prepare.plan(spec, spec.args, SandboxSettings())
    assert prep is not None and "npm run build" in prep.script
    assert prep.install_image == "node:22" and prep.image == "node:22-slim"
    assert prepare.plan(spec, spec.args, SandboxSettings(docker_image="custom")).install_image is None  # type: ignore[union-attr]


# ---- AI plans must run this repository ---------------------------------------------------

PLAN = {"kind": "node", "install": ["npm ci", "npm run build"], "command": "node", "args": ["build/index.js"]}
OWN = frozenset({"demo-mcp"})


@pytest.mark.parametrize(
    "change",
    [
        {"install": [], "command": "npx", "args": ["-y", "demo-mcp@latest"]},
        {"command": "uvx", "args": ["demo-mcp"]},
        {"install": ["npm install -g demo-mcp@1.2.0"]},
        {"install": ["uv pip install demo-mcp==1.0"]},
        {"command": "/usr/local/bin/npx", "args": ["demo-mcp"]},
        {"command": "/opt/deps/../usr/bin/npx"},
    ],
)
def test_plans_that_skip_the_repository_are_rejected(change: dict) -> None:
    with pytest.raises(PlanError):
        validate_plan({**PLAN, **change}, OWN)


def test_plans_that_build_the_repository_are_fine() -> None:
    assert validate_plan(PLAN, OWN).command == "node"
    assert (
        validate_plan({**PLAN, "install": ["npm ci", "npm install left-pad"]}, OWN).install[-1]
        == "npm install left-pad"
    )
    assert validate_plan({**PLAN, "command": "/opt/deps/app/node_modules/.bin/tsx", "args": ["src/index.ts"]}, OWN)


def test_own_packages(tmp_path: Path) -> None:
    write(tmp_path, "package.json", json.dumps({"name": "@scope/demo"}))
    write(tmp_path, "pyproject.toml", '[project]\nname = "demo-py"\n')
    assert own_packages(tmp_path) == {"@scope/demo", "demo-py"}
    with pytest.raises(PlanError):
        validate_plan({**PLAN, "install": ["npm i @scope/demo@2"]}, own_packages(tmp_path))


def test_bad_cached_plan_is_dropped(tmp_path: Path) -> None:
    write(tmp_path, "package.json", json.dumps({"name": "demo-mcp"}))
    repo = RepoInfo(url="u", clone_url="u", commit="abc", local_dir=str(tmp_path))
    planner = SetupPlanner(AISettings(), cache_dir=tmp_path / "plans")
    planner.remember(repo, SetupPlan(kind="node", command="npx", args=["-y", "demo-mcp@latest"], needs_network=True))
    assert planner.cached(repo) is None
    assert not list((tmp_path / "plans").glob("*.json"))


# ---- secrets that are public on purpose --------------------------------------------------

GOOGLE_KEY = "AIzaSyD" + "x" * 32


def secret_findings(tmp_path: Path, code: str) -> list:
    write(tmp_path, "server.ts", code)
    ctx = make_context(source_text=None, tmp_path=tmp_path)
    ctx.source = analyze_source(tmp_path / "server.ts")
    return run_rules(ctx, "MCP-SECRET-003")


def test_key_marked_public_adds_no_points(tmp_path: Path) -> None:
    code = f"// Yes, we're aware this API key is public. ;)\nfetch('https://x.googleapis.com/v1?key={GOOGLE_KEY}');\n"
    finding = secret_findings(tmp_path, code)[0]
    assert finding.confidence == Confidence.LOW and finding.severity == Severity.LOW and finding.risk_points == 0
    assert "public on purpose" in finding.description


def test_google_client_key_is_medium(tmp_path: Path) -> None:
    finding = secret_findings(tmp_path, f"const KEY = '{GOOGLE_KEY}';\n")[0]
    assert finding.severity == Severity.MEDIUM and "restricted" in finding.description


def test_real_secrets_stay_high(tmp_path: Path) -> None:
    finding = secret_findings(tmp_path, "const KEY = 'AKIAABCDEFGHIJKLMNOP';\n")[0]
    assert finding.severity == Severity.HIGH and finding.confidence == Confidence.HIGH


# ---- minified bundles -----------------------------------------------------------------------


def test_minified_detection() -> None:
    assert is_minified("var a=1;" * 1000)
    assert is_minified("\n".join(["x"] * 1000 + ["y" * 600] * 60))
    assert not is_minified("const a = 1;\n" * 1000 + "z" * 600)


def test_bundles_only_get_secret_checks(tmp_path: Path) -> None:
    bundle = "\n".join(["function f(a){return a}"] * 100 + ["eval(x);" + "a" * 600] * 60 + [f"var k='{GOOGLE_KEY}'"])
    write(tmp_path, "vendor.bundle.js", bundle)
    write(tmp_path, "server.js", "eval(userInput);\nconst line = '" + "b" * 600 + "'; eval(y);\n")
    facts = analyze_source(tmp_path)
    assert sorted(facts.minified_files) == ["server.js", "vendor.bundle.js"]
    assert [(h.category, h.file, h.line) for h in facts.hits if h.category == "code-eval"] == [
        ("code-eval", "server.js", 1)
    ]
    assert any(h.category == "secret" and h.file == "vendor.bundle.js" for h in facts.hits)


# ---- clearer errors and status -------------------------------------------------------------


def test_install_error_lines_pick_the_cause() -> None:
    output = "\n".join(
        ["added 400 packages"] * 20
        + ["/bin/sh: 1: git: not found", "Error: Command failed: git clone x", "  pid: 71,", "  stdout: null,", "}"]
    )
    assert install_error_lines(output) == ["/bin/sh: 1: git: not found", "Error: Command failed: git clone x"]
    assert install_error_lines("just\nsome\noutput") == ["just", "some", "output"]


def test_status_line() -> None:
    assert status_line("failed", False).startswith("failed: the server did not start")
    assert status_line("completed", True) == "completed (no known issues)"
    assert "did not finish" in status_line("partial", None)


# ---- bundled programs, code that looks like a key ----------------------------------------


def test_bundled_program_maps_to_the_bundler_entry(tmp_path: Path) -> None:
    write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "name": "@x/demo",
                "bin": {"demo": "bin/cli.mjs"},
                "scripts": {"build": "tsc -build && node scripts/build-cli.js"},
            }
        ),
    )
    write(
        tmp_path,
        "scripts/build-cli.js",
        "await esbuild.build({\n  entryPoints: [join(__dirname, 'start-server.ts')],\n  outfile: 'bin/cli.mjs',\n});\n",
    )
    write(tmp_path, "scripts/start-server.ts", "import '../src/server.js';\n")
    write(tmp_path, "src/server.ts", SERVER_TS)
    assert [(x.entry, x.source) for x in find_launches(tmp_path)] == [("bin/cli.mjs", "scripts/start-server.ts")]


def test_bundled_program_falls_back_to_the_dev_script(tmp_path: Path) -> None:
    write(
        tmp_path,
        "package.json",
        json.dumps({"name": "d", "bin": "out/cli.js", "scripts": {"build": "webpack", "dev": "tsx watch src/main.ts"}}),
    )
    write(tmp_path, "src/main.ts", SERVER_TS)
    assert [(x.entry, x.source) for x in find_launches(tmp_path)] == [("out/cli.js", "src/main.ts")]


@pytest.mark.parametrize(
    "line",
    [
        "authToken = options.authToken || process.env.AUTH_TOKEN",
        "const notionToken = process.env.NOTION_TOKEN",
        "api_key = os.environ.OPENAI_API_KEY",
        "token: this.config.accessToken,",
    ],
)
def test_code_references_are_not_credentials(tmp_path: Path, line: str) -> None:
    assert secret_findings(tmp_path, line + "\n") == []


def test_literal_credentials_are_still_found(tmp_path: Path) -> None:
    assert secret_findings(tmp_path, "const api_key = 'q8Zr2LmX0vPa9TkW4sYd7HbN'\n")


def test_keys_the_code_reads(tmp_path: Path) -> None:
    from mcp_scanner.utils.secrets import is_key_name

    write(
        tmp_path,
        "server.ts",
        "const t = process.env.NOTION_TOKEN;\nconst f = process.env['ENABLE_TOKEN_PASSTHROUGH'];\nconst u = process.env.BASE_URL;\n",
    )
    write(tmp_path, "app.py", "import os\nkey = os.getenv('OPENAI_API_KEY')\nport = os.environ['PORT_NUMBER']\n")
    reads = analyze_source(tmp_path).env_reads
    assert set(reads) == {"NOTION_TOKEN", "ENABLE_TOKEN_PASSTHROUGH", "BASE_URL", "OPENAI_API_KEY", "PORT_NUMBER"}
    assert sorted(n for n in reads if is_key_name(n)) == ["NOTION_TOKEN", "OPENAI_API_KEY"]
