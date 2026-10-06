# Development

## Setup

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev,ai]"        # Windows: .venv\Scripts\pip
```

## Checks

```bash
ruff check src tests evals
ruff format --check src tests evals
mypy
pytest                       # about 300 tests, around 30 seconds
mcp-scanner eval --allow-host
python src/scripts/gen_rules_doc.py    # after adding or changing a rule
```

Tests start small fixture servers as local processes. Test markers: `slow`, `network` (downloads real
servers), `docker`, `ai` (calls a real provider). Skip them with `pytest -m "not docker and not ai"`.

The `docker` tests skip by themselves unless Docker is running and the Python sandbox image exists:

```bash
docker build -f src/docker/sandbox-python.Dockerfile -t aevrin-sandbox-python .
```

The `ai` test skips unless `OPENROUTER_API_KEY` is set. It makes one call (about 2 US cents).

## Test folders

| Folder | What it tests |
|---|---|
| `tests/unit` | one module at a time: dependencies, validator, risk, registry, YAML rules, pins, probes, AI, reports, skills, evals |
| `tests/regression` | must-match and must-not-match text for every pattern; a must-fire example for every rule; a clean server that must stay clean |
| `tests/mcp` | the MCP client against real SDK servers over stdio and streamable HTTP; pagination; server requests; SSE endpoint checks |
| `tests/integration` | the whole engine: static and dynamic scans, canary leaks, rug pulls, config files, pins, multi-server shadowing |
| `tests/security` | hostile servers: no permission, secret isolation, hangs, crashes, output spam, endless pages, child processes, cleanup |
| `tests/cli` | every command through Typer's test runner |

## Dependencies

The list is short on purpose:

| Package | Why |
|---|---|
| typer | the command line |
| rich | readable console output |
| pydantic | data models and settings validation |
| pyyaml | config, YAML rules, skills, eval cases |
| httpx | streamable HTTP and SSE transports |
| psutil | process tree control and the watchdog |
| python-dotenv | loading a local `.env` file |

Optional: `openai`, `anthropic`, `xai-sdk` (AI review), `mcp` (only to run the fixture servers).

## Project layout

See [architecture.md](architecture.md) for the components and how data flows between them.

## Style

- Plain, simple English in docs, messages, and comments. No em dashes.
- Small functions, one idea per rule, evidence on every finding.
- Every user-facing message must be safe to show: no secrets, no raw environment values.
