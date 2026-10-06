# Architecture

This page shows how Aevrin MCP Scanner is built, piece by piece.

## The big picture

```text
CLI  (mcp_scanner/cli)
 |
 v
Scan Engine  (mcp_scanner/scanner)
 |
 +-- Target Resolver ........ what should we scan?       (mcp_scanner/config)
 |
 +-- Server Validator ....... is the target sane?        (mcp_scanner/scanner/validate.py)
 |
 +-- Launcher + Sandbox ..... start it safely            (mcp_scanner/sandbox)
 |
 +-- MCP Connection ......... speak the protocol         (mcp_scanner/mcp)
 |
 +-- Inventory Collector .... tools, prompts, resources  (mcp_scanner/mcp/inventory.py)
 |
 +-- Static Analysis ........ collect facts              (mcp_scanner/analyzers)
 |
 +-- Dynamic Analysis ....... watch real behavior        (mcp_scanner/analyzers/dynamic)
 |
 +-- Security Rules ......... turn facts into findings   (mcp_scanner/rules)
 |
 +-- Finding Validation ..... clean up findings          (mcp_scanner/validators)
 |
 +-- Risk Engine ............ score and grade            (mcp_scanner/risk)
 |
 +-- AI Analysis ............ optional second opinion    (mcp_scanner/ai)
 |
 +-- Report Engine .......... console, JSON, Markdown    (mcp_scanner/reports)
 |
 v
Results (ScanReport)
```

The most important idea: **analyzers collect facts, rules make findings.**
An analyzer never says "this is bad". It says "this tool has a parameter called `command`".
A rule then says "a tool that takes a free text command can run anything, that is risky".
This keeps both sides small and easy to test.

## Data flows through models

All parts talk using plain data models from `mcp_scanner/models`. They are Pydantic models, so they check their own fields and turn into JSON easily.

```text
ServerSpec        what to scan (command, url, env, headers)
ServerInventory   what the server told us (tools, prompts, resources, instructions)
ScanContext       everything a rule can read (inventory + facts + observations)
FindingCandidate  what a rule produces
Finding           a validated candidate with risk points
ServerResult      one server: inventory, findings, risk, errors, timing
ScanReport        the whole scan: many ServerResults + metadata + AI usage
```

---

## Components

Each component lists: what it does, why it exists, input, output, dependencies, how it talks to others, how to test it, and how to replace it.

### CLI (`mcp_scanner/cli`)

- **What:** Reads your command, loads config, calls the engine, prints results, picks the exit code.
- **Why:** People and CI systems need one simple entry point.
- **Input:** Command line arguments and the config file.
- **Output:** Console text, report files, an exit code.
- **Depends on:** `config`, `scanner`, `reports`, `skills`, `evaluation`.
- **Talks by:** Building a `ScanRequest` and calling `ScanEngine.run()`. Per-run flags are applied to a copy
  of the settings with `scanner/options.py`, which skills use too.
- **Test:** `typer.testing.CliRunner` tests in `tests/cli`.
- **Replace:** Any other front end (a web API, a GitHub Action) can build a `ScanRequest` and call the engine the same way.

### Target Resolver (`mcp_scanner/config/targets.py`)

- **What:** Turns "what you typed" into a list of `ServerSpec` objects.
- **Why:** A target can be a command, a URL, a client config file, a tools file, or "discover everything".
- **Input:** The target string and options.
- **Output:** `list[ServerSpec]`.
- **Depends on:** `config/mcp_config.py` (client config parser), `config/discovery.py` (known paths).
- **Test:** Unit tests with sample config files from many clients.
- **Replace:** Add a new input type by adding one branch that returns `ServerSpec` objects.

### Server Validator (`mcp_scanner/scanner/validate.py`)

- **What:** Checks a `ServerSpec` before anything runs: is the command found, is the URL valid.
- **Why:** Fail early with a clear message instead of a confusing crash later.
- **Input:** `ServerSpec`. **Output:** a list of problems (empty means OK).
- **Test:** Unit tests.

### Launcher and Sandbox (`mcp_scanner/sandbox`)

- **What:** Starts a local server inside a sandbox and stops it again, with the whole process tree.
- **Why:** Starting a server runs its code. That code might be hostile.
- **Input:** `ServerSpec` + `SandboxSettings`.
- **Output:** A `SandboxedProcess` with pipes, plus `SandboxObservations` (processes seen, network seen, files written).
- **Depends on:** `subprocess`, `psutil`, Docker CLI (optional).
- **Talks by:** The stdio transport reads and writes the process pipes.
- **Test:** Security tests that start hostile fixture servers (hang, crash, spam output, spawn children, read env).
- **Replace:** Add a new sandbox (for example gVisor or a VM) by writing one class with the same `start()` / `stop()` methods.

### MCP Connection (`mcp_scanner/mcp`)

- **What:** A small JSON-RPC client and three transports: stdio, streamable HTTP, SSE.
- **Why:** We need full control of the process and must refuse risky server requests (like sampling).
- **Input:** A transport. **Output:** An `MCPSession` with `initialize()`, `list_tools()`, `call_tool()` and more.
- **Talks by:** `transport.send(message)` and `transport.receive(timeout)`.
- **Test:** Integration tests against real servers built with the official MCP SDK, over stdio and HTTP.
- **Replace:** Any new transport only needs `send`, `receive`, and `close`.

### Inventory Collector (`mcp_scanner/mcp/inventory.py`)

- **What:** Reads tools, prompts, resources, resource templates, and server instructions, page by page.
- **Why:** Rules need the full picture, and a server may split lists into pages.
- **Input:** `MCPSession`. **Output:** `ServerInventory`.
- **Test:** Integration tests, plus a unit test with a fake session that returns many pages.

### Static Analysis (`mcp_scanner/analyzers`)

- **What:** Collects facts without running anything new.
  - `text.py`: finds all text surfaces and normalizes them (hidden characters, encodings).
  - `capabilities.py`: guesses what each tool can do from word tokens and the schema.
  - `source/`: reads server source code (Python with `ast`, JavaScript and TypeScript with patterns).
  - `dependencies.py`: reads dependency files.
- **Why:** Facts are shared by many rules. Collecting them once is faster and keeps rules simple.
- **Input:** `ServerInventory`, `ServerSpec`, optional source folder.
- **Output:** Fact objects stored on `ScanContext`.
- **Test:** Unit tests with small inputs.

### Dynamic Analysis (`mcp_scanner/analyzers/dynamic`)

- **What:** Watches real behavior while the server runs:
  - lists tools again to catch changes (rug pull),
  - compares tools with the last pinned scan,
  - calls safe tools with harmless "canary" inputs and checks the answers,
  - reads prompts and text resources,
  - collects process, network, and file observations from the sandbox.
- **Why:** Some attacks only show up at run time.
- **Input:** A live `MCPSession`, sandbox observations. **Output:** `DynamicObservations`.
- **Safety:** Off by default. Dangerous tools are never called unless you allow it.
  Source code is analyzed before dynamic analysis starts, so a tool whose code runs commands, evaluates code,
  writes files, or calls the network is skipped even when its description looks harmless.
- **Changed tools:** when a tool changes during the session, its new definition is added to the text surfaces
  (with "(after change)" in the location), so every text rule also checks what the server swapped in.
- **Test:** Real malicious fixture servers in `tests/fixtures/servers`.

### Security Rules (`mcp_scanner/rules`)

- **What:** Small classes that read facts and return `FindingCandidate` objects.
- **Why:** One rule per idea. Easy to read, test, enable, or disable.
- **Input:** `ScanContext`. **Output:** `list[FindingCandidate]`.
- **Test:** Regression tests with "must fire" and "must not fire" examples for every rule.
- **Replace:** Rules are found through a registry. Add, remove, or override any rule.

### Finding Validation (`mcp_scanner/validators`)

- **What:** Removes duplicates, checks evidence, handles negation, applies suppressions, sets validation status, and adjusts confidence.
- **Why:** Raw rule output is noisy. Users stop trusting noisy tools.
- **Input:** Candidates + context. **Output:** `list[Finding]`.

### Risk Engine (`mcp_scanner/risk`)

- **What:** Gives points to each finding and a score and grade to each server.
- **Why:** People need to know what to fix first.
- **Input:** Findings. **Output:** `RiskScore` with a list of explained factors.

### AI Analysis (`mcp_scanner/ai`)

- **What:** Optional review by OpenAI, Anthropic, or xAI.
- **Why:** AI is good at reading intent and explaining risk in plain words.
- **Rules:** It never deletes deterministic findings and never sees secrets.
- **Input:** Findings + inventory. **Output:** `AIReview` (notes, observations, summary, usage).
- **Replace:** Add a provider by writing one class with a `complete()` method.

### Report Engine (`mcp_scanner/reports`)

- **What:** Turns a `ScanReport` into console text, JSON, Markdown, or SARIF.
- **Input:** `ScanReport`. **Output:** Text.
- **Replace:** Add a format with one class and one registry entry.

### Skills (`mcp_scanner/skills`)

- **What:** Loads `SKILL.md` files, checks them, and runs their workflows through the engine.
- **Why:** Agents and people can reuse ready-made scan recipes.

### Evaluation (`mcp_scanner/evaluation`)

- **What:** Runs the scanner against known cases and measures quality.
- **Why:** Without numbers, nobody knows if a rule change made things better or worse.

---

## Folder map

```text
src/mcp_scanner/
  cli/          command line app
  config/       settings, client config parsing, discovery, target resolving
  models/       shared data models
  sandbox/      safe process and docker launching, watchdog
  mcp/          JSON-RPC client, transports, inventory collector
  scanner/      scan engine, context, server validator
  analyzers/    fact collectors (text, capabilities, source, dependencies, dynamic)
  rules/        rule base class, registry, YAML rules, built-in rules
  validators/   finding validator and suppressions
  risk/         scoring and grades
  ai/           AI providers, redaction, prompts, AI review
  skills/       skill loading, validation, running
  reports/      console, JSON, Markdown, SARIF
  evaluation/   eval cases, runner, metrics
  logging/      log setup with secret redaction
  utils/        small helpers (hashing, text, timing)
  data/         offline data (known bad packages, popular names)
```

Next to the package, `src/` also holds the project files that are not Python code:

```text
src/
  docker/       optional sandbox images (sandbox-node, sandbox-python)
  evals/        eval cases, test servers, tools files, configs
  examples/     a GitHub Actions job, a client config, a tools file
  rules/        example YAML rules
  scripts/      helper scripts (rules doc, real server scans)
  skills/       the bundled skills (packaged into the wheel)
```

## Threading model

The scanner is synchronous, which is easier to read and debug.
Background threads are used only where they must be:

- reading stdout and stderr of a server process,
- reading an SSE event stream,
- the sandbox watchdog.

Each thread puts data into a queue. The main thread reads the queue with a timeout.
