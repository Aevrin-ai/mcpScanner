# Implementation Plan

This is the plan we wrote before building Aevrin MCP Scanner.
It answers the big questions first, so the code has a clear shape.

If something here and the code disagree, the code wins, and this file should be fixed.

---

## 1. What the scanner does

Aevrin MCP Scanner checks MCP servers for security problems.

An MCP server gives an AI agent "tools". A tool might read files, run commands, or call websites.
A bad or careless tool can hurt the person using the agent.

The scanner:

1. Finds the MCP server you want to check.
2. Starts it safely (or connects to it over the network).
3. Asks it which tools, prompts, and resources it has.
4. Runs security checks on what it finds.
5. Optionally watches how the server behaves when it is used (dynamic analysis).
6. Removes weak or duplicate findings.
7. Gives every finding a risk score you can understand.
8. Optionally asks an AI model for a second opinion.
9. Writes a report (screen, JSON, Markdown, SARIF).

## 2. How the scanner works from start to finish

```text
CLI -> Target Resolver -> Server Validator -> Launcher (sandbox) -> MCP Session
    -> Inventory Collector -> Static Analyzers -> Dynamic Analyzers
    -> Rules -> Finding Validator -> Risk Engine -> AI Review -> Reporters
```

Each arrow is a small, separate module. Each one gets data in, gives data out.
The `ScanEngine` only calls the stages in order. It does not do the work itself.

## 3. How an MCP server is discovered

The user can point the scanner at a target in five ways:

| Input | Example | What happens |
|---|---|---|
| A command | `"npx -y @modelcontextprotocol/server-everything"` | Becomes a local (stdio) server |
| A URL | `https://example.com/mcp` | Becomes a remote (HTTP) server |
| An MCP config file | `~/.cursor/mcp.json` | Every server inside is read |
| A tools file | `tools.json` | Offline scan, nothing is started |
| `--discover` | | The scanner looks in the known config paths of popular MCP clients |

Config files from different clients use different key names (`mcpServers`, `servers`, `mcp.servers`, `context_servers`).
The parser handles all of them, allows comments (JSONC), and skips broken entries instead of failing.

## 4. How an MCP server is started

Starting a local server means running someone else's code. So we are careful:

- **Docker sandbox** (preferred): the server runs in a locked container. No network by default, read only file system, all Linux capabilities dropped, memory and process limits.
- **Process sandbox** (fallback): the server runs as a child process with a clean environment, a fresh temporary home folder, time limits, and a watchdog that kills it if it uses too much memory or starts too many processes.
- **Host confirmation**: the process sandbox is not a real security wall. So the scanner asks before it runs a server this way. In scripts you must pass `--allow-host` (or set it in config).

The server never sees the scanner's own environment. API keys like `OPENAI_API_KEY` are never passed down.

## 5. How the scanner connects to it

We use our own small MCP client. It speaks JSON-RPC over three transports:

- `stdio` (local process, line based JSON)
- `streamable HTTP` (the modern remote transport)
- `SSE` (the older remote transport)

Why our own client and not the SDK client?

1. We must own the process to sandbox it and to kill the full process tree.
2. We must refuse server requests like "please use your AI model for me" (sampling). Our client says it supports nothing extra.
3. We want to record strange protocol behavior as evidence.

The official MCP Python SDK is still used to build the real test servers, so we test against real SDK behavior.

## 6. How MCP tools are discovered

After the `initialize` handshake the collector calls:

- `tools/list`
- `prompts/list` (only if the server says it has prompts)
- `resources/list` and `resources/templates/list` (only if the server says it has resources)

Every list call follows `nextCursor` pages, with a page limit, so big servers are fully read and evil servers cannot loop forever.
The server `instructions` text from the handshake is saved too, because agents put it in their system prompt.

## 7. How tools are analyzed

Analyzers collect facts. They do not decide if something is bad.

- **Text surfaces**: every piece of text the agent will read (tool description, parameter descriptions, enum values, defaults, prompt text, resource text, server instructions).
- **Capabilities**: what a tool can do (run commands, write files, call URLs, run SQL), based on word tokens in the name, the description, and the input schema.
- **Source facts** (if source code is given): MCP tool functions and the dangerous calls inside them, with simple taint tracking from tool parameters.
- **Dependency facts**: packages from `requirements.txt`, `pyproject.toml`, `package.json`, and lock files.
- **Config facts**: how the server is launched (command, args, env, headers, URL).

## 8. How security checks are executed

Rules are small classes. Each rule:

- has an ID like `MCP-EXEC-001`, a title, a category, a default severity
- reads facts from the `ScanContext`
- returns `FindingCandidate` objects with evidence

The `RuleRegistry` finds built-in rules automatically. Users can add simple YAML regex rules from a folder, or Python rules through a plugin entry point.
A crash in one rule is caught, recorded as a scan error, and the other rules keep running.

## 9. How findings are validated

The `FindingValidator` turns candidates into findings:

1. Drop candidates without evidence.
2. Merge duplicates (same rule, same target, same evidence).
3. Look at negation ("this tool does **not** run commands") and mark those as likely false positives.
4. Raise confidence when two independent sources agree (for example, the description says "runs shell commands" and the source code calls `subprocess` with `shell=True`).
5. Mark dynamic proof as `confirmed` (for example, our secret canary came back in a tool result).
6. Apply user suppressions (with a reason, and an optional expiry date).

## 10. How risk is calculated

Each finding gets points: severity points times a confidence factor.
The server score is the sum, capped at 100. The grade (A to F) comes from the score.
A confirmed malicious finding always forces grade F.
Every point is listed in the report, so you can see why the number is what it is.
The number is a sorting aid, not a scientific truth. The docs say so.

## 11. How AI providers are used

AI is optional and off unless you turn it on.

- Providers: OpenAI, Anthropic, xAI (Grok), and OpenRouter (one key for many models, through the OpenAI SDK). Each one uses an official Python SDK.
- AI reviews findings and tools, and writes a short summary.
- AI can add notes and "AI observations", but it can never delete a deterministic finding or change its severity.
- Secrets are removed from text before it is sent. Untrusted text is wrapped in random markers so it cannot pretend to be instructions.
- Calls, tokens, and (if you set prices) cost are tracked and shown.

## 12. How results are stored

- Reports are written to the output folder (`--output`), one file per format.
- The JSON report is the main record. `mcp-scanner report <file.json>` can turn it into other formats later.
- Tool "pins" (hashes of each tool definition) are saved in a small JSON store, so the next scan can tell if a tool changed ("rug pull").

## 13. How reports are generated

All reporters read the same `ScanReport` model. They never re-compute data.
Formats: console, JSON, Markdown, SARIF. A new format is one new class plus one registry line.

## 14. How CLI output works

The console reporter prints a summary block (server, status, counts), then each finding in a simple block:
severity, rule ID, tool, description, why it matters, evidence, recommendation, confidence.
Logs go to stderr. Results go to stdout. So `--json` output can be piped safely.
Exit code: `0` clean, `1` findings at or above `--fail-on`, `2` scan error.

## 15. How evaluations work

`src/evals/` holds real test servers and offline tool files, each with a case file and an expected results file.
`mcp-scanner eval` scans every case and compares results with the expected ones.
It reports detection rate, precision, recall, false positive rate, false negative rate, confidence, run time, AI usage, and cost.
The data set has both bad and good servers, so false positives are measured too.

## 16. How skills are loaded and executed

A skill is a folder with a `SKILL.md` file. The top of the file (front matter) says what the skill is, its inputs, and a `workflow` block. The rest of the file is plain instructions any agent can follow.

- `mcp-scanner skills list` finds skills.
- `mcp-scanner skills validate` checks them.
- `mcp-scanner skills run <name>` runs the workflow through the normal scan engine.

Skills are data only. They cannot run their own code. They can only call a short list of safe actions (`scan`, `inspect`, `discover`, `report`).

## 17. How new security checks can be added later

- Built-in Python rule: one small file in `src/mcp_scanner/rules/builtin/`, plus tests. It is picked up automatically.
- YAML rule: one file in a rules folder, passed with `--rules-dir`.
- Plugin rule: a Python package that exposes rules through the `aevrin_mcp_scanner.rules` entry point.

## 18. How the system handles failures

- Every stage records its errors in the result instead of crashing the whole scan.
- A scan has a status: `completed`, `partial`, or `failed`.
- A partial scan is never shown as "safe". The safe flag has three values: `true`, `false`, or `null` (unknown).
- Timeouts exist for startup, every request, and the whole scan.
- AI errors never fail a scan. They are listed as errors in the report.

## 19. How the system remains safe when scanning untrusted servers

- No server is started without a sandbox or your clear approval.
- Clean environment. No scanner secrets leak to the server.
- Fresh temporary home and work folders, deleted after the scan.
- Timeouts, memory limit, process count limit, output size limit.
- The whole process tree is killed at the end, even if the server ignores signals.
- Dynamic tool calls are opt in, and dangerous tools are not called unless you ask.
- All server text is treated as hostile data, never as instructions, including when it is sent to AI.

The full details are in [safety.md](safety.md) and [sandboxing.md](sandboxing.md).

---

## Build order

| Phase | Work |
|---|---|
| 1 | Study existing designs and threat research |
| 2 | Architecture and design docs |
| 3 | Project structure, packaging, config |
| 4 | Sandbox, launcher, transports, MCP session |
| 5 | Inventory collector (tools, prompts, resources) |
| 6 | Scan engine and context |
| 7 | Rule system and registry |
| 8 | Static analyzers (text, capabilities, source, dependencies, config) |
| 9 | Dynamic analyzers (rug pull, canaries, probes, process watch) |
| 10 | Finding validator and suppressions |
| 11 | Risk engine |
| 12 | AI providers and AI review |
| 13 | Skills |
| 14 | Reporters |
| 15 | CLI |
| 16 | Evals |
| 17 | Tests |
| 18 | Real server runs |
| 19 | Fix bugs and false positives |
| 20 | Final docs pass |
