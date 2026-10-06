# Command line

Results go to stdout. Progress, questions, and logs go to stderr. So `--json` output can be piped safely.

Exit codes for `scan`: `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` the scan failed
or was incomplete.

## scan

```bash
mcp-scanner scan [TARGET] [options]
```

TARGET can be:

| Target | Example |
|---|---|
| A command | `"npx -y some-server@1.2.3"`, `"python server.py"` |
| A repository link | `https://github.com/owner/server`, also GitLab, Bitbucket, Codeberg, `/tree/<ref>/<folder>`. See [repositories.md](repositories.md) |
| A folder | `./some-server` (a repository you already cloned) |
| A URL | `https://mcp.example.com/mcp` (streamable HTTP), `https://x.example/sse` (SSE) |
| An MCP client config | `~/.cursor/mcp.json`, `claude_desktop_config.json`, VS Code `settings.json`, Codex `config.toml` |
| A tools file | `tools.json` (a list of tools, or a saved `tools/list` answer) |

Main options:

| Option | Meaning |
|---|---|
| `--discover` | Scan every server in the known MCP client config files |
| `-s, --server NAME` | Only scan servers with this name (repeat for more) |
| `--dynamic / --static` | Watch the live server (relist tools, read prompts, call safe tools) |
| `--no-connect` | Do not start or contact servers. Check config, source, and dependencies only |
| `--run` | For a repository link or folder: install and start the server in the Docker sandbox. Without it, the code is only read |
| `--source PATH` | Server source code, for code checks. A local script in the command is found automatically |
| `--sandbox auto\|docker\|process` | Which sandbox to use |
| `--allow-host` | Allow the process sandbox without asking |
| `--network none\|allow\|auto` | Network for the Docker sandbox. `auto`: only when the server needs an online service, see [repositories.md](repositories.md#api-keys-and-the-network) |
| `-e, --env KEY=VALUE` | Extra environment variable for the server, for example its API key. See [authentication.md](authentication.md) |
| `-H, --header "Name: value"` | Extra HTTP header for remote servers, for example `Authorization: Bearer ...` |
| `--transport http\|sse` | Force a remote transport |
| `-r, --rule ID` | Only run these rules (IDs or prefixes like `MCP-EXEC`) |
| `--disable-rule ID` | Skip these rules |
| `--rules-dir DIR` | Load YAML rules from a folder |
| `--min-severity LEVEL` | Hide findings below this level |
| `--fail-on LEVEL` | Exit 1 at or above this level (`none` to never fail) |
| `-f, --format FORMAT` | `console`, `json`, `markdown`, `sarif` (repeat for more) |
| `-o, --output DIR` | Folder for report files |
| `--json` | Print the JSON report to stdout instead of the console view |
| `--ai / --no-ai`, `--ai-provider`, `--ai-model` | AI second opinion (`openai`, `anthropic`, `xai`, `openrouter`, `groq`), see [ai.md](ai.md) |
| `--ai-setup auto\|always\|never` | With `--run`: let the AI work out how to install and start a repository, see [repositories.md](repositories.md#when-automatic-setup-is-not-enough-ai-setup) |
| `--no-pins`, `--update-pins` | Tool pins, see below |
| `--call-dangerous-tools` | Let dynamic analysis call risky tools (sandbox only!) |
| `--timeout SECONDS` | Hard time limit per server |
| `--startup-timeout SECONDS` | Time a server may take to start (default 60). Raise it when npx or uvx downloads a big package |
| `-c, --config FILE` | Scanner config file |
| `-v`, `-vv` | More logs |

### Which sandbox runs the server

`--allow-host` only gives permission. It does not pick the sandbox. With the default `--sandbox auto` and
Docker running, `npx`, `uvx`, `node`, and `python` servers still start in Docker, with no network unless you
add `--network allow`. To run on this machine, pass `--sandbox process --allow-host`.

### Tool pins

Each scan saves a hash of every tool definition in `~/.aevrin-mcp-scanner/pins.json`. The next scan compares.
A changed tool is reported as MCP-DYN-003. New tools are pinned automatically. A changed pin is only replaced
when you pass `--update-pins`, so a change keeps being reported until someone accepts it.

## inspect

```bash
mcp-scanner inspect TARGET [--json]
```

Connects and lists tools, prompts, and resources. No rules run. Good for a first look.

## discover

```bash
mcp-scanner discover [--json] [--all]
```

Lists MCP client config files on this computer and the servers in them. It only reads files.
Known clients: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, Zed, Cline,
LM Studio, Kiro, Amazon Q.

## report

```bash
mcp-scanner report scan.json -f markdown -f sarif -o reports
```

Turns a saved JSON report into other formats.

## rules

```bash
mcp-scanner rules list [--category tool-poisoning] [--match MCP-EXEC] [--json]
mcp-scanner rules show MCP-POISON-001
mcp-scanner rules validate ./my-rules
```

## skills

```bash
mcp-scanner skills list
mcp-scanner skills show deep-audit
mcp-scanner skills validate [PATH]
mcp-scanner skills run quick-scan --input target="python server.py" [--allow-host]
```

See [skills.md](skills.md).

## eval

```bash
mcp-scanner eval [--case NAME] [--allow-host] [--ai] [-o DIR] [--json]
```

See [evals.md](evals.md).

## version

```bash
mcp-scanner version
```
