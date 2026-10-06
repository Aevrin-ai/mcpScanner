# Configuration

Settings come from three places. Later ones win:

1. Built-in defaults.
2. A YAML config file: `--config FILE`, or `AEVRIN_CONFIG`, or `mcp-scanner.yaml` in the current folder.
3. Environment variables (see below), then command line flags.

Unknown keys in the config file are an error, so a typo like `timout` is caught at once.
The full list of keys, with comments, is in [config.example.yaml](../config.example.yaml).

## API keys

API keys never go in the config file. Put them in your environment or in a `.env` file next to where you run
the scanner (see [.env.example](../.env.example)):

```text
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
XAI_API_KEY=...
```

## Environment variables

| Variable | Setting |
|---|---|
| `AEVRIN_CONFIG` | path of the config file |
| `AEVRIN_AI_ENABLED` | `ai.enabled` |
| `AEVRIN_AI_PROVIDER` | `ai.provider` |
| `AEVRIN_AI_MODEL` | `ai.model` |
| `AEVRIN_SANDBOX_MODE` | `sandbox.mode` |
| `AEVRIN_SANDBOX_ALLOW_HOST` | `sandbox.allow_host` |
| `AEVRIN_SANDBOX_NETWORK` | `sandbox.network` |
| `AEVRIN_LOG_LEVEL` | `logging.level` |
| `AEVRIN_OUTPUT_DIR` | `output.directory` |
| `AEVRIN_PINS_FILE` | `scan.pins_file` |

## Sections

| Section | What it controls |
|---|---|
| `scan` | `min_severity`, `fail_on`, `source_path`, `pins_file`, `connect` |
| `timeouts` | `startup`, `request`, `tool_call`, `server_total` (seconds) |
| `sandbox` | mode, host permission, network, limits, home isolation, env passthrough, Docker images |
| `dynamic` | on or off, which probes run, call budget, content size limit |
| `rules` | `enabled`, `disabled` (IDs or prefixes), `severity_overrides`, `rules_dirs` |
| `ai` | provider, model, timeouts, retries, call and size budgets, `pricing` for cost estimates |
| `output` | `formats`, `directory`, `show_evidence` |
| `logging` | `level`, `json_format`, `file` |
| `suppressions` | known findings to ignore, each with a reason |
| `servers` | servers to scan when no target is given (same shape as an MCP client config entry) |

## Suppressions

```yaml
suppressions:
  - rule_id: MCP-FS-002          # an ID or a pattern like MCP-FS-*
    server: filesystem           # server name pattern, default "*"
    target: read_file            # tool or target pattern, default "*"
    reason: Limited to the project folder by the server's own config.
    expires: 2027-01-01          # optional; after this date the finding counts again
```

A suppressed finding stays in the JSON report with status `suppressed` and your reason, so reviews can see it.

## Severity overrides

```yaml
rules:
  severity_overrides:
    MCP-PERM-002: medium
```
