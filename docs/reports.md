# Reports

All formats are made from the same `ScanReport`. Reporters never compute anything new, so every format says
the same thing.

| Format | Flag | File | Best for |
|---|---|---|---|
| Console | `-f console` (default) | none | reading in a terminal |
| JSON | `-f json` or `--json` | `mcp-scan-<id>.json` | the full record, automation, re-rendering later |
| Markdown | `-f markdown` | `mcp-scan-<id>.md` | pull requests, tickets, wikis |
| SARIF 2.1.0 | `-f sarif` | `mcp-scan-<id>.sarif` | GitHub code scanning and other CI tools |

```bash
mcp-scanner scan tools.json -f json -f markdown -f sarif -o reports
mcp-scanner report reports/mcp-scan-abc123.json -f markdown     # convert later
```

## What every finding has

| Field | Meaning |
|---|---|
| `id` | stable ID (`F-` plus a hash), the same in every scan of the same server |
| `rule_id`, `title` | which rule found it |
| `severity` | how bad it is if real: info, low, medium, high, critical |
| `confidence` | how sure we are: low, medium, high |
| `validation_status` | confirmed, validated, unverified, likely-false-positive, suppressed |
| `target_kind`, `target_name` | tool, prompt, resource, server, config, source, or dependency, and its name |
| `description`, `why_it_matters`, `attack_scenario`, `recommendation` | plain words |
| `evidence` | up to five pieces of proof: kind, location, short snippet |
| `risk_points` | points this finding added to the score |
| `malicious` | the evidence shows hostile intent, not just risk |
| `validation_notes` | what the validator did (negation, corroboration, suppression) |
| `ai_review` | the AI verdict, if AI review ran |

## JSON layout

```text
{
  "schema_version": "1.0",
  "scanner", "scanner_version", "scan_id", "started_at", "finished_at", "duration_seconds",
  "status": "completed | partial | failed",
  "options": {...},                     the settings used, without secrets
  "summary": {"servers", "severity_counts", "worst_severity"},
  "servers": [
    {
      "server": {"name", "transport", "target", "env_keys", "header_keys", "origin", "source_path"},
      "status", "summary": {"is_safe": true | false | null, ...},
      "inventory": {tools, prompts, resources, instructions, ...},
      "findings": [...],
      "risk": {"score", "grade", "label", "factors": [...], "notes": [...]},
      "observations": {tool_calls, skipped_tools, tool_changes, canary_hits, protocol_events, sandbox},
      "ai": {...}, "errors": [...], "rules_run": [...], "stage_seconds": {...}
    }
  ],
  "ai_usage": {...}, "errors": [...]
}
```

`is_safe` has three values: `true` (no findings of low or higher, scan complete), `false` (findings),
and `null` (the scan was incomplete, so we do not know).

## SARIF notes

- `level`: critical and high are `error`, medium is `warning`, low and info are `note`.
- `properties.security-severity` lets GitHub rank alerts (critical 9.5, high 8.0, medium 5.5, low 3.0).
- Source code and dependency findings point to the file and line. Config findings point to the config file.
  Tool findings use a logical location `server/tool/name`.
- Suppressed and likely false positive findings carry a SARIF `suppressions` entry with the reason.
