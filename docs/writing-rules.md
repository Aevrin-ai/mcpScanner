# Writing rules

There are three ways to add a check. Pick the simplest one that works.

| Way | Good for | Can run code |
|---|---|---|
| YAML rule | Words or patterns in tool text | No |
| Built-in Python rule | Anything, using all scan facts | Yes, reviewed with the project |
| Plugin rule | Your own Python rules, shipped as a package | Yes |

## The big idea

**Analyzers collect facts. Rules make findings.** A rule never starts a server or calls the network. It reads
the `ScanContext` and returns `FindingCandidate` objects. The validator and the risk engine do the rest.

What a rule can read from `ctx`:

| Field | What it is |
|---|---|
| `ctx.tools`, `ctx.inventory` | tools, prompts, resources, and server instructions |
| `ctx.surfaces` | every text the agent reads, with its location (`metadata_surfaces`, `dynamic_surfaces`) |
| `ctx.capabilities` | per tool: exec, fs-read, fs-write, network, database, messaging, browser, secrets, with reasons |
| `ctx.source` | source code facts: tool functions and dangerous calls, with taint (or `None`) |
| `ctx.dependencies` | packages from the launch command and project files |
| `ctx.observations` | dynamic facts: tool calls, tool changes, canary hits, protocol events, sandbox events |
| `ctx.spec` | how the server is launched (command, args, env names, URL, headers) |
| `ctx.peer_tools` | tool names of the other servers in the same scan |

## YAML rules

```yaml
# my-rules/internal.yaml
id: CUSTOM-INTERNAL-001
title: Tool mentions an internal host name
severity: medium           # info, low, medium, high, critical
category: data-exfiltration
confidence: high           # low, medium, high
description: A tool talks about a host that should never leave the company network.
recommendation: Check where this tool sends data.
match:
  pattern: "\\b[a-z0-9-]+\\.corp\\.example\\.com\\b"
  surfaces: [tool-description, param-description, tool-output]   # optional
  tool_name: "^billing_"                                          # optional
  case_sensitive: false
```

- One file can hold one rule, or several under `rules:`.
- Surface kinds: `instructions`, `tool-name`, `tool-title`, `tool-description`, `tool-annotation`,
  `param-description`, `param-value`, `param-name`, `prompt-description`, `prompt-argument`, `prompt-text`,
  `resource-description`, `resource-text`, `tool-output`.
- Text is normalized first (lookalike letters folded, invisible characters removed).
- Matches inside quotes, or in text about detecting attacks, get low confidence automatically.
- A rule with the same ID as a built-in rule replaces it.

Check and use them:

```bash
mcp-scanner rules validate my-rules
mcp-scanner scan tools.json --rules-dir my-rules
```

See [src/rules/example-rules.yaml](../src/rules/example-rules.yaml).

## Built-in Python rules

Add a class to a file in `src/mcp_scanner/rules/builtin/`. The registry finds it automatically.

```python
from mcp_scanner.models.finding import Evidence, TargetKind
from mcp_scanner.models.severity import Category, Confidence, Severity
from mcp_scanner.rules.base import Rule


class NoVersionInName(Rule):
    id = "MCP-QUALITY-099"
    title = "Server name has no version"
    category = Category.QUALITY
    severity = Severity.INFO
    description = "The server does not report a version."
    why_it_matters = "Without a version you cannot tell which code you scanned."
    recommendation = "Set a version in the server info."

    def check(self, ctx):
        if ctx.connected and not ctx.inventory.server_version:
            yield self.finding(
                TargetKind.SERVER,
                ctx.spec.name,
                "The server did not report a version.",
                [Evidence.make("protocol", "initialize", "(no version)")],
                confidence=Confidence.HIGH,
            )
```

Checklist for a new rule:

1. One idea per rule. Keep `check()` short. Put shared logic in an analyzer.
2. Always give evidence. Candidates without evidence are dropped.
3. Pick confidence honestly. Low confidence findings score 0 (they are "possible").
4. Set `context_text` to the text just before a text match, so the validator can spot negations.
5. Set `needs = frozenset({NEEDS_SOURCE})` (or `NEEDS_DYNAMIC`) if the rule needs those facts.
6. Add a "must fire" example to `tests/regression/test_every_rule.py`. The test fails if a rule has none.
7. Run `python src/scripts/gen_rules_doc.py` to update [rules.md](rules.md).

## Plugin rules

A separate package can add rules through the `aevrin_mcp_scanner.rules` entry point:

```toml
# your package's pyproject.toml
[project.entry-points."aevrin_mcp_scanner.rules"]
acme = "acme_mcp_rules:RULES"      # a list of Rule classes or instances, or a function returning one
```

A plugin that fails to load is logged and skipped. A rule that crashes during a scan is recorded as a scan
error, and all other rules keep running.
