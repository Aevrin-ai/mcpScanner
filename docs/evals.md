# Evals

Evals measure how well the scanner works. Without numbers, nobody knows if a rule change made things better or
worse.

```bash
mcp-scanner eval --allow-host                 # all cases
mcp-scanner eval --case poisoned-server       # one case
mcp-scanner eval --allow-host --ai-provider anthropic --ai   # include AI review and its cost
```

`--allow-host` is needed because the eval servers start as local processes. They are the small fixture servers
in this repository (`src/evals/servers`, `tests/fixtures/servers`). They are hostile on purpose but only touch the
scanner's fake home folder and never make real network requests.

Results are written to `src/evals/reports/eval-<time>.json` and `.md`.

## The data set

```text
src/evals/
  cases/<name>/case.yaml     one case per folder
  servers/                   real MCP servers built with the official MCP SDK
  tools/                     offline tools files
  configs/                   MCP client config files (scanned with --no-connect)
  projects/                  a server project with dependency files
```

It has both bad and good cases, so false positives are measured too:

| Kind | Cases |
|---|---|
| bad | tool poisoning, rug pull, secret theft (canary), command injection, hidden Unicode, output injection, persistence, poisoned tools file, leaky tools file, risky client config, supply chain project |
| good | careful file server, prompt injection detector (talks about attacks), safe notes server, normal developer tools file, clean client config |

## A case file

```yaml
name: rug-pull-server
description: A harmless tool swaps in a poisoned definition after its first call.
malicious: true                 # true: a user should be warned about this server
target: "{python} {root}/servers/rug_pull_server.py"
source: "{root}/servers/rug_pull_server.py"     # optional
dynamic: true
connect: true                   # false: --no-connect
expect:
  must_find: [MCP-DYN-002, MCP-INJ-001]          # IDs or prefixes
  must_not_find: [MCP-EXEC]
  min_grade: D                  # at least this bad
  max_grade: B                  # at most this bad (good cases)
  allow: [MCP-QUALITY]          # good cases: these do not count as false positives
```

`{python}` is the Python running the scanner, `{root}` is the evals folder.

## The numbers

Rule level:

- **True positive**: an expected rule fired.
- **False negative**: an expected rule did not fire.
- **False positive**: a `must_not_find` rule fired, or, in a good case, any medium or higher finding with
  medium or high confidence that is not in `allow`.
- **Precision** = TP / (TP + FP). **Recall** = TP / (TP + FN).

Server level:

- A server is **flagged** when its grade is D or F, or it has a high or critical finding with medium or high
  confidence.
- **Detection rate** = flagged bad cases / bad cases. **False negative rate** = 1 - detection rate.
- **False positive rate** = flagged good cases / good cases.

Also reported: average confidence of true positives, run time per case, and AI calls, tokens, and cost.

A case **passes** when it has no false negatives, no false positives, and its grade is inside the expected range.

## Honest limits

These cases were written together with the scanner, so a perfect score here does not prove the scanner finds
everything in the wild. Treat the eval as a regression guard: it tells you when a change breaks something that
used to work. Add a case every time you find a miss or a false alarm on a real server.
