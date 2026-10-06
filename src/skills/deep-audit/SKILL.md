---
name: deep-audit
description: Full audit of one MCP server with dynamic analysis, source code checks, and all report formats.
version: 1.0.0
tags: [scan, dynamic, audit]
inputs:
  target:
    description: Command, URL, MCP client config file, or tools JSON file to scan.
    required: true
  source:
    description: Folder with the server source code, for code checks. Leave empty if you do not have it.
    default: ""
  output:
    description: Folder for the report files.
    default: reports
workflow:
  - name: Dynamic scan
    action: scan
    with:
      target: "${inputs.target}"
      source: "${inputs.source}"
      dynamic: true
      min_severity: info
      fail_on: high
      formats: [console, json]
      output: "${inputs.output}"
  - name: Write Markdown and SARIF reports
    action: report
    with:
      formats: [markdown, sarif]
      output: "${inputs.output}"
---

# Deep audit

Use this skill before you trust a new MCP server, or when a quick scan found something you want to understand.

## What it does

1. Runs every static rule.
2. Reads the server source code, if you give it, and follows tool input into dangerous calls.
3. Turns on dynamic analysis:
   - lists the tools again to catch definitions that change during a session ("rug pull"),
   - reads prompts and text resources,
   - calls only tools that look safe, with harmless inputs,
   - checks if planted fake secrets come back,
   - records processes, network connections, and files written in the sandbox.
4. Writes JSON, Markdown, and SARIF reports.

Tools that may change things (run commands, write files, send messages, query databases, call the network) are never called by this skill.

## How to run it

```bash
mcp-scanner skills run deep-audit \
  --input target="python server.py" \
  --input source=./server-src \
  --input output=./audit
```

Without Docker you also need `--allow-host`, because the server then runs on your machine.

## How to read the result

- `confirmed` findings are proven by behavior. Treat them as real.
- `validated` findings have strong evidence.
- `unverified` findings are heuristic. A person should look.
- The "Why this score" table lists every risk point.
