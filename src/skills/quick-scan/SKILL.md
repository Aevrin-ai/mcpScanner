---
name: quick-scan
description: Static scan of one MCP server. Fast, no tool calls, good first look.
version: 1.0.0
tags: [scan, static]
inputs:
  target:
    description: Command, URL, MCP client config file, or tools JSON file to scan.
    required: true
  fail_on:
    description: Exit with code 1 when a finding is at or above this severity.
    default: high
workflow:
  - name: Static scan
    action: scan
    with:
      target: "${inputs.target}"
      dynamic: false
      fail_on: "${inputs.fail_on}"
      formats: [console, json]
---

# Quick scan

Use this skill when you want a fast first look at one MCP server.

## What it does

1. Starts or connects to the server (in the Docker sandbox when possible).
2. Lists its tools, prompts, and resources.
3. Runs every static rule: hidden instructions, dangerous tools, secrets, config problems, and supply chain checks.
4. Prints the result and writes a JSON report.

It never calls the server's tools.

## How to run it

```bash
mcp-scanner skills run quick-scan --input target="python server.py"
```

## How to read the result

- Start with critical and high findings.
- "Possible" findings (low confidence) add no risk points. Look at them only if you have time.
- A grade of D or F means: do not connect this server to an agent until you understand every high finding.
