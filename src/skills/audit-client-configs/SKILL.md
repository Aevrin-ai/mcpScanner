---
name: audit-client-configs
description: Find every MCP client config on this computer and scan all servers in them.
version: 1.0.0
tags: [discover, scan]
inputs:
  output:
    description: Folder for the report files.
    default: reports
workflow:
  - name: Find client configs
    action: discover
  - name: Scan all configured servers
    action: scan
    with:
      discover: true
      dynamic: false
      fail_on: high
      formats: [console, json, markdown]
      output: "${inputs.output}"
---

# Audit client configs

Use this skill to check all MCP servers your AI apps use: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Zed, and more.

## What it does

1. Looks in the known config file locations of popular MCP clients. It only reads them.
2. Scans every server it finds, with static rules.
3. Also checks how each server is configured: plain text secrets, unpinned packages, shell wrappers, risky environment variables.
4. Compares tool names across servers, to catch one server copying another server's tool names.

## How to run it

```bash
mcp-scanner skills run audit-client-configs
```

Local servers start in the Docker sandbox when Docker is running. Otherwise you are asked before each server runs on your machine.

## What to do next

- Rotate any secret reported by MCP-SECRET-002 and move it to an environment variable.
- Pin package versions reported by MCP-CFG-001.
- Remove servers with grade D or F, or run `deep-audit` on them.
