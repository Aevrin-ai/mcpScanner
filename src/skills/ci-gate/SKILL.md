---
name: ci-gate
description: Scan an MCP server in CI and fail the build on high findings. Writes SARIF for code scanning.
version: 1.0.0
tags: [ci, sarif]
inputs:
  target:
    description: Command, URL, MCP client config file, or tools JSON file to scan.
    required: true
  source:
    description: Folder with the server source code.
    default: ""
  fail_on:
    description: Lowest severity that fails the build.
    default: high
  output:
    description: Folder for the report files.
    default: mcp-scan-results
workflow:
  - name: Scan for CI
    action: scan
    with:
      target: "${inputs.target}"
      source: "${inputs.source}"
      dynamic: false
      fail_on: "${inputs.fail_on}"
      formats: [json, sarif]
      output: "${inputs.output}"
---

# CI gate

Use this skill in a CI pipeline, so a pull request that adds a risky tool fails before it is merged.

## What it does

1. Runs a static scan, plus source code checks when you give the source folder.
2. Writes a JSON report and a SARIF file.
3. Exits with code 1 when a finding is at or above `fail_on`, and code 2 when the scan itself failed.

## Example (GitHub Actions)

```yaml
- run: pip install aevrin-mcp-scanner
- run: mcp-scanner skills run ci-gate --input target=tools.json --input source=src --allow-host
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: mcp-scan-results
```

Scanning a saved `tools.json` (the answer of `tools/list`) needs no server process at all, which is the safest option in CI.
