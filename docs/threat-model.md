# Threat model

This page lists the attacks the scanner looks for, and the attacks against the scanner itself.

## Attacks against the agent (what we scan for)

| Attack | How it works | Rules |
|---|---|---|
| Prompt injection in metadata | Tool text tells the model to ignore its instructions | MCP-INJ-001, -002, -003, -005 |
| Tool poisoning | Hidden orders in a description: read a secret file, put the chat into a parameter, hide it from the user | MCP-POISON-001 to -007 |
| Line jumping | A description gives orders that apply before any tool is called | MCP-POISON-006, MCP-SHADOW-001 |
| Tool shadowing | One server changes how another server's tool behaves (add a BCC, change a recipient) | MCP-SHADOW-001 to -004 |
| Rug pull | A server changes its tools after you approved them | MCP-DYN-002, MCP-DYN-003, MCP-CFG-001 |
| Output injection | A tool result carries orders for the model | MCP-INJ-004 |
| Secret theft | The server reads environment variables or secret files and returns or sends them | MCP-DYN-001, MCP-SECRET-005, MCP-SECRET-006, MCP-FS-004, MCP-NET-002 |
| Dangerous capability | A tool can run any command, write any file, fetch any URL, run any SQL | MCP-EXEC-001, MCP-FS-001, MCP-NET-001, MCP-SQL-001 |
| Vulnerable code | Tool input reaches a shell, eval, pickle, a file path, a SQL string, or a template | MCP-EXEC-002 to -004, MCP-FS-003, MCP-SQL-002, MCP-SRC-004 |
| Malware | Reverse shells, decoded code, writes to startup files | MCP-SRC-001 to -003, MCP-DYN-004, MCP-DYN-006 |
| Supply chain | Known malicious package versions, typosquats, install scripts | MCP-DEP-001 to -004 |
| Weak setup | Plain text secrets in configs, `curl \| sh` launches, privileged containers, plain HTTP, no auth | MCP-SECRET-002, MCP-CFG-*, MCP-PRIV-002, MCP-AUTH-* |
| Client abuse | The server asks for sampling, roots, or elicitation | MCP-PROTO-001 |

## Attacks against the scanner

The server under test is hostile. It may try to hurt the machine running the scan, or to fool the scan.

| Attack | Defense |
|---|---|
| Run code on the scanning machine | Docker sandbox by default. Process sandbox only with permission. |
| Steal the scanner's secrets | Clean environment allowlist. API keys never reach the server. |
| Steal files from the home folder | Fake home folder with decoys. (The process sandbox cannot stop a determined server from reading real paths. Use Docker.) |
| Hang the scan | Timeouts for startup, each request, each tool call, and the whole server. |
| Exhaust memory or processes | Watchdog limits (process sandbox) or Docker limits. |
| Flood the client | Message size limits, page limits, item limits, a capped stderr buffer. |
| Survive the scan | The whole process tree is killed. Children are found before the parent exits. |
| Send the client somewhere else | SSE endpoints on another host are refused (MCP-PROTO-003). |
| Use the client's model | The client offers no capabilities and refuses sampling. |
| Inject into the AI review | Secrets removed, text fenced with random markers, the AI cannot change results. |
| Hide text from the reviewer | Invisible characters are shown as escapes in reports. |
| Look harmless during the scan | Dynamic relisting, canaries, pins between scans, and source checks. Some servers will still behave differently outside a scan. See [limitations.md](limitations.md). |
| Leave secrets in reports | Evidence is masked, runtime text is scrubbed, env and header values are never shown. |
