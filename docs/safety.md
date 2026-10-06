# Safety

Scanning an MCP server is not like scanning a document. To list its tools, the scanner has to start the
server, and starting it runs the server's code. That code may be hostile. This page explains how the scanner
protects you, and what you still need to do yourself.

## The rules the scanner follows

1. **Nothing runs without a sandbox or your clear permission.**
   With Docker running, local servers start in a locked container. Without Docker, the scanner asks first
   (in a terminal) or refuses (in scripts), unless you pass `--allow-host`.
2. **The server never sees your secrets.**
   It gets an empty environment plus a short list of harmless variables (like `PATH`). Your `OPENAI_API_KEY`,
   cloud tokens, and SSH agent are not passed down. Only variables named in the server's own config, or in
   `sandbox.env_passthrough`, are added.
3. **The server gets a fake home folder.**
   It holds decoy files (`.ssh/id_rsa`, `.aws/credentials`, `.env`) with random fake values. The real home
   folder is not touched by a well behaved server, and a hostile one finds only decoys.
4. **Everything is limited.**
   Start time, every request, every tool call, and the whole scan have time limits. Memory, CPU time, number of
   processes, and message size are limited too.
5. **Everything is cleaned up.**
   The whole process tree is killed at the end, including children the server started. The temporary folders
   are deleted.
6. **Dynamic analysis is careful.**
   It is off unless you pass `--dynamic`. Even then, tools that may change something are never called: tools
   that run commands, write files, send messages, query databases, call the network, or are marked destructive.
   Tools whose source code shows such calls are skipped too.
7. **Server text is data, never instructions.**
   This also holds when text is sent to an AI model: secrets are removed first, and the text is wrapped in
   random markers that the model is told never to obey.
8. **The client asks for nothing.**
   The scanner tells the server it supports no extra features. If the server still asks for sampling (using
   your AI model), roots, or elicitation, the scanner refuses and reports it.

## What you still need to do

- **Prefer Docker.** The process sandbox is not a security wall. A hostile server running on your machine can
  still read files your user can read. The Docker sandbox is much stronger.
- **Do not use `--allow-host` for servers you do not trust.** Use it on a throwaway VM, in CI, or inside the
  scanner's own container (see [docker.md](docker.md)).
- **Do not use `--call-dangerous-tools` outside a throwaway sandbox.** It lets dynamic analysis call tools
  that may delete data or send messages.
- **Scan tools files when you can.** `mcp-scanner scan tools.json` runs nothing at all.
- **Use `--no-connect` to audit configs.** It checks client configs, source, and dependencies without starting
  any server.

## Remote servers

For `http://` and `https://` targets nothing runs locally. The scanner only sends MCP requests.
With `--dynamic` it may call tools that look safe. Some remote tools still have side effects on the remote
side (for example a counter or a log). Leave dynamic analysis off for remote servers you do not own.

## Reports and logs

- Reports never show environment or header values, only their names.
- Secrets found by rules are masked (`AKIA...(redacted, 20 chars)`).
- Text the server returned at run time is scrubbed of secrets and planted canary values before it is stored.
- Log messages pass through the same secret filter.
