# Scanning servers that need a key

Many MCP servers only work with a key: a token for your GitHub account, an API key for an online service, or
a sign in. The scanner passes your key to the server the same way your MCP client would. It never prints the
key, never saves it, and never sends it to the AI provider.

## Which method a server uses

| Method | Where the key goes | Scanner option | Example servers |
|---|---|---|---|
| Bearer token (HTTP) | `Authorization: Bearer <token>` header | `--header "Authorization: Bearer $TOKEN"` | GitHub remote MCP, Context7 remote, most hosted servers |
| API key header (HTTP) | a header with the server's own name | `--header "CONTEXT7_API_KEY: $KEY"` | Context7 remote |
| Basic auth (HTTP) | `Authorization: Basic <base64 of user:password>` | `--header "Authorization: Basic $B64"` | self hosted servers |
| MCP OAuth (HTTP) | a bearer token that you get by signing in | sign in with the provider, then `--header "Authorization: Bearer $TOKEN"` | servers that answer 401 with `resource_metadata` |
| API key in the env (stdio) | an environment variable of the server process | `--env NAME=value` | GitHub local (`GITHUB_PERSONAL_ACCESS_TOKEN`), Context7 local (`CONTEXT7_API_KEY`) |
| API key as an argument (stdio) | a command line flag | part of the command: `"npx ... --api-key $KEY"` | Context7 local (`--api-key`) |

Prefer the env or header form. A key on the command line can be seen by other programs on your machine.

When an HTTP server refuses access (HTTP 401 or 403), the scan says which method it asked for, from its
`WWW-Authenticate` answer:

```text
The server at https://example.com/mcp refused access (HTTP 401). It expects a bearer token:
--header 'Authorization: Bearer <token>'.
```

A stdio server without its key usually stops at once. The scan shows its last output, for example
`GITHUB_PERSONAL_ACCESS_TOKEN not set`. Other servers start without the key and fail only when a tool is called.
For those, the report lists the keys the code reads that you did not pass:

```text
note: The code reads these keys from its environment: AUTH_TOKEN, NOTION_TOKEN. They were not passed, so
tools that need them can fail. Pass them with --env NAME=value to test those tools.
```

## Examples

```bash
# GitHub remote MCP server: a personal access token as a bearer token
export GITHUB_MCP_PAT=...            # https://github.com/settings/tokens, read only scopes are enough
mcp-scanner scan https://api.githubcopilot.com/mcp/ --header "Authorization: Bearer $GITHUB_MCP_PAT"

# Context7 remote: the API key in its own header (it also works without a key, with lower limits)
export CONTEXT7_API_KEY=...          # https://context7.com/dashboard
mcp-scanner scan https://mcp.context7.com/mcp --header "CONTEXT7_API_KEY: $CONTEXT7_API_KEY"

# Context7 local (stdio): the API key in the env, in the Docker sandbox with the network on
mcp-scanner scan "npx -y @upstash/context7-mcp@4.1.1" --env CONTEXT7_API_KEY=$CONTEXT7_API_KEY \
  --sandbox docker --network allow --dynamic

# A server from a repository that needs a key: AI setup finds the key name, you pass the value
mcp-scanner scan https://github.com/owner/repo --run --dynamic --network auto --ai-provider groq \
  --env EXAMPLE_API_KEY=...
```

On Windows PowerShell, use `$env:GITHUB_MCP_PAT` instead of `$GITHUB_MCP_PAT`.

## Try it with the test server

`tests/fixtures/servers/auth_server.py` is a small harmless MCP server that needs a key. It supports both
methods: a bearer token over HTTP, and an API key in the env over stdio. The key is whatever you put in
`AUTH_DEMO_TOKEN`.

```bash
# 1. Make a throwaway test key
export AUTH_DEMO_TOKEN=demo-$(python -c "import secrets; print(secrets.token_hex(16))")

# 2. HTTP with a bearer token: start the server, then scan without and with the key
python tests/fixtures/servers/auth_server.py --http 8766 &
mcp-scanner scan http://127.0.0.1:8766/mcp --dynamic                                    # fails: HTTP 401
mcp-scanner scan http://127.0.0.1:8766/mcp --dynamic --header "Authorization: Bearer $AUTH_DEMO_TOKEN"

# 3. stdio with an API key in the env
mcp-scanner scan "python tests/fixtures/servers/auth_server.py" --sandbox process --allow-host --dynamic \
  --env AUTH_DEMO_TOKEN=$AUTH_DEMO_TOKEN
```

Use the Python of the scanner's virtual environment in step 3 (for example `.venv/Scripts/python.exe` on
Windows), because the test server needs the MCP SDK.

## How the key is protected

- **Reports** list only the names: `header_keys: ["Authorization"]` and `env_keys: ["AUTH_DEMO_TOKEN"]`.
  Values are never written.
- **Keys on the command line** (`--api-key VALUE`, `--token=VALUE`, `--password VALUE`, ...) are masked in the
  report target, the server name, recorded child processes, server output, and error messages:
  `--api-key ctx7...(redacted, 38 chars)`.
- **Docker sandbox**: env values reach the server container through the Docker CLI's own environment, so they
  do not show up in the process list. The install container never gets them.
- **AI review and AI setup** see redacted text only. Keys you pass are not part of what is sent.
- **Config files**: when a client config stores a key in plain text (in env, headers, the URL, or an argument
  such as `--api-key VALUE`), MCP-SECRET-002 reports it with the value masked.

After testing with a real key, rotate it if it was ever pasted into a chat, a log, or a shared terminal.
