# Scanning a GitHub repository

You can give the scanner a link to a repository, or a folder you already cloned:

```bash
mcp-scanner scan https://github.com/owner/some-mcp-server
mcp-scanner scan https://github.com/owner/repo/tree/v2.1.0/servers/files    # a tag and a sub folder
mcp-scanner scan ./some-mcp-server                                           # a local folder
```

Supported links: GitHub, GitLab, Bitbucket, Codeberg, `git@host:owner/repo.git`, and any `https://...git` URL.
A link can point at a branch, tag, or commit (`/tree/<ref>`), a sub folder, or one file (`/blob/<ref>/src/server.py`).

## Two ways to scan

| | Default: read the code | `--run`: start the server |
|---|---|---|
| What runs | nothing from the repository | install scripts and the server, inside Docker |
| Needs | git (or nothing, for GitHub) | Docker |
| Tools come from | the source code | the live server |
| Checks | text, tools, source code, dependencies, config | all of the left, plus runtime: rug pulls, canaries, safe tool calls, files written |
| Good for | a first look, servers that need a desktop app or an account, CI | a real test before you trust a server |

## What happens without `--run`

1. **Fetch.** A shallow copy of the one commit goes into `~/.aevrin-mcp-scanner/repos/`. Git runs with code-running
   features turned off: no hooks, no submodules, no LFS filters, and **symlinks become plain files**, so a link
   to `~/.ssh/id_rsa` inside the repository can never make the scanner read your real key. Without git, GitHub
   repositories are downloaded as a zip, and paths that would land outside the folder are skipped.
2. **Find the servers.** In this order: config blocks in the README (`"mcpServers": {...}`), `pyproject.toml`
   scripts, `package.json` `bin` and `main`, then common entry files (`server.py`, `src/server.py`,
   `index.js`, ...) that contain MCP code. If the README names the servers, only those are used. One repository
   can hold several servers, and each one is scanned on its own (named `repo:entry`).
3. **Read the tools from the code.** Python is read with a real parser: `@mcp.tool()`, `@mcp.prompt()`, and
   `@mcp.resource()` decorators (FastMCP and the MCP SDK), parameter types and defaults from the function
   signature, `Field(description=...)`, low-level `Tool(name=..., inputSchema=...)` objects, and the server
   `instructions`. JavaScript and TypeScript are read with patterns: `registerTool`, `server.tool`, and tool
   objects with `name` and `description`. If an entry file only starts the real server through a computed path,
   the scanner looks for the files that create an MCP server and reads those instead.

   When the code shows no tools, two more places are tried:
   - **A tools file the repository ships.** First `tools.json`, `mcp.json`, `server.json`, `testdata/tools.json`,
     `.mcp/tools.json`, `src/tools.json`, `src/mcp.json`, `test/tools.json`, `tools/tools.json`, then any other
     JSON file with a `tools` list (`node_modules`, `package.json`, and `tsconfig` files are skipped). This helps
     when the tool code is generated, minified, or in a language the scanner does not parse.
   - **Go and Rust code**, read with patterns: `mcp.NewTool("name", mcp.WithDescription(...))` and
     `mcp.Tool{Name: ..., Description: ...}` in Go (also when the text is wrapped in a translation call), and
     `#[tool(description = ...)] fn name` in Rust. Test files and `testdata` folders are skipped. These give tool
     names and descriptions, not parameter schemas.
4. **Scan.** Every rule runs as for a live server, except the runtime rules. Source code and dependency checks
   cover the whole server, including other package folders in the repository.

The report says the tools were read from code and nothing was run, and shows the start command the
repository suggests.

## What happens with `--run`

```bash
mcp-scanner scan https://github.com/owner/some-mcp-server --run --dynamic
```

`--run` only works in the Docker sandbox. It refuses to install a repository on your own machine.

1. **Install container** (network on, no secrets, no canaries, its own time limit `timeouts.install`, default
   10 minutes, 4 GB of memory): the repository is copied into a fresh Docker volume, then
   - Python: a virtual environment, `requirements.txt`, and the project itself (`pyproject.toml` or `setup.py`),
   - Node: `npm ci` (or `npm install`), and `npm run build` when the entry file only exists after a build.

   This container uses the full Debian images (`node:22`, `ghcr.io/astral-sh/uv:python3.12-bookworm`), which have
   git and compilers. Many builds need them: install scripts that clone git submodules, native modules. The
   server container still uses the slim images with the same Debian and runtime version.
2. **Server container** (the normal locked sandbox, no network unless `--network allow` or `--network auto`):
   the server is started from that volume. When the project installs a program (a `pyproject.toml` script), that
   program is started, with the virtual environment on `PATH`, the same way `uvx` would start it. The volume is
   writable for this one scan, because many servers write logs or caches next to their code, and it is deleted
   when the scan ends.

Only real MCP servers are started. A README or manifest can name helper programs too (a daemon, a CLI, an
installer). Launches whose code has no MCP server in it are skipped. When a package is listed as an MCP server
(`mcpName` in `package.json`, or a `server.json`), only the program that `npx <package>` runs is started.

TypeScript projects often name their programs by their build output (`"bin": "./build/src/index.js"`), which
does not exist until the project is built. The scanner maps the output back to its source file with the
`tsconfig.json` `outDir` (or the usual `build`, `dist`, `lib`, `out` folders). Code checks read the source file,
and `--run` builds the project and starts the built program. When a bundler makes the program (esbuild,
rollup, webpack), the source is the entry named in the bundler script the `build` script runs (`entryPoints`,
`input`), or the file the `dev` or `start` script runs (`tsx watch scripts/start-server.ts`).

## When automatic setup is not enough: AI setup

Some repositories need more than the common steps: a monorepo with pnpm workspaces, a build step, a special
start command, a stdio flag, or an API key. With an AI provider, the scanner can work this out for you:

```bash
export OPENROUTER_API_KEY=...        # or ANTHROPIC_API_KEY, OPENAI_API_KEY, XAI_API_KEY
mcp-scanner scan https://github.com/owner/repo --run --dynamic --ai-provider openrouter
```

How it works:

1. Automatic setup runs first, as above. It is fast and free, and covers most repositories.
2. When it finds no start command, or the server does not start, the AI gets a short summary of the repository:
   the file list, the README, the manifests (`package.json`, `pyproject.toml`, `Dockerfile`, `.env.example`,
   ...), and the error from the failed attempt. It answers with a plan: install commands, the start command,
   whether the server needs the internet, and which API keys it expects.
3. The plan is checked before use. It must name one program without shell syntax, its install steps cannot
   use `sudo` or pipe a downloaded script into a shell, and it cannot set `PATH`, `HOME`, `LD_PRELOAD`, or
   similar variables. It must also run this repository's code: the start program must be `node`, `python`, or a
   program under `/opt/deps`, and the plan may not install or run the published package of the same name
   (`npx <package>`, `npm install <package>`, `pip install <package>`). Otherwise the scan would test a release
   from the registry, not the commit you asked for. Saved plans are checked again with these rules.
4. The plan runs in the same two containers as above. Install steps run only in the install container (network
   on, no secrets), which already runs the repository's own install scripts. The server runs in the locked
   container.
5. A plan that breaks one of these rules is sent back once, with the reason, so the AI can fix it.
   If the plan fails too, the AI gets that error and one more try. If that fails and automatic setup found a
   start command it did not try yet, automatic setup is used. Only then does the scan stop and report the errors.
6. A plan that works is saved per commit in `~/.aevrin-mcp-scanner/setup-plans/`. The next scan of the same
   commit uses it without an AI call.

| `--ai-setup` (`ai.setup`) | When the AI plans |
|---|---|
| `auto` (default) | only when automatic setup finds nothing or the server does not start. With `--network auto`, the AI is also asked first, but only for advice (see below) |
| `always` | for every repository with `--run`. Automatic setup is the fallback when the plans fail |
| `never` | never. AI review still runs if it is on |

Safety: the repository text is untrusted. Secrets are redacted and the text, including error output, is wrapped
in random markers, the same way as the AI review (see [ai.md](ai.md)). The plan's install commands are shown in
the JSON report under `server.repository.setup`, so you can see exactly what ran.

### API keys and the network

The plan lists the API keys the server expects (`required_env`). Names that appear nowhere in the repository
are dropped, because models sometimes invent them. If you did not pass a key with `--env`, the server gets a
placeholder value, so it can still start and list its tools. Tool calls that need a real key fail.

Without AI too, the report lists the keys the code reads by name (`process.env.NOTION_TOKEN`,
`os.getenv("OPENAI_API_KEY")`) that you did not pass. To test the tools that need them, pass the key:

```bash
mcp-scanner scan https://github.com/owner/repo --run --dynamic --ai-provider openrouter \
  --network auto --env EXAMPLE_API_KEY=...
```

Keys passed with `--env` only reach the server container, never the install container or the AI.

`--network auto` gives the server container the network only when the server needs an online service:

- with AI: when the plan says its tools call an online API (`needs_network`),
- without AI: when the source code makes network calls.

When automatic setup found a start command, the AI plan only advises here: it decides the network and names the
API keys, and automatic setup still installs and starts the server. The plan takes over only if automatic setup
fails. A plan saved by an earlier scan is reused as advice. New advice is not saved, because it was never used to
start the server, so a scan without a saved plan makes one small AI call per server.

The report says whether the network was on and why. When tool calls fail only because the sandbox was offline
(`fetch failed`, `ENOTFOUND`, ...), the report says so and suggests `--network auto` or `--network allow`.

### Speed

- Automatic setup costs nothing and needs no AI.
- An AI plan takes a few seconds. One plan for a mid size repository used about 5,000 to 8,000 input tokens,
  around 1 to 3 US cents with `anthropic/claude-sonnet-5.5`.
- npm and pnpm downloads are cached between scans (install containers only). The second scan of a pnpm
  monorepo took 77 s instead of 257 s.
- When two tool calls in a row time out (the server waits for a desktop app that is not in the sandbox), the
  remaining calls are skipped instead of waiting for each one.

## Example: davinci-resolve-mcp

```bash
mcp-scanner scan https://github.com/samuelgursky/davinci-resolve-mcp
mcp-scanner scan https://github.com/samuelgursky/davinci-resolve-mcp --run --dynamic
```

This repository holds a Python server (`src/server.py`) and a Node server
(`bin/davinci-resolve-advanced-mcp.mjs`). Both are found from the README.

- Without `--run`, the code shows 426 tools for the Python server. That count includes the 389 "granular" tools
  that the code imports for its `--full` mode.
- With `--run`, the live Python server lists its 37 default tools, plus 14 prompts and 9 resources. The Node
  server lists 18 tools. DaVinci Resolve does not run in the sandbox, so tool calls that need it fail. That is
  expected: the scan checks what the server says and does, not video editing.

## Example: superproductivity-mcp (a server that needs a desktop app)

```bash
mcp-scanner scan https://github.com/ben-elliot-nice/superproductivity-mcp --run --dynamic
```

The README and `pyproject.toml` name two programs: the MCP server and a helper daemon. Only the server has MCP
code, so only it is started, through its installed program `superproductivity-mcp`. It lists 16 tools. Its tool
calls wait for the Super Productivity desktop app, which is not in the sandbox, so after two timeouts the other
calls are skipped. Result: completed, grade B (score 3), in about 65 s.

## Example: Context7 (a pnpm monorepo that calls an online API)

```bash
mcp-scanner scan https://github.com/upstash/context7 --run --dynamic --network auto --ai-provider openrouter
```

Automatic setup finds no start command, because the server lives in `packages/mcp` of a pnpm workspace. The AI
setup plan first tried npm, which cannot install `workspace:*` versions. With that error, the second plan ran
pnpm through npx, built the package, and started `packages/mcp/dist/index.js --transport stdio`. The plan said
the tools call an online API, so `--network auto` turned the network on, and both tools answered with real
data. Result: completed, grade B (score 7.2).

## When a scan cannot finish

A scan tries these steps in order and stops at the first one that gives a result:

1. **The live server** (`--run`): automatic setup, then the AI setup plan if you use one.
2. **The tools without running anything.** If the server did not start, its tools are read from the code, a
   tools file, or Go and Rust code (as above), and every tool rule runs on them. The scan is marked partial, the
   start error stays in the report, and a note says where the tools came from.
3. **A public report from an earlier scan.** If the scan still failed or found no tools, the scanner looks for a
   public report of an earlier scan of the same server. A report is only used when its source repository (on
   GitHub) or its npm package matches exactly. It is shown in its own section, "Public report from an earlier
   scan (not made by this scan, not part of its score)", with its grade, version, date, and findings. This scan's
   own status and grade do not change: a failed scan stays failed and its grade stays `?`.
4. **The real error.** If none of this gives anything, the report shows the errors that stopped the scan.

Turn step 3 off with `scan.prescanned_fallback: false`. It needs internet access. Local folders are never looked
up.

## Limits

- Static tool reading can miss tools whose names or descriptions are built at run time (string concatenation,
  loops over data files). It can also show tools that exist in the code but are only turned on by a flag.
  `--run` shows exactly what the server registers.
- Without an AI provider, `--run` follows the common install paths only. With one, the AI setup plan handles
  most other layouts. Servers that need system packages (`apt-get`) cannot be installed, because the install
  container runs without root. Then scan without `--run`, or start the server yourself and scan its command or
  URL.
- Private repositories work when your git can already fetch them (for example over SSH). The scanner never asks
  for a password.
