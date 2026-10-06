# Docker

Docker is used in two different ways. Do not mix them up.

1. **The Docker sandbox**: the scanner runs on your machine and starts each local MCP server in its own locked
   container. This is the default when Docker is running. See [sandboxing.md](sandboxing.md).
2. **The scanner in a container**: the whole scanner runs inside a container. Servers then run as child
   processes inside that container, which is the sandbox. This page is about this second way.

## Build

```bash
docker build -t aevrin-mcp-scanner .
```

The image has Python 3.12, the scanner with AI support and the MCP SDK, Node.js and npm (for `npx` servers),
and uv (for `uvx` servers). It runs as a non-root user (`scanner`, uid 10001).

Inside the image `AEVRIN_SANDBOX_MODE=process` and `AEVRIN_SANDBOX_ALLOW_HOST=true` are set, because the
container itself is the security boundary. Never copy these settings to your own machine.

## Run

On Windows with Git Bash, put `MSYS_NO_PATHCONV=1` in front of `docker run`. Otherwise Git Bash rewrites
container paths like `/work/targets` into Windows paths. PowerShell and cmd do not need this.

```bash
# A tools file (nothing starts, no network needed)
docker run --rm --network none -v "$PWD:/work/targets:ro" aevrin-mcp-scanner scan /work/targets/tools.json

# A server from npm (needs the network to download it)
docker run --rm -v "$PWD/reports:/work/reports" aevrin-mcp-scanner \
  scan "npx -y @modelcontextprotocol/server-everything@2026.8.31" --dynamic -f json -o /work/reports

# With AI review (the key comes from your shell, it is never stored in the image)
docker run --rm -e OPENROUTER_API_KEY -v "$PWD:/work/targets:ro" aevrin-mcp-scanner \
  scan /work/targets/tools.json --ai-provider openrouter
```

## Compose

`compose.yaml` runs the scanner with locked down settings: read only root file system, all capabilities
dropped, `no-new-privileges`, process, memory, and CPU limits, and small `tmpfs` folders for `/tmp` and home.

```bash
mkdir -p targets reports
cp tools.json targets/
docker compose run --rm scanner scan /work/targets/tools.json -f markdown -o /work/reports
docker compose run --rm evals                      # run the eval suite with no network
```

A `.env` file next to `compose.yaml` is passed in, for AI keys.

## Optional sandbox images

`src/docker/` has two images for the Docker sandbox (the first way above):

- `src/docker/sandbox-node.Dockerfile`: Node with npm packages downloaded ahead of time, so servers can start with
  `--network none`.
- `src/docker/sandbox-python.Dockerfile`: Python with the MCP SDK, for `python server.py` style servers.

Point the scanner at them with `sandbox.docker_image_node` and `sandbox.docker_image_python`.

## CI

See [src/examples/github-actions.yml](../src/examples/github-actions.yml) for a GitHub Actions job that scans a tools
file and the source code, fails on high findings, and uploads SARIF.
