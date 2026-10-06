# Sandboxing

The scanner has two sandboxes. It picks one per server with `sandbox.mode` (or `--sandbox`):

| Mode | What happens |
|---|---|
| `auto` (default) | Docker when it is running and the command is known (`npx`, `node`, `uvx`, `python`, ...), else the process sandbox |
| `docker` | Always Docker. Fails if Docker is not running |
| `process` | Always the process sandbox. Needs `--allow-host` or your confirmation |

## Docker sandbox

The server runs like this (simplified):

```text
docker run --rm -i --init
  --network none                  no network (sandbox.network: allow or auto to change)
  --read-only                     the image cannot be changed
  --cap-drop ALL                  no special Linux powers
  --security-opt no-new-privileges
  --pids-limit 32 --memory 1024m --cpus 1
  --user 65534:65534              a nobody user
  -v <workspace>/home:/home/sandbox     fake home with decoy secrets
  -v <workspace>/tmp:/tmp
  -v <local script folder>:/mnt/argN:ro read only, only what the command names
  <image> <command> <args>
```

- Images: `node:22-slim` for Node commands and `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` for Python
  commands. Change them with `sandbox.docker_image_node`, `sandbox.docker_image_python`, or force one image with
  `sandbox.docker_image`.
- Environment values travel through the Docker CLI's own environment, so they never show up in the process list.
- The container is removed at the end, even after a crash.
- A missing image is pulled before the server starts, so a slow first download does not count against
  `timeouts.startup`.
- The default Python image has no packages. A server started as `python server.py` (a plain script, not npx,
  uvx, or a repository) that needs the MCP SDK needs `src/docker/sandbox-python.Dockerfile`:

  ```bash
  docker build -f src/docker/sandbox-python.Dockerfile -t aevrin-sandbox-python .
  ```

  ```yaml
  sandbox:
    mode: docker
    docker_image_python: aevrin-sandbox-python
  ```
- Package cache files (`.npm`, `.cache`, uv, yarn) are left out of "files written", so real changes stand out.

### The install step (npx, uvx, pipx run, and `--run` repositories)

Servers that are downloaded when they start would need the network inside the sandbox, and a slow download
would count against the startup time limit. So the Docker sandbox installs them first, in a separate container:

| | Install container | Server container |
|---|---|---|
| Network | on | off (unless `--network allow`, or `--network auto` and the server needs it) |
| Secrets | none: no canaries, no server env | canaries and the server's own env |
| Writes to | a fresh Docker volume for this scan | the fake home, tmp (and the volume, for repositories) |
| Time limit | `timeouts.install` (600 s) | `timeouts.startup` (60 s) |
| Memory | `sandbox.install_memory_mb` (4096 MB), Node heap set to 3/4 of it | `sandbox.memory_mb` (1024 MB) |
| Image (repositories) | full Debian image with git and compilers | slim image, same Debian and runtime |

- `npx -y pkg@1.2.3 args` becomes `npm install pkg@1.2.3`, then `node <the package's program> args`.
- `uvx pkg==1.2.3 args` (and `pipx run`) becomes `uv pip install` into a virtual environment, then that
  environment's program.
- A Docker volume is used instead of a folder on this machine, because Windows and macOS share folders with
  containers slowly: an npm install with 6,600 files took 53 s into a shared folder and 6 s into a volume.
- npm downloads are kept in a shared cache that only install containers can see. npm checks every package
  against its sha512 integrity hash when it reads the cache, so one scan cannot plant a changed package for a
  later one. pnpm keeps its store in the same place and checks file integrity before it links a file. uv does
  not check this way, so there is no uv cache.
- An AI setup plan (`--run` with an AI provider) runs its install commands here too, and nowhere else.
- Package names from the command are passed to the shell quoted, so a name cannot add shell commands.
- The volume and every container are removed at the end of the scan, also after errors.
- If a scan is killed before it can clean up (the terminal is closed), its volume stays. The next Docker
  install removes such volumes once they are more than an hour old and no container uses them.

Install scripts (for example npm `postinstall`) do run, but only in the install container, which holds nothing
worth stealing. They are also reported by MCP-DEP-003 when the project files are available.

What the Docker sandbox does not see: processes and network connections inside the container. Docker enforces
the limits, but runtime rules that need the process list (MCP-DYN-004, MCP-DYN-005) only work with the process
sandbox. Files written to the fake home folder are still seen (MCP-DYN-006).

## Process sandbox

The server runs as a normal child process of the scanner:

- Clean environment (an allowlist of harmless variables) and a fresh temporary home, temp, and work folder.
- `HOME`, `USERPROFILE`, `APPDATA`, `XDG_*`, and `TMP` point into the workspace.
- A watchdog thread checks the process tree every half second: memory, CPU time, number of processes, and new
  network connections. It records every child process and connection, labelled with the scan phase
  (`startup`, `listing`, `probing`).
- On Linux and macOS the server leads its own process group, gets a CPU time limit, and core dumps are off.
- At the end, the whole tree is stopped: first politely, then by force. Children are found before the parent
  exits, because on Windows they cannot be found through the parent afterwards.

**It is not a security wall.** The server runs as your user and can read any file your user can read, if it
knows where to look. Use it for servers you trust, on a throwaway machine, or inside a container.

## The workspace

Every server gets its own folder in the system temp folder, named `aevrin-scan-*`:

```text
aevrin-scan-xxxx/
  home/   fake home: .ssh/id_rsa, .aws/credentials, .env, .config/gh/hosts.yml (all fake, with canary values)
  tmp/
  work/   the server's working folder
```

The scanner compares the folder before and after the scan to see which files the server wrote. Writes to
startup files (`.bashrc`, `.ssh/authorized_keys`, autostart folders) are reported as MCP-DYN-006.
The folder is deleted at the end. Keep it for debugging with `sandbox.keep_workspace: true`.

## Canaries

A canary is a random fake secret. The scanner plants two:

- `SERVICE_API_TOKEN` in the server environment (a name that secret stealing code likes to grab),
- the same kind of value inside the decoy files in the fake home folder.

If a canary value ever appears in a tool result, a prompt, a resource, the server instructions, or a tool
definition, the server read a secret it was never asked for and handed it to the agent. That is reported as
MCP-DYN-001 with status `confirmed`. Canary values are removed from reports.
