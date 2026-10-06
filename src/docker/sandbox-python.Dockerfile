# Optional image for the Docker sandbox, for Python MCP servers that use the official SDK.
#
# The default Python sandbox image has uv and Python but no packages. Servers started
# with `uvx` download what they need (this needs --network allow). Servers started as
# `python server.py` need their packages already installed. This image adds the MCP SDK.
#
# Build:  docker build -f src/docker/sandbox-python.Dockerfile -t aevrin-sandbox-python .
# Use:    mcp-scanner scan "python server.py" --sandbox docker
#         with sandbox.docker_image_python: aevrin-sandbox-python in your config

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
RUN uv pip install --system --no-cache "mcp>=2.3,<3"
# The scanner runs the container as user 65534 (nobody) with a read only file system.
