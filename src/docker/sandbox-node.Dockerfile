# Optional image for the Docker sandbox, for Node MCP servers.
#
# It is the default node image with a writable npm cache folder prepared for the
# sandbox user, plus a pre-downloaded copy of the servers you name in SERVERS, so a
# scan can run with --network none.
#
# Build:  docker build -f src/docker/sandbox-node.Dockerfile \
#           --build-arg SERVERS="@modelcontextprotocol/server-everything@2026.8.31" \
#           -t aevrin-sandbox-node .
# Use:    sandbox.docker_image_node: aevrin-sandbox-node in your config

FROM node:22-slim
ARG SERVERS=""
ENV npm_config_cache=/opt/npm-cache
RUN mkdir -p /opt/npm-cache \
 && if [ -n "$SERVERS" ]; then for s in $SERVERS; do npm cache add "$s"; done; fi \
 && chmod -R a+rX /opt/npm-cache
