# Aevrin MCP Scanner in a container.
#
# Inside this image the container itself is the sandbox: servers run as child
# processes of the scanner (process sandbox), as a non-root user, with no access
# to your real home folder. That is why AEVRIN_SANDBOX_ALLOW_HOST is true here.
# Never set it to true on your own machine unless you trust the server.
#
# Build:  docker build -t aevrin-mcp-scanner .
# Use:    docker run --rm aevrin-mcp-scanner scan /work/tools.json
# More:   docs/docker.md
#
# License: PolyForm Noncommercial 1.0.0. Commercial use needs a license key, given at
# run time and never baked into the image: a Docker secret at /run/secrets/aevrin_license,
# or the AEVRIN_LICENSE variable. See docs/licensing.md. No private signing key is ever
# part of this image. Official images are signed with cosign by the release workflow.

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE COMMERCIAL-LICENSE.md TRADEMARKS.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Aevrin MCP Scanner" \
      org.opencontainers.image.description="Find security problems in MCP servers and tools." \
      org.opencontainers.image.vendor="Aevrin" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Node.js (for npx servers), uv (for uvx servers), and git (for repository links).
# GitHub links also work without git (zip download), other hosts need it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs npm ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[ai,servers]" && rm /tmp/*.whl

COPY LICENSE NOTICE COMMERCIAL-LICENSE.md TRADEMARKS.md /usr/share/doc/aevrin-mcp-scanner/

RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /work

ENV AEVRIN_SANDBOX_MODE=process \
    AEVRIN_SANDBOX_ALLOW_HOST=true \
    AEVRIN_OUTPUT_DIR=/work/reports \
    AEVRIN_LICENSE_FILE=/run/secrets/aevrin_license \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["mcp-scanner"]
CMD ["--help"]
