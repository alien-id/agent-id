# Alien Agent ID — vault p2p sync full e2e image.
#
# One image serves every container (sso + device-a/b/c). It carries the raw
# plugin sources, examples/dev-sso.mjs, socat (for the loopback SSO forward),
# and curl (health polling). No build step: the plugins are pure ESM .mjs.
#
# Build context is the REPO ROOT (see docker-compose.yml `build.context: ../..`)
# so we can COPY plugins/ + examples/. The send list is trimmed by the
# per-Dockerfile ignore file `Dockerfile.dockerignore` next to this file
# (BuildKit convention) — NOT a root-level .dockerignore.

FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends socat curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Only the pieces the CLIs and dev-sso need. examples/ is required in the sso
# container (dev-sso.mjs) and harmless elsewhere — one image is simplest.
COPY plugins/agent-id-core   /app/plugins/agent-id-core
COPY plugins/agent-id-vault  /app/plugins/agent-id-vault
COPY examples/dev-sso.mjs    /app/examples/dev-sso.mjs

# Cross-plugin bare-specifier resolution (@alien-id/agent-id-core/lib/*.mjs).
# The plugins are zero-external-dep pure JS, so a single symlink is sufficient
# at runtime — no `npm install` / `bun install` needed. dev-sso.mjs imports
# core via a RELATIVE path, and core never bare-imports itself, so vault is the
# only consumer that needs the link.
RUN mkdir -p /app/plugins/agent-id-vault/node_modules/@alien-id \
  && ln -s ../../../agent-id-core \
       /app/plugins/agent-id-vault/node_modules/@alien-id/agent-id-core

# Scenario runner + shared shell helpers.
COPY tests/e2e-docker/lib.sh          /app/e2e/lib.sh
COPY tests/e2e-docker/sso-entry.sh    /app/e2e/sso-entry.sh
COPY tests/e2e-docker/device-entry.sh /app/e2e/device-entry.sh
COPY tests/e2e-docker/scenario.sh     /app/e2e/scenario.sh
RUN chmod +x /app/e2e/*.sh

ENV AGENT_ID_STATE_DIR=/state
ENV SSO_ISSUER_URL=http://127.0.0.1:5050
