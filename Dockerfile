# ── ipfs-gate-escrow Dockerfile (the money box) ──────────────────────────────
# NEW in the ipfs-gate decoupling: v4call's box runs bare OpenRC on Alpine with no
# Dockerfile; this image exists so the box can ALSO run as a container — the
# single-server combined profile (ipfs-gate-node compose `--profile escrow`) and
# container-based VPS deploys. Same guardrails either way: the env_file holding
# IPFS_GATE_ACTIVE_KEY lives only on the box host; no ports are exposed (the box
# makes only OUTBOUND connections: HTTPS to Hive RPC, WSS to the Nostr relay).
FROM node:20-alpine

# Build tools for better-sqlite3's native module.
RUN apk add --no-cache python3 make g++ sqlite

WORKDIR /app

COPY package.json ./

# escrow-core is a sibling dependency (`file:../escrow-core` in package.json) and
# lives OUTSIDE this build context. `npm run docker:prep` vendors a clean source
# snapshot into ./vendor/escrow-core; we place it at /escrow-core — a sibling of
# /app — so the UNCHANGED `file:../escrow-core` path resolves at install time
# exactly as on bare metal.
COPY vendor/escrow-core /escrow-core

# --install-links is REQUIRED: it packs the file: dependency into a real directory
# in node_modules instead of a symlink (a symlink would resolve escrow-core's own
# deps from /escrow-core, which has no node_modules in the image → boot crash).
RUN npm install --omit=dev --install-links

COPY index.js escrow-box.js nostr-transport.mjs ./

# Ledger DB + persisted box reporting key live under /app/data.
RUN mkdir -p /app/data && chown -R node:node /app/data

VOLUME ["/app/data"]

# NO EXPOSE — the box listens on nothing. Outbound-only by design.

USER node

CMD ["node", "index.js"]
