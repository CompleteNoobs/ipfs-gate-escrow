# archive/ — frozen snapshots of past working-build docs

This directory preserves point-in-time **copies** of build/deploy notes from
working builds, so they are not lost when the live docs get rewritten for a new
platform. Files here are frozen snapshots — the canonical, still-maintained
versions live in the repo root.

## Snapshots

### `pre-nixos-alpine-build-2026-07-29/`
The last **Alpine/Ubuntu-era working-build** deploy recipe for the decoupled escrow
box, captured on 2026-07-29 before the move to a **NixOS** host. In the first NixOS
sandbox the box is co-located with the node and talks to it over a **local strfry
relay** (escrow-protocol/0.1, kind-31337) — the box stays outbound-only, so the
deploy recipe changes for NixOS.

Manifest:
- `walkthrough.wiki` — the Alpine/Docker escrow-box deploy recipe

> Not archived (still canonical, kept live in repo root): `README.md`, and the box
> code (`escrow-box.js`, `nostr-transport.mjs`, `index.js`).
