# ipfs-gate-escrow

The **isolated ipfs-gate escrow money box** — the settlement authority for the decoupled
ipfs-gate stack. Wraps the shared [escrow-core](https://github.com/CompleteNoobs/escrow-core)
library; holds the **only** copy of the escrow account's active key plus its own durable
ledger. The gate node ([ipfs-gate-node](https://github.com/CompleteNoobs/ipfs-gate-node))
is a keyless reporter: it sends signed `event-report` messages over escrow-protocol/0.1
(Nostr kind-31337, inner schnorr signature is the trust gate) and finalizes on the box's
signed `settlement-receipt`.

> **Status: Phase 2 BUILT** (adapted from
> [v4call-escrow](https://github.com/CompleteNoobs/v4call-escrow) @`946c7a6`): claim-settle
> dispatch via `escrow-core/adapters/ipfs-gate.js`, owner-is-payer guard, memo-probe
> disburse recovery, completion receipts, Dockerfile + compose (NEW — v4call's box is
> bare OpenRC only). 20/20 box tests + 11/11 adversarial dry-run green (`npm test`,
> `npm run dry-run`). Next per `../decoupling-notes/ipfs-gate-split-plan.md`: Phase 3
> node flip, Phase 4 LXC integration.

Two money invariants (inherited from escrow-core, originally extracted from ipfs-gate itself):

1. `payments.tx_id UNIQUE` — replay guard; every escrowed payment is independently
   re-verified on-chain before any disbursement.
2. Settlement cap — `settlement = min(meteredUsage, verified deposit)`; a lying report can
   only re-split the verified envelope between refund-to-owner and retained-by-escrow,
   never mint, never pay a third party.

Deployment shapes (Phase 2+): bare OpenRC on a minimal Alpine host (the v4call-proven
path, `walkthrough.wiki`) **or** Docker (new in this repo). Real-funds production is
strongly recommended on its own host, separate from the gate node. Never install
Claude/dev tooling on a real-funds box.
