// ── ipfs-gate-escrow/index.js — the money-box boot entrypoint ─────────────────
//
// Runs the isolated ipfs-gate escrow box (the SETTLEMENT AUTHORITY). On its own minimal
// host this is the ONLY process that holds the active key (IPFS_GATE_ACTIVE_KEY) and
// the only place a disbursement is computed and signed. It opens its OWN durable ledger,
// trusts reports only from the node reporting-key(s) in ESCROW_EXPECTED_REPORTERS, and
// settles each claim's verified on-chain envelope (see escrow-box.js for the safety proof).
//
// GUARDRAIL: no Claude / no dev tooling on a real-funds box. Operate via logs + SSH.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const escrowCore = require('escrow-core');
const { createEscrowBox } = require('./escrow-box');

function reqEnv(name) {
  const v = (process.env[name] || '').trim();
  if (!v) { console.error(`[escrow-box] FATAL: ${name} is required`); process.exit(1); }
  return v;
}

// The box's escrow-reporting key (schnorr): signs settlement-receipts AND the Nostr events
// it publishes. Persisted so its pubkey is stable (the node pins it to verify receipts).
function loadOrCreateBoxKey(keyPath) {
  try {
    const j = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    if (/^[0-9a-f]{64}$/i.test(j.sk_hex || '')) return j.sk_hex.toLowerCase();
    throw new Error('sk_hex missing/invalid');
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn(`[escrow-box] ${keyPath}: ${e.message} — generating a fresh key`);
    const skHex = crypto.randomBytes(32).toString('hex');
    const pubkey = escrowCore.getReportingPubkey(skHex);
    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
    fs.writeFileSync(keyPath, JSON.stringify({ sk_hex: skHex, pubkey, created_at: new Date().toISOString() }, null, 2), { mode: 0o600 });
    console.log(`[escrow-box] generated box reporting key → ${keyPath} (pubkey ${pubkey})`);
    return skHex;
  }
}

async function main() {
  const account  = process.env.ESCROW_ACCOUNT || process.env.IPFS_GATE_HIVE_ACCOUNT || '';
  if (!account) { console.error('[escrow-box] FATAL: ESCROW_ACCOUNT (or IPFS_GATE_HIVE_ACCOUNT) is required'); process.exit(1); }
  const currency = (process.env.ESCROW_CURRENCY || process.env.PAYMENT_CURRENCY || 'CNOOBS').toUpperCase();
  const keyEnv   = 'IPFS_GATE_ACTIVE_KEY';
  reqEnv(keyEnv);                                  // the active key MUST be present on the box
  const feeAccount = (process.env.FEE_ACCOUNT || '').trim() || null;  // optional: only single-payment fees use it
  const dbPath   = process.env.ESCROW_DB_PATH || path.join(__dirname, 'data', 'ipfs-gate-escrow.db');
  const keyPath  = process.env.ESCROW_KEY_PATH || path.join(__dirname, 'data', 'escrow-reporting-key.json');
  const relays   = (process.env.NOSTR_RELAYS || '').split(',').map(s => s.trim()).filter(Boolean);
  const reporters = (process.env.ESCROW_EXPECTED_REPORTERS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  // Box-authoritative settlement knobs (the node's quote-side env must match; on
  // divergence THESE win — document in both .env.examples):
  //   GUARDIAN_CANCEL_FEE_PCT  dormant-guardian anti-churn fee % (monolith default 0)
  //   MIN_REFUND               dust floor below which a refund is retained (default 0.05)
  // Both are read by escrow-core/pricing.js at require time and surfaced through the
  // adapter; set them in the environment BEFORE this process starts.

  if (reporters.length === 0) { console.error('[escrow-box] FATAL: ESCROW_EXPECTED_REPORTERS is required (fail-closed: a money box must know which node key(s) it trusts)'); process.exit(1); }
  if (!reporters.every(r => /^[0-9a-f]{64}$/.test(r))) { console.error('[escrow-box] FATAL: ESCROW_EXPECTED_REPORTERS must be 64-hex schnorr pubkeys'); process.exit(1); }

  // Non-native token precision must be locked explicitly (Decision #3).
  if (currency !== 'HBD' && currency !== 'HIVE') {
    const p = parseInt(process.env.ESCROW_TOKEN_PRECISION || '', 10);
    if (!Number.isInteger(p)) { console.error(`[escrow-box] FATAL: ESCROW_TOKEN_PRECISION required for non-native currency ${currency}`); process.exit(1); }
    escrowCore.registerPrecision(currency, p);
  }

  const boxSkHex = loadOrCreateBoxKey(keyPath);
  const boxPub   = escrowCore.getReportingPubkey(boxSkHex);
  const adapter  = escrowCore.createIpfsGateAdapter({ account, currency, keyEnv });
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const ledger   = escrowCore.openLedger(dbPath, { adapterMigrations: adapter.ledgerMigrations() });

  const { createNostrTransport } = await import('./nostr-transport.mjs');
  const log = (lvl, msg) => console[lvl === 'error' ? 'error' : 'log'](`[escrow-box] ${msg}`);
  const transport = relays.length
    ? createNostrTransport({ relays, selfSkHex: boxSkHex, log })
    : null;
  if (!transport) console.warn('[escrow-box] NOSTR_RELAYS empty — running WITHOUT a transport (recovery-only/diagnostic mode)');

  const box = createEscrowBox({
    escrowCore, ledger, adapter,
    config: { account, currency, keyEnv, feeAccount, expectedReporters: reporters },
    boxSkHex,
    deps: { transport },          // getTransaction/broadcastClient default to LIVE chain
    log,
  });

  await box.start();
  console.log(`[escrow-box] escrow-core ${escrowCore.version} ready: @${account} (${currency}) · ledger ${dbPath}`);
  console.log(`[escrow-box]   box reporting pubkey: ${boxPub}   ← the node must pin this (ESCROW_BOX_PUBKEY) to verify receipts`);
  console.log(`[escrow-box]   trusts ${reporters.length} reporter key(s); cancel fee ${adapter.cancelFeePct}% · dust floor ${adapter.minRefund}; ${relays.length} relay(s)`);

  const shutdown = () => { try { if (transport) transport.close(); ledger.close(); } catch {} process.exit(0); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch(e => { console.error('[escrow-box] FATAL:', e); process.exit(1); });
