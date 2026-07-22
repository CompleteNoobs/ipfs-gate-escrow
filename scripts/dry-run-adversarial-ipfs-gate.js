#!/usr/bin/env node
// ── dry-run-adversarial-ipfs-gate.js — the box's guards proven against a REAL ledger ──
// Companion to escrow-core/scripts/dry-run-adversarial.js, driven through the
// ipfs-gate adapter + the real escrow-box, with a mock chain + mock broadcast +
// throwaway never-funded key (no network, no funds at risk). Run before ANY
// deployment that will touch real value:   node scripts/dry-run-adversarial-ipfs-gate.js
//
// The two mandatory invariants (v4call decoupling gate) plus the ipfs-gate guards:
//   #1 replay-reject          — a settled ref/nonce/tx can never settle twice
//   #2 crash-no-double-disburse — a box killed mid-settlement recovers EXACTLY one refund
//   #3 conservation           — a lying report only re-splits the verified envelope
//   #4 fail-closed gates      — unauthorized silence, forged-payment drop, owner-is-payer

'use strict';

const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const dhive = require('@hiveio/dhive');

const escrowCore = require('escrow-core');
const { createEscrowBox } = require('../escrow-box');

const NOW = 1_800_000_000_000;
const HOUR_MS = 60 * 60 * 1000;
const KEY_ENV = 'TGATE_DRYRUN_KEY';
const THROWAWAY_KEY = dhive.PrivateKey.fromSeed('ipfs-gate-escrow-dry-run').toString();

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-box-dryrun-'));
  const dbPath = path.join(dir, 'ledger.db');
  process.env[KEY_ENV] = THROWAWAY_KEY;

  const adapter = escrowCore.createIpfsGateAdapter({ account: 'dryescrow', currency: 'HBD', keyEnv: KEY_ENV });
  const ledger = escrowCore.openLedger(dbPath, { adapterMigrations: adapter.ledgerMigrations() });
  const nodeSk = crypto.randomBytes(32).toString('hex');
  const nodePub = escrowCore.getReportingPubkey(nodeSk);
  const boxSk = crypto.randomBytes(32).toString('hex');

  const txs = new Map();
  const chainAdd = (txId, { sender, amount, memo }) => txs.set(txId, { block_num: 100, operations: [
    ['transfer', { from: sender, to: 'dryescrow', amount: `${Number(amount).toFixed(3)} HBD`, memo }],
  ] });
  const sent = [];
  let n = 0;
  const broadcastClient = { broadcast: { sendOperations: async (ops) => {
    const id = 'drytx_' + (++n);
    sent.push({ to: ops[0][1].to, amount: ops[0][1].amount, memo: ops[0][1].memo });
    return { id };
  } } };

  const config = { account: 'dryescrow', currency: 'HBD', keyEnv: KEY_ENV, expectedReporters: [nodePub] };
  const mkBox = (extra = {}) => createEscrowBox({
    escrowCore, ledger, adapter, config, boxSkHex: boxSk,
    deps: { getTransaction: async (t) => txs.get(t) || { block_num: null, operations: [] },
            broadcastClient, now: () => NOW, ...extra },
    log: () => {},
  });

  const claim = (id, owner, extra = {}) => ({
    claim_id: id, owner, kind: 'original', state: 'active',
    size_bytes: 5_000_000, rate_locked: 1, copies_requested: 1, paid_hours: 48,
    start_ts: NOW - 10 * HOUR_MS, expiry_ts: NOW + 38 * HOUR_MS,
    amount_paid: 240, currency: 'HBD', ...extra });
  const fund = (id, owner, amount = 240) => {
    const tx = `tx-${id}`;
    chainAdd(tx, { sender: owner, amount, memo: `ipfs-gate:upload:r-${id}` });
    return [{ tx_id: tx, sender: owner, amount, memo: `ipfs-gate:upload:r-${id}`, currency: 'HBD' }];
  };
  const report = (c, rows, trigger, opts = {}) => escrowCore.signReport(
    escrowCore.buildEventReport({
      service: 'ipfs-gate', ref: c.claim_id, subject: c.claim_id,
      facts: adapter.buildClaimSettleReportFacts({ claim: c, payRows: rows, trigger, now: NOW }),
      nonce: opts.nonce || `${c.claim_id}:settle`, createdAt: NOW, reporter: 'dry-node',
    }), opts.sk || nodeSk);

  console.log(`ipfs-gate escrow box — adversarial dry-run (ledger: ${dbPath})\n`);

  // ── #1 replay-reject ──
  const box = mkBox();
  const c1 = claim('dr1', 'alice');
  const r1 = fund('dr1', 'alice');
  const out1 = await box.handleReport(report(c1, r1, 'cancel'));
  check('settles the happy path (pro-rata refund 190/240)', () => {
    assert.equal(out1.status, 'settled');
    assert.equal(out1.outflows[0].amount, 190);
    assert.equal(sent.length, 1);
  });
  {
    const again = await box.handleReport(report(c1, r1, 'cancel'));
    check('#1a same-nonce redelivery is a duplicate no-op', () => {
      assert.equal(again.status, 'duplicate');
      assert.equal(sent.length, 1);
    });
  }
  {
    const box2 = mkBox(); // "restart"
    const again = await box2.handleReport(report(c1, r1, 'cancel', { nonce: 'dr1:settle:again' }));
    check('#1b post-restart redelivery is already_settled (durable atomicClose)', () => {
      assert.equal(again.status, 'already_settled');
      assert.equal(sent.length, 1);
    });
  }
  {
    // the SAME on-chain tx smuggled under a NEW ref: tx_id UNIQUE keeps it out
    const c1b = claim('dr1b', 'alice');
    const rowsReplay = [{ ...r1[0] }];
    const out = await mkBox().handleReport(report(c1b, rowsReplay, 'cancel'));
    check('#1c a settled tx re-submitted under a new ref cannot fund a second settlement', () => {
      assert.equal(out.status, 'rejected');
      assert.match(out.reason, /no_verified_payments/);
      assert.equal(sent.length, 1);
    });
  }

  // ── #2 crash-no-double-disburse ──
  delete process.env[KEY_ENV];                    // simulate: box has no key (≈ died pre-disburse)
  const c2 = claim('dr2', 'bob');
  const r2 = fund('dr2', 'bob');
  const outP = await mkBox().handleReport(report(c2, r2, 'cancel'));
  check('#2a keyless settlement parks the refund as pending (no broadcast)', () => {
    assert.equal(outP.status, 'pending');
    assert.equal(sent.length, 1);
  });
  process.env[KEY_ENV] = THROWAWAY_KEY;
  {
    const boxR = mkBox({ findOutgoingByMemo: async () => ({ status: 'not_found' }) });
    const done1 = await boxR.disbursePending();
    const done2 = await boxR.disbursePending();
    check('#2b recovery disburses the pending refund EXACTLY once', () => {
      assert.equal(done1, 1);
      assert.equal(done2, 0);
      assert.equal(sent.length, 2);
    });
  }
  {
    // landed-but-lost-response: probe finds the memo on-chain → mark sent, never re-broadcast
    delete process.env[KEY_ENV];
    const c3 = claim('dr3', 'carol');
    const r3 = fund('dr3', 'carol');
    await mkBox().handleReport(report(c3, r3, 'cancel'));
    process.env[KEY_ENV] = THROWAWAY_KEY;
    const boxR = mkBox({ findOutgoingByMemo: async () => ({ status: 'found', txId: 'onchain-prior' }) });
    const done = await boxR.disbursePending();
    check('#2c memo-probe match marks sent WITHOUT re-broadcasting', () => {
      assert.equal(done, 1);
      assert.equal(sent.length, 2);
    });
  }

  // ── #3 conservation under lies ──
  {
    const c4 = claim('dr4', 'dave', { paid_hours: 48, start_ts: NOW - 60 * HOUR_MS }); // fully consumed
    const r4 = fund('dr4', 'dave');
    const out = await mkBox().handleReport(report(c4, r4, 'admin_void_innocent_guardian')); // the LIE
    check('#3 a lying trigger only re-splits the verified envelope (240 → owner, 0 minted)', () => {
      assert.equal(out.status, 'settled');
      assert.equal(out.outflows[0].amount, 240);
      assert.equal(out.outflows[0].to_account, 'dave');
      assert.equal(out.receipt.refund + out.receipt.settlement, 240);
    });
  }

  // ── #4 fail-closed gates ──
  {
    const strangerSk = crypto.randomBytes(32).toString('hex');
    const c5 = claim('dr5', 'erin');
    const r5 = fund('dr5', 'erin');
    const out = await mkBox().handleReport(report(c5, r5, 'cancel', { sk: strangerSk }));
    check('#4a unauthorized reporter is rejected silently (no receipt oracle)', () => {
      assert.equal(out.status, 'rejected');
      assert.equal(out.receipt, undefined);
    });
  }
  {
    const c6 = claim('dr6', 'frank');
    const rows = fund('dr6', 'frank');
    rows.push({ tx_id: 'tx-not-on-chain', sender: 'frank', amount: 5000, memo: 'ipfs-gate:extend:dr6', currency: 'HBD' });
    const out = await mkBox().handleReport(report(c6, rows, 'admin_void_innocent_guardian'));
    check('#4b a forged payment is dropped — the envelope cannot be inflated', () => {
      assert.equal(out.outflows[0].amount, 240);
    });
  }
  {
    const c7 = claim('dr7', 'grace');
    const tx = 'tx-dr7-mallory';
    chainAdd(tx, { sender: 'mallory', amount: 240, memo: 'ipfs-gate:upload:r-dr7' });
    const rows = [{ tx_id: tx, sender: 'mallory', amount: 240, memo: 'ipfs-gate:upload:r-dr7', currency: 'HBD' }];
    const out = await mkBox().handleReport(report(c7, rows, 'cancel'));
    check('#4c owner-is-payer: refunds can never be redirected away from the verified payer', () => {
      assert.equal(out.status, 'rejected');
      assert.match(out.reason, /payment_sender_mismatch/);
    });
  }

  ledger.close();
  console.log('\n──────────────────────────────────────────────');
  console.log(`\x1b[32mALL GUARDS HELD — ${passed}/${passed} checks passed.\x1b[0m`);
  console.log('Invariant #1 (replay-reject) and #2 (crash-no-double-disburse) confirmed against the real ledger.');
}

main().catch((e) => { console.error('\x1b[31mGUARD FAILED:\x1b[0m', e); process.exit(1); });
