// ── ipfs-gate-escrow/test/box.test.js — the box proven IN ISOLATION ───────────
// Adapted from v4call-escrow/test/box.test.js@946c7a6 (scenarios A–I) for
// ipfs-gate claim settlement. Drives the REAL escrow-box against the REAL
// escrow-core ledger/settle/disburse primitives, with only the two unavoidable
// externals injected: chain reads (deps.getTransaction → the real verifyPayment)
// and the broadcast (deps.broadcastClient — a mock; no key/funds/network).
//
// What it proves:
//   A  happy claim-settle (extend envelope!) refunds the owner + receipt verifies under the box key
//   B  a report from an UNAUTHORIZED reporter is rejected silently (hard gate #1)
//   C  a TAMPERED report fails the signature (hard gate #2)
//   D  an in-process REDELIVERY is a no-op (no double disburse)
//   E  a redelivery after RESTART (fresh box, same durable ledger) is a no-op
//   F  a LYING report can only RE-SPLIT the verified envelope — never mint/drain/redirect
//   G  a FORGED extra payment (not on chain) is dropped — can't inflate the envelope
//   H  a TRANSIENT verify error → retry (no close), then the SAME report settles
//   I  no-key leaves the refund PENDING → disbursePending() recovers EXACTLY once
//   +  ipfs-gate specifics: dormant/forfeit/innocent/permanent triggers, dust floor,
//      owner-is-payer guard, unknown-kind terminal reject, single-payment pure refund

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const dhive = require('@hiveio/dhive');

const escrowCore = require('escrow-core');
const { createEscrowBox } = require('../escrow-box');

const NOW = 1_800_000_000_000;
const HOUR_MS = 60 * 60 * 1000;
const KEY_ENV = 'TGATE_TEST_KEY';
// throwaway, never-funded — only so disburse()'s PrivateKey.fromString path runs.
const THROWAWAY_KEY = dhive.PrivateKey.fromSeed('ipfs-gate-escrow-box-test').toString();

// A mock chain: register real on-chain payments; unknown txIds resolve to an op-less tx
// (→ verifyPayment throws a STRUCTURAL unprocessable_entity, i.e. "forged/not found").
function makeChain() {
  const txs = new Map();
  return {
    add(txId, { sender, account, amount, currency = 'HBD', memo: m }) {
      txs.set(txId, { block_num: 100, operations: [
        ['transfer', { from: sender, to: account, amount: `${Number(amount).toFixed(3)} ${currency}`, memo: m }],
      ] });
    },
    getTransaction: async (txId) => txs.has(txId) ? txs.get(txId) : { block_num: null, operations: [] },
  };
}

function makeBroadcast() {
  const sent = [];
  let n = 0;
  return {
    sent,
    client: { broadcast: { sendOperations: async (ops) => {
      const id = 'mocktx_' + (++n);
      sent.push({ kind: ops[0][0], to: ops[0][1].to, amount: ops[0][1].amount, memo: ops[0][1].memo, id });
      return { id };
    } } },
  };
}

function setup({ now = NOW, reporters } = {}) {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const adapter = escrowCore.createIpfsGateAdapter({ account: 'tgateescrow', currency: 'HBD', keyEnv: KEY_ENV });
  const ledger = escrowCore.openLedger(':memory:', { adapterMigrations: adapter.ledgerMigrations() });
  const nodeSk = crypto.randomBytes(32).toString('hex');
  const nodePub = escrowCore.getReportingPubkey(nodeSk);
  const boxSk = crypto.randomBytes(32).toString('hex');
  const boxPub = escrowCore.getReportingPubkey(boxSk);
  const chain = makeChain();
  const broadcast = makeBroadcast();
  const config = { account: 'tgateescrow', currency: 'HBD', keyEnv: KEY_ENV,
    expectedReporters: reporters || [nodePub] };
  const mkBox = (extra = {}) => createEscrowBox({
    escrowCore, ledger, adapter, config, boxSkHex: boxSk,
    deps: { getTransaction: chain.getTransaction, broadcastClient: broadcast.client, now: () => now, ...extra },
    log: () => {},
  });
  return { adapter, ledger, nodeSk, nodePub, boxSk, boxPub, chain, broadcast, config, mkBox, box: mkBox() };
}

// The canonical active claim: 5 MB, rate 1 HBD/MB-hour, 1 copy, 48h paid (240) + 24h extend (120).
function activeClaim(claimId, owner, overrides = {}) {
  return {
    claim_id: claimId, owner, kind: 'original', state: 'active',
    size_bytes: 5_000_000, rate_locked: 1, copies_requested: 1, paid_hours: 72,
    start_ts: NOW - 10 * HOUR_MS, expiry_ts: NOW + 62 * HOUR_MS,
    amount_paid: 240, currency: 'HBD',
    ...overrides,
  };
}

// Register the claim's payments on the mock chain and return the payRows.
function fundClaim(s, claimId, owner, { upload = 240, extend = 120 } = {}) {
  const rows = [];
  if (upload > 0) {
    const tx = `tx-upload-${claimId}`;
    s.chain.add(tx, { sender: owner, account: s.config.account, amount: upload, memo: `ipfs-gate:upload:r-${claimId}` });
    rows.push({ tx_id: tx, sender: owner, amount: upload, memo: `ipfs-gate:upload:r-${claimId}`, currency: 'HBD' });
  }
  if (extend > 0) {
    const tx = `tx-extend-${claimId}`;
    s.chain.add(tx, { sender: owner, account: s.config.account, amount: extend, memo: `ipfs-gate:extend:${claimId}` });
    rows.push({ tx_id: tx, sender: owner, amount: extend, memo: `ipfs-gate:extend:${claimId}`, currency: 'HBD' });
  }
  return rows;
}

function signedClaimReport(s, claim, payRows, trigger, { sk, nonce, mutate } = {}) {
  const facts = s.adapter.buildClaimSettleReportFacts({ claim, payRows, trigger, now: NOW });
  if (mutate) mutate(facts);
  const report = escrowCore.buildEventReport({
    service: 'ipfs-gate', ref: claim.claim_id, subject: claim.claim_id, facts,
    nonce: nonce || `${claim.claim_id}:settle`, createdAt: NOW, reporter: 'tgate-node',
  });
  return escrowCore.signReport(report, sk || s.nodeSk);
}

// ── A. happy path: extend envelope, pro-rata refund to the owner ─────────────
test('A: claim-settle refunds pro-rata from the FULL envelope (310 of 360), receipt verifies', async () => {
  const s = setup();
  const claim = activeClaim('c-a', 'alice');
  const rows = fundClaim(s, 'c-a', 'alice');                 // 240 + 120 on-chain
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));

  assert.equal(out.status, 'settled');
  assert.equal(out.outflows.length, 1);
  assert.equal(out.outflows[0].to_account, 'alice');
  assert.equal(out.outflows[0].amount, 310);                 // (72−10)h × 5MB × 1 — exceeds the 240 original
  assert.equal(out.outflows[0].memo, 'ipfs-gate:refund:c-a');
  assert.equal(s.broadcast.sent.length, 1);
  assert.equal(out.receipt.refund, 310);
  assert.equal(out.receipt.settlement, 50);                  // retained by escrow
  assert.ok(escrowCore.verifyReport(out.receipt, s.boxPub), 'receipt verifies under the box key');
  // conservation: refund + retained == verified envelope
  assert.equal(out.receipt.refund + out.receipt.settlement, 360);
});

test('dormant guardian cancel (fee 0 default): full pledge back', async () => {
  const s = setup();
  const claim = activeClaim('c-dg', 'bob', { state: 'dormant', kind: 'guardian', paid_hours: 48, amount_paid: 100 });
  const rows = fundClaim(s, 'c-dg', 'bob', { upload: 0, extend: 0 });
  const tx = 'tx-pledge-c-dg';
  s.chain.add(tx, { sender: 'bob', account: s.config.account, amount: 100, memo: 'ipfs-gate:guardian:cid-1' });
  rows.push({ tx_id: tx, sender: 'bob', amount: 100, memo: 'ipfs-gate:guardian:cid-1', currency: 'HBD' });

  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'dormant_cancel'));
  assert.equal(out.status, 'settled');
  assert.equal(out.outflows[0].amount, 100);
  assert.equal(out.receipt.settlement, 0);
});

test('admin forfeit: zero outflows, envelope retained, still a signed settled receipt', async () => {
  const s = setup();
  const claim = activeClaim('c-ff', 'mallory', { paid_hours: 48 });
  const rows = fundClaim(s, 'c-ff', 'mallory', { extend: 0 });
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'admin_void_forfeit'));
  assert.equal(out.status, 'settled');
  assert.equal(out.outflows.length, 0);
  assert.equal(s.broadcast.sent.length, 0);
  assert.equal(out.receipt.refund, 0);
  assert.equal(out.receipt.settlement, 240);
});

test('innocent guardian on CID ban: full escrow back regardless of fee config', async () => {
  const s = setup();
  const claim = activeClaim('c-in', 'carol', { state: 'dormant', kind: 'guardian', amount_paid: 100 });
  const tx = 'tx-pledge-c-in';
  s.chain.add(tx, { sender: 'carol', account: s.config.account, amount: 100, memo: 'ipfs-gate:guardian:cid-2' });
  const rows = [{ tx_id: tx, sender: 'carol', amount: 100, memo: 'ipfs-gate:guardian:cid-2', currency: 'HBD' }];
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'admin_void_innocent_guardian'));
  assert.equal(out.outflows[0].amount, 100);
});

test('permanent claim (host-until-unpinned): cancel refunds nothing', async () => {
  const s = setup();
  const claim = activeClaim('c-pm', 'dave', {
    paid_hours: 1, amount_paid: 25, expiry_ts: 253402300799000 });
  const tx = 'tx-perm-c-pm';
  s.chain.add(tx, { sender: 'dave', account: s.config.account, amount: 25, memo: 'ipfs-gate:upload:r-perm' });
  const rows = [{ tx_id: tx, sender: 'dave', amount: 25, memo: 'ipfs-gate:upload:r-perm', currency: 'HBD' }];
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.outflows.length, 0);
  assert.equal(out.receipt.settlement, 25);
});

test('dust floor: sub-MIN_REFUND remainder is retained, not disbursed', async () => {
  const s = setup();
  // 0.048 envelope, 10h used of 48h → raw refund 0.038 < MIN_REFUND 0.05 → retained
  const claim = activeClaim('c-du', 'erin', { size_bytes: 500_000, rate_locked: 0.001, paid_hours: 48, amount_paid: 0.048 });
  const tx = 'tx-dust';
  s.chain.add(tx, { sender: 'erin', account: s.config.account, amount: 0.048, memo: 'ipfs-gate:upload:r-du' });
  const rows = [{ tx_id: tx, sender: 'erin', amount: 0.048, memo: 'ipfs-gate:upload:r-du', currency: 'HBD' }];
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.status, 'settled');
  assert.equal(out.outflows.length, 0);
  assert.equal(out.receipt.refund, 0);
  assert.ok(out.receipt.dust > 0);
});

// ── B/C. hard gates ──────────────────────────────────────────────────────────
test('B: unauthorized reporter is rejected SILENTLY (no receipt oracle)', async () => {
  const s = setup();
  const strangerSk = crypto.randomBytes(32).toString('hex');
  const claim = activeClaim('c-b', 'alice');
  const rows = fundClaim(s, 'c-b', 'alice');
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel', { sk: strangerSk }));
  assert.equal(out.status, 'rejected');
  assert.equal(out.receipt, undefined);
  assert.equal(s.broadcast.sent.length, 0);
});

test('C: a tampered report fails the signature gate', async () => {
  const s = setup();
  const claim = activeClaim('c-c', 'alice');
  const rows = fundClaim(s, 'c-c', 'alice');
  const signed = signedClaimReport(s, claim, rows, 'cancel');
  signed.facts.claimFacts.start_ts = NOW - 1;                // tamper AFTER signing
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'rejected');
  assert.match(out.reason, /signature/);
});

// ── D/E. idempotency ─────────────────────────────────────────────────────────
test('D: in-process redelivery (same nonce) is a no-op — exactly one disburse', async () => {
  const s = setup();
  const claim = activeClaim('c-d', 'alice');
  const rows = fundClaim(s, 'c-d', 'alice');
  const signed = signedClaimReport(s, claim, rows, 'cancel');
  const first = await s.box.handleReport(signed);
  assert.equal(first.status, 'settled');
  const again = await s.box.handleReport(signed);
  assert.equal(again.status, 'duplicate');
  assert.equal(s.broadcast.sent.length, 1);
});

test('E: redelivery after RESTART (fresh box, same ledger, fresh nonce) is already_settled', async () => {
  const s = setup();
  const claim = activeClaim('c-e', 'alice');
  const rows = fundClaim(s, 'c-e', 'alice');
  const first = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(first.status, 'settled');
  const box2 = s.mkBox();                                    // same durable ledger
  const again = await box2.handleReport(signedClaimReport(s, claim, rows, 'cancel', { nonce: `${claim.claim_id}:settle:retry2` }));
  assert.equal(again.status, 'already_settled');
  assert.ok(again.receipt, 'prior receipt returned');
  assert.equal(s.broadcast.sent.length, 1);
});

// ── F/G. lying node / forged payments ────────────────────────────────────────
test('F: lying trigger can only RE-SPLIT the verified envelope, never mint', async () => {
  const s = setup();
  // Node lies: claims a fully-consumed claim was 'admin_void_innocent_guardian' (full back).
  const claim = activeClaim('c-f', 'alice', { paid_hours: 48, start_ts: NOW - 60 * HOUR_MS });
  const rows = fundClaim(s, 'c-f', 'alice', { extend: 0 });  // 240 verified
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'admin_void_innocent_guardian'));
  assert.equal(out.status, 'settled');
  // worst case: whole envelope refunded to the VERIFIED PAYER — nothing minted
  assert.equal(out.outflows[0].amount, 240);
  assert.equal(out.outflows[0].to_account, 'alice');
  assert.equal(out.receipt.refund + out.receipt.settlement, 240);
});

test('F2: inflated claim facts cannot exceed the verified envelope', async () => {
  const s = setup();
  const claim = activeClaim('c-f2', 'alice', { rate_locked: 9999, size_bytes: 1e12 });
  const rows = fundClaim(s, 'c-f2', 'alice');                // 360 verified
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.status, 'settled');
  assert.equal(out.outflows.length, 0);                      // absurd usage → all retained
  assert.equal(out.receipt.settlement, 360);
});

test('G: a forged payment (not on chain) is dropped — envelope not inflated', async () => {
  const s = setup();
  const claim = activeClaim('c-g', 'alice');
  const rows = fundClaim(s, 'c-g', 'alice');                 // 360 real
  rows.push({ tx_id: 'tx-forged', sender: 'alice', amount: 1000, memo: 'ipfs-gate:extend:c-g', currency: 'HBD' });
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'admin_void_innocent_guardian'));
  assert.equal(out.status, 'settled');
  assert.equal(out.outflows[0].amount, 360, 'refund capped at the REAL envelope');
});

test('owner-is-payer guard: deposits paid by someone else than the refund target → terminal', async () => {
  const s = setup();
  const claim = activeClaim('c-om', 'alice');
  const tx = 'tx-om';
  s.chain.add(tx, { sender: 'mallory', account: s.config.account, amount: 240, memo: 'ipfs-gate:upload:r-om' });
  const rows = [{ tx_id: tx, sender: 'mallory', amount: 240, memo: 'ipfs-gate:upload:r-om', currency: 'HBD' }];
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.status, 'rejected');
  assert.match(out.reason, /payment_sender_mismatch/);
  assert.ok(out.receipt, 'terminal reject carries a signed failed receipt');
  assert.equal(out.receipt.status, 'failed');
  assert.equal(s.broadcast.sent.length, 0);
});

test('unknown report kind (e.g. a v4call call-end) is terminally rejected', async () => {
  const s = setup();
  const report = escrowCore.buildEventReport({
    service: 'ipfs-gate', ref: 'c-uk', subject: 'c-uk',
    facts: { kind: 'call-end', payments: [] },
    nonce: 'c-uk:settle', createdAt: NOW, reporter: 'tgate-node',
  });
  const out = await s.box.handleReport(escrowCore.signReport(report, s.nodeSk));
  assert.equal(out.status, 'rejected');
  assert.equal(out.receipt.status, 'failed');
});

test('all payments structurally unverifiable → no_verified_payments terminal reject', async () => {
  const s = setup();
  const claim = activeClaim('c-nv', 'alice');
  const rows = [{ tx_id: 'tx-ghost', sender: 'alice', amount: 240, memo: 'ipfs-gate:upload:r-nv', currency: 'HBD' }];
  const out = await s.box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.status, 'rejected');
  assert.match(out.reason, /no_verified_payments/);
});

// ── H. transient → retry, then settle ────────────────────────────────────────
test('H: transient verify error → retry (no close), then the SAME report settles', async () => {
  const s = setup();
  const claim = activeClaim('c-h', 'alice');
  const rows = fundClaim(s, 'c-h', 'alice');
  let failOnce = true;
  const flaky = async (txId) => {
    if (failOnce) { failOnce = false; throw new Error('All Hive nodes failed'); }
    return s.chain.getTransaction(txId);
  };
  const box = s.mkBox({ getTransaction: flaky });
  const signed = signedClaimReport(s, claim, rows, 'cancel');
  const first = await box.handleReport(signed);
  assert.equal(first.status, 'retry');
  assert.equal(s.ledger.getPaymentsByRef('c-h').length, 0, 'nothing recorded before retry');
  const second = await box.handleReport(signed);             // same stable nonce
  assert.equal(second.status, 'settled');
  assert.equal(s.broadcast.sent.length, 1);
});

// ── I. crash/no-key recovery — pending disbursed exactly once ────────────────
test('I: no key → refund PENDING; disbursePending() (probe not_found) recovers exactly once', async () => {
  const s = setup();
  delete process.env[KEY_ENV];                               // box booted without its key
  const claim = activeClaim('c-i', 'alice');
  const rows = fundClaim(s, 'c-i', 'alice');
  const completed = [];
  const box = s.mkBox({
    findOutgoingByMemo: async () => ({ status: 'not_found' }),
    onRefCompleted: async (ref, status) => completed.push({ ref, status }),
  });
  const out = await box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.status, 'pending');
  assert.equal(s.broadcast.sent.length, 0);

  process.env[KEY_ENV] = THROWAWAY_KEY;                      // operator provisions the key
  const n1 = await box.disbursePending();
  assert.equal(n1, 1);
  assert.equal(s.broadcast.sent.length, 1);
  assert.deepEqual(completed, [{ ref: 'c-i', status: 'settled' }]);
  const n2 = await box.disbursePending();                    // idempotent
  assert.equal(n2, 0);
  assert.equal(s.broadcast.sent.length, 1);
});

test('I2: memo probe FOUND → marked sent WITHOUT re-broadcast (landed-but-lost-response)', async () => {
  const s = setup();
  delete process.env[KEY_ENV];
  const claim = activeClaim('c-i2', 'alice');
  const rows = fundClaim(s, 'c-i2', 'alice');
  const box = s.mkBox({ findOutgoingByMemo: async () => ({ status: 'found', txId: 'onchain-tx-1' }) });
  const out = await box.handleReport(signedClaimReport(s, claim, rows, 'cancel'));
  assert.equal(out.status, 'pending');
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const n = await box.disbursePending();
  assert.equal(n, 1);
  assert.equal(s.broadcast.sent.length, 0, 'NEVER re-broadcast a landed refund');
  const row = s.ledger.db.prepare("SELECT * FROM refunds WHERE ref = 'c-i2'").get();
  assert.equal(row.status, 'sent');
  assert.equal(row.tx_id, 'onchain-tx-1');
});

// ── single-payment: pure refund path (future admin orphan refunds) ───────────
test('single-payment report with platformFee 0 refunds the verified amount', async () => {
  const s = setup();
  const tx = 'tx-orphan';
  s.chain.add(tx, { sender: 'frank', account: s.config.account, amount: 12.5, memo: 'ipfs-gate:upload:r-orph' });
  const facts = s.adapter.buildSinglePaymentReportFacts({
    txId: tx, sender: 'frank', amount: 12.5, currency: 'HBD',
    memo: 'ipfs-gate:upload:r-orph', payoutTo: 'frank', platformFee: 0,
  });
  const report = escrowCore.buildEventReport({
    service: 'ipfs-gate', ref: 'orphan-1', subject: 'orphan-1', facts,
    nonce: 'orphan-1:settle', createdAt: NOW, reporter: 'tgate-node',
  });
  const out = await s.box.handleReport(escrowCore.signReport(report, s.nodeSk));
  assert.equal(out.status, 'settled');
  assert.equal(out.outflows.length, 1);
  assert.equal(out.outflows[0].to_account, 'frank');
  assert.equal(out.outflows[0].amount, 12.5);
});
