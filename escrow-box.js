// ── ipfs-gate-escrow/escrow-box.js — the isolated money box (the SETTLEMENT AUTHORITY) ──
//
// Adapted from v4call-escrow/escrow-box.js@946c7a6 (the proven box). The generic
// machinery — hard gates, nonce dedup, on-chain re-verify, synchronous commit,
// disburse lifecycle, memo-probe recovery, receipts — is carried over unchanged;
// the v4call call-end settle path (ring/connect carve-out, callee/fee split,
// attestations) is replaced by ipfs-gate CLAIM settlement.
//
// THE SAFETY PROPERTY (why a compromised node can't drain funds):
//   The box verifies EVERY escrowed payment (upload/guardian/owncopy/extend) on-chain
//   itself (escrow-core.verifyPayment, tx-anchored + exact-memo) and only ever
//   disburses within that verified envelope. ipfs-gate's split is the simplest case:
//       refund(→ claim owner) + retained(stays in escrow)  ==  verified envelope − dust
//   So a lying report can only RE-SPLIT a claim's verified deposits between the owner
//   and the operator — never mint money, never pay a third party (the box additionally
//   REQUIRES the refund recipient to be the verified payer of the deposits).
//
// IDEMPOTENCY (no double-disburse, ever): two durable guards, exactly as in-process.
//   - tx_id UNIQUE  → a replayed payment can't be recorded (or counted) twice.
//   - atomicClose() → a single-winner state flip; a redelivered report / crash-retry /
//     two concurrent reports for the same ref produce exactly ONE settlement.
//
// PURE + INJECTABLE (so it is provable offline): all I/O is injected — `transport`
// (subscribe/publish), `deps.getTransaction` (chain reads), `deps.broadcastClient`,
// `deps.verifySidechain`, `deps.now`. Tests drive handleReport() directly.
//
// NO CLAUDE ON THE MONEY BOX (guardrail): developed/tested on a dev host; the
// production box runs it on a minimal host with no dev tooling.

'use strict';

// Purposes whose on-chain amount does NOT form the refundable deposit envelope.
// BLACKLIST, not whitelist (the proven v4call lesson — a whitelist rejected every
// real payment when a new purpose appeared): everything that is not an explicit
// escrow OUTFLOW memo counts toward the deposit cap. ipfs-gate deposit purposes
// today: upload, guardian (legacy backstop), owncopy, extend — and any future one
// just works.
const NON_DEPOSIT_PURPOSES = new Set(['refund', 'fee']);
const isDepositPurpose = (p) => !NON_DEPOSIT_PURPOSES.has(p);

function isTransient(err) {
  // escrow-core.verifyPayment throws CODED errors for every on-chain verdict:
  //   'bad_request' / 'unprocessable_entity' → structural (forged / wrong memo / not found).
  // Anything WITHOUT one of those codes is a thrown network/timeout → transient.
  // Transient returns 'retry' BEFORE any close; structural DROPS that one payment.
  if (!err) return false;
  return err.code !== 'bad_request' && err.code !== 'unprocessable_entity';
}

/**
 * Create an escrow box bound to one escrow account/key/ledger.
 *
 * @param escrowCore  require('escrow-core')
 * @param ledger      escrowCore.openLedger(dbPath, { adapterMigrations: adapter.ledgerMigrations() })
 * @param adapter     escrowCore.createIpfsGateAdapter({ account, currency, keyEnv, cancelFeePct, minRefund })
 * @param config      { account, currency, keyEnv, expectedReporters:[pubkeyHex…] }
 * @param boxSkHex    64-hex schnorr sk for SIGNING settlement-receipts
 * @param deps        { getTransaction, broadcastClient, verifySidechain?, now?, transport? }
 * @param log         (level, msg) => void
 */
function createEscrowBox({ escrowCore, ledger, adapter, config, boxSkHex, deps = {}, log = () => {} }) {
  if (!escrowCore || !ledger || !adapter || !config) throw new Error('createEscrowBox: escrowCore, ledger, adapter, config are required');
  if (!config.account || !config.keyEnv) throw new Error('createEscrowBox: config.account + config.keyEnv are required');

  const seen = escrowCore.createSeenIds();
  const nowFn = () => (deps.now ? deps.now() : Date.now());
  const expectedReporters = new Set(config.expectedReporters || []);

  const reject = (ref, reason) => { log('warn', `report rejected (ref=${ref}): ${reason}`); return { status: 'rejected', ref, reason }; };

  // PERMANENT rejection of an AUTHORIZED, signature-valid report → also return a signed
  // status:'failed' receipt so the node's retry-until-received drainer gets a terminal
  // answer and stops republishing. Never used for the hard gates (bad sig / unauthorized
  // reporter) — those stay silent: an untrusted counterparty gets no receipt oracle.
  const rejectTerminal = (ref, reason, currency) => {
    log('warn', `report rejected TERMINALLY (ref=${ref}): ${reason}`);
    const receipt = escrowCore.buildSettlementReceipt({
      ref, settlement: 0, refund: 0, dust: 0, currency: currency || config.currency,
      disburseTx: null, status: 'failed', reason, createdAt: nowFn(),
    });
    return { status: 'rejected', ref, reason, receipt: boxSkHex ? escrowCore.signReport(receipt, boxSkHex) : receipt };
  };

  function authorizedReporter(pubkey) {
    // No allow-list configured → the box refuses ALL reports (fail closed).
    return !!pubkey && expectedReporters.has(pubkey);
  }

  function placesFor(currency) {
    return adapter.precision(currency || config.currency);
  }

  // Resolve a payment currency's TRUE on-chain precision before any money math
  // (8dp HE tokens vs the 3dp registry default). Cached; fail-safe on lookup error.
  async function resolveCurrencyPrecision(cur) {
    try { await (deps.resolvePrecision || escrowCore.resolvePrecision)(cur); }
    catch (e) { log('warn', `precision resolve ${cur}: ${e.message}`); }
  }

  // Map a disburse error to a durable-row disposition. TRANSIENT (network) + no_key
  // are RETRYABLE → leave the row 'pending' (disbursePending re-attempts after an
  // on-chain idempotency probe). Only a PERMANENT failure is the terminal 'failed'.
  function dispositionForDisburseError(e) {
    if (e && (e.code === 'no_key' || e.code === 'transient')) return 'pending';
    try { if (escrowCore.classifyBroadcastError && escrowCore.classifyBroadcastError(e) === 'transient') return 'pending'; } catch {}
    return 'failed';
  }

  // Build a settlement-receipt from the durable state of an already-settled ref, so a
  // redelivered report gets the SAME answer without re-disbursing. ipfs-gate outflows
  // are all refunds (reason = the settle trigger); settlement (the retained portion)
  // is not reconstructable from the refunds table alone — the receipt's job here is
  // the refund status, so it reports settlement 0 with the summed refunds.
  function receiptFromLedger(ref, status) {
    const refunds = ledger.db.prepare('SELECT * FROM refunds WHERE ref = ?').all(ref);
    const total = refunds.reduce((s, x) => s + Number(x.amount || 0), 0);
    const first = refunds.find(r => r.tx_id);
    const currency = refunds[0] ? refunds[0].currency : config.currency;
    const receipt = escrowCore.buildSettlementReceipt({
      ref, settlement: 0, refund: total,
      dust: 0, currency, disburseTx: (first && first.tx_id) || null,
      status: status || 'settled', createdAt: nowFn(),
    });
    return boxSkHex ? escrowCore.signReport(receipt, boxSkHex) : receipt;
  }

  // Disburse one recorded outflow row; shared by claim-settle and single-payment.
  async function disburseOutflows(ref, outflows, places) {
    let disburseTx = null, overall = 'settled';
    for (const o of outflows) {
      const { refund_id } = ledger.recordRefund({
        ref, to_account: o.to_account, amount: o.amount, currency: o.currency, memo: o.memo, reason: o.reason });
      try {
        const { txId } = await escrowCore.disburse(
          { to: o.to_account, amount: o.amount, currency: o.currency, memo: o.memo,
            fromAccount: config.account, keyEnv: config.keyEnv, places },
          { client: deps.broadcastClient }
        );
        ledger.markRefundSettled(refund_id, 'sent', txId);
        o.txId = txId; o.status = 'sent';
        if (!disburseTx) disburseTx = txId;
      } catch (e) {
        if (dispositionForDisburseError(e) === 'pending') {
          o.status = 'pending'; if (overall === 'settled') overall = 'pending';
          log('error', `disburse ${o.kind} → ${o.to_account} left PENDING (retryable ${e.code || 'net'}): ${e.message}`);
        } else {
          ledger.markRefundSettled(refund_id, 'failed', null);
          o.status = 'failed'; overall = 'failed';
          log('error', `disburse ${o.kind} → ${o.to_account} FAILED (permanent): ${e.message}`);
        }
      }
    }
    return { disburseTx, overall };
  }

  /**
   * Handle one signed event-report. Returns one of:
   *   { status:'settled'|'pending'|'failed', ref, receipt, outflows }   — a real settlement
   *   { status:'duplicate'|'already_settled', ref, receipt? }           — idempotent no-op
   *   { status:'retry', ref, reason }                                   — transient; node re-reports
   *   { status:'rejected', ref, reason }                                — bad sig / unauthorized (silent)
   *   { status:'rejected', ref, reason, receipt }                       — authorized but structurally bad
   */
  async function handleReport(signed) {
    const ref = signed && signed.ref;

    // 1. shape / proto / type
    if (!signed || signed.proto !== escrowCore.PROTO || signed.type !== 'event-report') return reject(ref, 'bad_shape');
    if (!ref || !signed.nonce) return reject(ref, 'missing ref/nonce');

    // 2. HARD GATE — authorized reporter + valid schnorr signature over the canonical payload
    if (!authorizedReporter(signed.pubkey)) return reject(ref, `unauthorized reporter pubkey ${signed.pubkey}`);
    if (!escrowCore.verifyReport(signed, signed.pubkey)) return reject(ref, 'bad signature');

    // 3. Fast-path dedup — read-only here (has, not markSeen): the nonce is only CONSUMED
    //    after a successful atomicClose, so a transient-retry (stable `ref:settle` nonce)
    //    is never wrongly blocked. Durable guards are the authority across restarts.
    if (seen.has(signed.nonce)) {
      log('info', `duplicate report (nonce seen) ref=${ref}`);
      return { status: 'duplicate', ref };
    }

    const facts = signed.facts || {};
    if (facts.kind === 'single-payment') return handleSinglePayment(signed, ref, facts);
    if (facts.kind !== 'claim-settle') return rejectTerminal(ref, `unknown report kind '${facts.kind}'`, facts.currency);

    const claimFacts = facts.claimFacts || {};
    const trigger = facts.trigger || 'cancel';
    const payments = Array.isArray(facts.payments) ? facts.payments : [];

    if (!claimFacts.owner) return rejectTerminal(ref, 'claimFacts.owner required', facts.currency);
    if (claimFacts.claim_id && claimFacts.claim_id !== ref) {
      return rejectTerminal(ref, `ref/claim_id mismatch (${claimFacts.claim_id})`, facts.currency);
    }

    // Resolve every distinct payment currency's true precision up front.
    for (const cur of new Set([facts.currency, ...payments.map(p => p.currency)].filter(Boolean))) {
      await resolveCurrencyPrecision(cur);
    }

    // 4. Independently VERIFY each escrowed payment on-chain (the verified envelope).
    //    Abort to 'retry' on a transient error BEFORE any close; drop forged rows.
    const verified = [];
    for (const p of payments) {
      const currency = p.currency || config.currency;
      let v;
      try {
        v = await escrowCore.verifyPayment(
          { txId: p.txId, sender: p.sender, account: config.account, currency,
            expectedMemo: p.memo, expectedAmount: p.amount },
          { getTransaction: deps.getTransaction }
        );
      } catch (e) {
        if (isTransient(e)) return { status: 'retry', ref, reason: `verify ${p.txId}: ${e.message}` };
        log('warn', `dropping payment ${p.txId} (structural verify failure): ${e.message}`);
        continue; // forged / wrong-memo payment can't enter the envelope
      }
      // Hive-Engine tokens need the sidechain hard-confirm; native HIVE/HBD skip it.
      const verifySidechain = deps.verifySidechain || escrowCore.verifySidechain;
      if (!escrowCore.isNativeCurrency(v.currency) && verifySidechain) {
        try { await verifySidechain(p.txId); }
        catch (e) { if (isTransient(e)) return { status: 'retry', ref, reason: `sidechain ${p.txId}: ${e.message}` };
                    log('warn', `dropping HE payment ${p.txId} (sidechain reject): ${e.message}`); continue; }
      }
      const purpose = (escrowCore.parseMemo(p.memo) || {}).purpose || p.purpose || 'upload';
      verified.push({ v, purpose, memo: p.memo });
    }

    // 4b. Pre-commit guard: OWNER IS THE PAYER. Every monolith claim payment is verified
    // with sender = the claim owner (upload/reserve, guardian pledge, own-copy, extend —
    // server.js verifyPayment call sites), and the refund outflow goes to the owner. A
    // report whose verified deposits were paid by someone ELSE than the asserted refund
    // recipient is structurally wrong (or an attempted redirect) → terminal, pre-commit,
    // so a corrected re-report can still settle.
    for (const x of verified) {
      if (isDepositPurpose(x.purpose) && x.v.sender !== claimFacts.owner) {
        return rejectTerminal(ref, `payment_sender_mismatch: ${x.v.txId} paid by ${x.v.sender}, owner ${claimFacts.owner}`, facts.currency);
      }
    }

    // ── SYNCHRONOUS commit section (no await): record + single-winner close atomically. ──
    const pre = ledger.getPaymentsByRef(ref);
    if (pre.some(r => r.settle_state === 'closed')) {
      log('info', `ref ${ref} already settled — returning prior receipt`);
      return { status: 'already_settled', ref, receipt: receiptFromLedger(ref) };
    }
    for (const { v, memo, purpose } of verified) {
      const row = { tx_id: v.txId, ref, sender: v.sender, currency: v.currency, amount: v.paid,
        memo, block_num: v.blockNum };
      // Claim facts (node-asserted; can only ever re-split the verified envelope) are
      // persisted on the DEPOSIT rows so a crash-recovering box can settle without the
      // report. cancel_fee_pct is the BOX's authoritative knob, never the node's.
      if (isDepositPurpose(purpose)) {
        row.claim_id = ref;
        row.owner = claimFacts.owner;
        if (claimFacts.claim_kind      != null) row.claim_kind       = String(claimFacts.claim_kind);
        if (claimFacts.claim_state     != null) row.claim_state      = String(claimFacts.claim_state);
        if (claimFacts.rate_locked     != null) row.rate_locked      = Number(claimFacts.rate_locked);
        if (claimFacts.size_bytes      != null) row.size_bytes       = Number(claimFacts.size_bytes);
        if (claimFacts.copies_requested != null) row.copies_requested = Number(claimFacts.copies_requested);
        if (claimFacts.paid_hours      != null) row.paid_hours       = Number(claimFacts.paid_hours);
        if (claimFacts.start_ts        != null) row.start_ts         = Number(claimFacts.start_ts);
        if (claimFacts.expiry_ts       != null) row.expiry_ts        = Number(claimFacts.expiry_ts);
        row.cancel_fee_pct = adapter.cancelFeePct;
        row.settle_trigger = trigger;
      }
      try {
        ledger.recordPayment(row);
      } catch (e) {
        if (e && e.code === 'conflict') continue; // tx already recorded — idempotent
        throw e;
      }
    }
    const payRows = ledger.getPaymentsByRef(ref);
    if (payRows.length === 0) {
      log('warn', `ref ${ref} has no verified payments — nothing to settle`);
      return rejectTerminal(ref, 'no_verified_payments', facts.currency);
    }
    if (!ledger.atomicClose(ref)) {
      log('info', `ref ${ref} lost atomicClose race — already settling/settled`);
      return { status: 'already_settled', ref, receipt: receiptFromLedger(ref) };
    }
    seen.markSeen(signed.nonce); // we won the close → consume the nonce
    // ── end synchronous commit section ──

    // 5. Derive money facts from the DURABLE rows (the authority). The refundable
    // envelope is the SUM of deposit-purpose rows — the original upload/pledge/
    // owncopy deposit plus every extend top-up (extendClaim never bumps the
    // monolith's amount_paid, so the envelope is the only correct cap).
    let deposit = 0;
    for (const r of payRows) {
      const purpose = (escrowCore.parseMemo(r.memo) || {}).purpose || 'upload';
      if (isDepositPurpose(purpose)) deposit += Number(r.amount) || 0;
    }
    const primary = payRows.find(r => r.claim_id != null) || payRows[0];
    const currency = primary.currency || config.currency;
    const places = placesFor(currency);
    const now = nowFn();
    deposit = escrowCore.roundCoins(deposit, currency, places);

    // 6. Metering + the cap (the money-safety invariant) — escrow-core.settle, never inline.
    // The dust floor is the monolith's MIN_REFUND (box-authoritative adapter knob), so
    // sub-floor refunds are retained exactly as broadcastRefund's 'skipped' path.
    const record = {
      trigger, deposit, currency,
      claim_state: primary.claim_state ?? claimFacts.claim_state,
      rate_locked: primary.rate_locked ?? claimFacts.rate_locked,
      size_bytes: primary.size_bytes ?? claimFacts.size_bytes,
      copies_requested: primary.copies_requested ?? claimFacts.copies_requested,
      paid_hours: primary.paid_hours ?? claimFacts.paid_hours,
      start_ts: primary.start_ts ?? claimFacts.start_ts,
      expiry_ts: primary.expiry_ts ?? claimFacts.expiry_ts,
      cancel_fee_pct: adapter.cancelFeePct,
    };
    const meteredUsage = adapter.meteredUsage(record, now);
    const settled = escrowCore.settle({ deposit, meteredUsage, currency, places, dustFloor: adapter.minRefund });

    // 7. ipfs-gate split — at most ONE outflow: the refund to the verified owner.
    const split = adapter.settlementSplit(
      { owner: primary.owner || claimFacts.owner, currency, trigger },
      settled,
      { ref, places }
    );

    // 8. Durable refund lifecycle → disburse with the box key → mark sent/pending/failed.
    const { disburseTx, overall } = await disburseOutflows(ref, split.outflows, places);

    // 9. Signed settlement-receipt back to the node.
    const receipt = escrowCore.buildSettlementReceipt({
      ref, settlement: settled.settlement, refund: settled.refund, dust: settled.dust,
      currency, disburseTx, status: overall, createdAt: now });
    const signedReceipt = boxSkHex ? escrowCore.signReport(receipt, boxSkHex) : receipt;

    log('info', `settled ${ref} (${trigger}): refund=${settled.refund} retained=${settled.settlement} status=${overall}`);
    return { status: overall, ref, receipt: signedReceipt, outflows: split.outflows };
  }

  /**
   * Handle a single-payment report — one-off refunds outside the claim lifecycle
   * (e.g. a future admin orphan-payment refund path). Verifies the ONE reported
   * on-chain payment itself, splits via adapter.singlePaymentSplit (platformFee 0
   * = pure refund), disburses. Same idempotency guards as handleReport.
   */
  async function handleSinglePayment(signed, ref, facts) {
    const payments = Array.isArray(facts.payments) ? facts.payments : [];
    if (payments.length !== 1) return rejectTerminal(ref, 'single-payment report must carry exactly one payment', facts.currency);
    const p = payments[0];
    const currency = p.currency || facts.currency || config.currency;
    await resolveCurrencyPrecision(currency);

    let v;
    try {
      v = await escrowCore.verifyPayment(
        { txId: p.txId, sender: p.sender, account: config.account, currency,
          expectedMemo: p.memo, expectedAmount: p.amount },
        { getTransaction: deps.getTransaction }
      );
    } catch (e) {
      if (isTransient(e)) return { status: 'retry', ref, reason: `verify ${p.txId}: ${e.message}` };
      return rejectTerminal(ref, `structural verify failure: ${e.message}`, currency);
    }
    const verifySidechain = deps.verifySidechain || escrowCore.verifySidechain;
    if (!escrowCore.isNativeCurrency(v.currency) && verifySidechain) {
      try { await verifySidechain(p.txId); }
      catch (e) {
        if (isTransient(e)) return { status: 'retry', ref, reason: `sidechain ${p.txId}: ${e.message}` };
        return rejectTerminal(ref, `sidechain reject: ${e.message}`, currency);
      }
    }

    // ── SYNCHRONOUS commit section ──
    const pre = ledger.getPaymentsByRef(ref);
    if (pre.some(r => r.settle_state === 'closed')) {
      log('info', `ref ${ref} already settled — returning prior receipt`);
      return { status: 'already_settled', ref, receipt: receiptFromLedger(ref) };
    }
    try {
      ledger.recordPayment({ tx_id: v.txId, ref, sender: v.sender, currency: v.currency, amount: v.paid,
        memo: p.memo, block_num: v.blockNum });
    } catch (e) {
      if (e && e.code !== 'conflict') throw e;
    }
    const payRows = ledger.getPaymentsByRef(ref);
    if (payRows.length === 0) {
      log('warn', `ref ${ref} has no verified payment — nothing to settle`);
      return rejectTerminal(ref, 'no_verified_payments', currency);
    }
    if (!ledger.atomicClose(ref)) {
      log('info', `ref ${ref} lost atomicClose race — already settling/settled`);
      return { status: 'already_settled', ref, receipt: receiptFromLedger(ref) };
    }
    seen.markSeen(signed.nonce);
    // ── end synchronous commit section ──

    const verifiedAmount = payRows.reduce((s, r) => s + (Number(r.amount) || 0), 0);
    const now = nowFn();
    const places = placesFor(currency);
    const split = adapter.singlePaymentSplit(verifiedAmount, facts, { ref, feeAccount: config.feeAccount, places });

    const { disburseTx, overall } = await disburseOutflows(ref, split.outflows, places);

    const receipt = escrowCore.buildSettlementReceipt({
      ref, settlement: 0, refund: split.net, dust: 0,
      currency, disburseTx, status: overall, createdAt: now });
    const signedReceipt = boxSkHex ? escrowCore.signReport(receipt, boxSkHex) : receipt;

    log('info', `settled ${ref} (single-payment): net=${split.net} fee=${split.fee} status=${overall}`);
    return { status: overall, ref, receipt: signedReceipt, outflows: split.outflows };
  }

  // Crash-recovery: disburse any refund rows still 'pending'. IDEMPOTENCY PROBE FIRST:
  // if this exact memo already went out from the escrow account, a prior attempt DID
  // land (its response was lost) — mark 'sent', never re-broadcast. Inconclusive probe
  // → skip this cycle rather than risk a double-pay. When a ref's LAST pending row
  // completes, deps.onRefCompleted(ref, status) fires (start() wires it to publish a
  // refreshed COMPLETION receipt so the node learns the money actually moved).
  async function disbursePending() {
    const pending = ledger.db.prepare("SELECT * FROM refunds WHERE status = 'pending'").all();
    let done = 0;
    const touched = new Set();
    const probeFn = deps.findOutgoingByMemo || escrowCore.findOutgoingByMemo;
    for (const r of pending) {
      if (probeFn) {
        let probe;
        try { probe = await probeFn(config.account, r.memo, r.currency); }
        catch (e) { log('warn', `recovery: ${r.refund_id} probe threw — skip this cycle: ${e.message}`); continue; }
        if (probe && probe.status === 'found') {
          ledger.markRefundSettled(r.refund_id, 'sent', probe.txId || null);
          done++; touched.add(r.ref);
          log('info', `recovery: ${r.refund_id} already on-chain (memo match) — marked sent`);
          continue;
        }
        if (probe && probe.status === 'error') { log('warn', `recovery: ${r.refund_id} probe inconclusive — skip this cycle`); continue; }
        // status:'not_found' → confirmed not yet sent → safe to (re)disburse below.
      }
      try {
        await resolveCurrencyPrecision(r.currency);   // registry is empty after a restart
        const { txId } = await escrowCore.disburse(
          { to: r.to_account, amount: r.amount, currency: r.currency, memo: r.memo,
            fromAccount: config.account, keyEnv: config.keyEnv, places: placesFor(r.currency) },
          { client: deps.broadcastClient }
        );
        ledger.markRefundSettled(r.refund_id, 'sent', txId);
        done++; touched.add(r.ref);
      } catch (e) {
        if (dispositionForDisburseError(e) === 'pending') { log('error', `recovery: ${r.refund_id} (${r.reason || 'outflow'} → ${r.to_account}) still retryable: ${e.message}`); continue; }
        ledger.markRefundSettled(r.refund_id, 'failed', null);
        touched.add(r.ref);
        log('error', `recovery: ${r.refund_id} failed (permanent): ${e.message}`);
      }
    }
    if (done) log('info', `recovery disbursed ${done} pending refund(s)`);
    if (deps.onRefCompleted && touched.size) {
      const countPending = ledger.db.prepare("SELECT COUNT(*) AS n FROM refunds WHERE ref = ? AND status = 'pending'");
      const anyFailed    = ledger.db.prepare("SELECT COUNT(*) AS n FROM refunds WHERE ref = ? AND status = 'failed'");
      for (const ref of touched) {
        if (countPending.get(ref).n > 0) continue;
        const status = anyFailed.get(ref).n > 0 ? 'failed' : 'settled';
        try { await deps.onRefCompleted(ref, status); }
        catch (e) { log('error', `onRefCompleted ${ref}: ${e.message}`); }
      }
    }
    return done;
  }

  // Wire the injected transport: every inbound event-report → handleReport → publish the receipt.
  async function start() {
    if (!deps.onRefCompleted && deps.transport && deps.transport.publish) {
      deps.onRefCompleted = async (ref, status) => {
        const receipt = receiptFromLedger(ref, status);
        for (const pk of expectedReporters) await deps.transport.publish(receipt, { to: pk });
        log('info', `published COMPLETION receipt for ${ref} (${status})`);
      };
    }
    await disbursePending(); // settle anything left mid-flight before taking new work
    if (deps.transport && deps.transport.subscribe) {
      deps.transport.subscribe(async (signed) => {
        const out = await handleReport(signed);
        if (out.receipt && deps.transport.publish) await deps.transport.publish(out.receipt, { to: signed.pubkey });
      });
      log('info', 'escrow box listening for event-reports');
    }
    const retryMs = Number(deps.pendingRetryMs) || 60000;
    if (retryMs > 0) {
      const t = setInterval(() => { disbursePending().catch(e => log('error', `periodic disbursePending: ${e.message}`)); }, retryMs);
      if (t && t.unref) t.unref();
    }
  }

  return { handleReport, disbursePending, start, _seen: seen };
}

module.exports = { createEscrowBox, isDepositPurpose, NON_DEPOSIT_PURPOSES };
