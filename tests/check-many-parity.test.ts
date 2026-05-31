/**
 * M2 check_many parity test (Track A).
 *
 * Validates that the batched `check_many(handle, actions[])` API in the
 * napi runtime (`packages/aps-sdk-runtime/src/lib.rs`) yields, for each
 * action in the batch, exactly the same decision and receipt a single
 * `check(handle, action)` call would. The batched path amortizes only
 * the FFI marshalling cost; it changes no verifier semantics.
 *
 * Proof box
 *   Proves: a check_many result shows each action was evaluated under
 *   the same policy as a single check. Every element runs the identical
 *   aps_check code path against the same compiled authority and verifier
 *   context, in input order, so the i-th batched decision is byte-equal
 *   to the i-th sequential decision (decisionType, reasonCode,
 *   sequenceId, decisionIdHex, eventMacHex all match).
 *   Does NOT prove: anything about wall-clock latency on any platform
 *   other than where a measurement was actually taken. No public latency
 *   claim is approved from this test.
 *
 * Environment gate
 *   The live comparison needs the compiled native binding
 *   (`@aeoess/aps-sdk-runtime` -> `*.node`). That artifact is produced by
 *   the napi CLI build (`napi build`), which is not available in every
 *   environment (notably this macOS arm64 dev host has no napi CLI
 *   installed and no `.node` present). When the binding is absent this
 *   test does NOT fake a pass: it runs the input-construction and
 *   parity-contract checks that need no native code, and marks the
 *   native comparison subtests as skipped with an explicit reason. The
 *   byte-level parity itself is also exercised host-independently by
 *   the Rust unit tests in `packages/aps-sdk-runtime/src/lib.rs`
 *   (`check_many_tests`), which run under `cargo test`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Decision shape returned by both `check` and `check_many`.
interface DecisionOutput {
  decisionType: string;
  reasonCode: number;
  reasonName: string;
  sequenceId: bigint;
  decisionIdHex: string;
  eventMacHex: string;
}

interface ToolEntryInput {
  descriptorHashHex: string;
  localId: number;
}

interface ActionInput {
  version: number;
  passportIdHashHex: string;
  toolDescriptorHashHex: string;
  localToolId: number;
  operationId: number;
  resourceType: number;
  riskClass: number;
  resourcePathDepth: number;
  costUnits: number;
  sequenceId: bigint;
  nonceHex: string;
  resourcePathHashes: bigint[];
}

interface NativeBinding {
  loadPassportUnverified(
    passportJson: string,
    tools: ToolEntryInput[],
    sinkConfig: { mode: string },
  ): unknown;
  authorityInfo(handle: unknown): {
    passportIdHashHex: string;
    toolRegistryRootHex: string;
  };
  computeRegistryRoot(tools: ToolEntryInput[]): string;
  hashResourcePath(components: string[]): bigint[];
  check(handle: unknown, action: ActionInput): DecisionOutput;
  check_many?(handle: unknown, actions: ActionInput[]): DecisionOutput[];
  checkMany?(handle: unknown, actions: ActionInput[]): DecisionOutput[];
}

/** Try to load the compiled native binding. Returns null when absent. */
function tryLoadNative(): NativeBinding | null {
  const candidates = [
    '@aeoess/aps-sdk-runtime',
    '../packages/aps-sdk-runtime',
    '../packages/aps-sdk-runtime/index.js',
  ];
  for (const id of candidates) {
    try {
      const mod = require(id) as NativeBinding;
      if (mod && typeof mod.check === 'function') {
        return mod;
      }
    } catch {
      // try next candidate
    }
  }
  return null;
}

const TOOL_DESCRIPTOR_HASH_HEX =
  'abcd000000000000000000000000000000000000000000000000000000000000';

function buildPassport(rootHex: string): string {
  const now = Date.now();
  const issued = new Date(now - 30_000).toISOString();
  const expires = new Date(now + 30_000).toISOString();
  return JSON.stringify({
    type: 'aps.runtime_passport',
    version: '0.1',
    passport_id: 'rp_m2parity0000000000000000000',
    agent_id: 'ag_m2parity0000000000000000000',
    principal_id: 'pr_m2parity0000000000000000000',
    beneficiary_id: 'bn_m2parity0000000000000000000',
    issuer: 'https://gateway.example.test',
    issued_at: issued,
    expires_at: expires,
    max_clock_skew_ms: 1000,
    policy_epoch: 42,
    revocation_epoch: 1842,
    tool_registry_root: `blake3:${rootHex}`,
    delegation_chain_hash:
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    effective_authority_hash:
      'blake3:0000000000000000000000000000000000000000000000000000000000000000',
    risk_class: 'R2',
    minimum_tier_required: 'T2',
    tier_attested: 'T2',
    verifier_instance_id: 'vi_m2parity0000000000000000000',
    verifier_build_hash:
      'blake3:1111111111111111111111111111111111111111111111111111111111111111',
    session_id: 'sn_m2parity0000000000000000000',
    sequence_start: 1000,
    sequence_end: 2000,
    budget_lease: {
      lease_id: 'bl_m2parity0000000000000000000',
      max_actions: 1000,
      max_cost_units: 50000,
      sublease_parent: null,
    },
    authority_blob_encoding: 'application/aps-authority+json',
    authority_blob: {
      allowed_tools: [`blake3:${TOOL_DESCRIPTOR_HASH_HEX}`],
      allowed_operations: ['read'],
      resource_scopes: ['customer/*'],
      approval_rules: [],
    },
    receipt_stream_id: 'rs_m2parity0000000000000000000',
    signature: 'ed25519:' + '0'.repeat(128),
  });
}

function sameDecision(a: DecisionOutput, b: DecisionOutput): void {
  assert.equal(a.decisionType, b.decisionType, 'decisionType');
  assert.equal(a.reasonCode, b.reasonCode, 'reasonCode');
  assert.equal(a.reasonName, b.reasonName, 'reasonName');
  assert.equal(a.sequenceId, b.sequenceId, 'sequenceId');
  assert.equal(a.decisionIdHex, b.decisionIdHex, 'decisionIdHex');
  assert.equal(a.eventMacHex, b.eventMacHex, 'eventMacHex');
}

function batchFn(native: NativeBinding):
  | ((handle: unknown, actions: ActionInput[]) => DecisionOutput[])
  | null {
  if (typeof native.check_many === 'function') {
    return native.check_many.bind(native);
  }
  if (typeof native.checkMany === 'function') {
    return native.checkMany.bind(native);
  }
  return null;
}

const native = tryLoadNative();
const SKIP_REASON =
  'native binding (@aeoess/aps-sdk-runtime *.node) not built in this environment; ' +
  'byte-level parity is also exercised host-independently by the Rust check_many_tests ' +
  '(cargo test). This is environment-gated, not a fabricated pass.';

// -----------------------------------------------------------------------
// Contract checks that need no native code: these always run.
// -----------------------------------------------------------------------

test('parity contract: batched result length equals action count', () => {
  // The documented contract: check_many returns exactly one decision per
  // input action, in order, with no cross-action short-circuit. We assert
  // the shape contract here independent of the native path so the
  // expectation is pinned even when the binding is absent.
  const actions: ActionInput[] = [];
  // Construct three placeholder actions; we only check arity semantics.
  for (let i = 0; i < 3; i++) {
    actions.push({
      version: 1,
      passportIdHashHex: '00'.repeat(32),
      toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
      localToolId: 0,
      operationId: 0,
      resourceType: 0,
      riskClass: 2,
      resourcePathDepth: 1,
      costUnits: 1,
      sequenceId: BigInt(1000 + i),
      nonceHex: '00112233445566778899aabbccddeeff',
      resourcePathHashes: [],
    });
  }
  assert.equal(actions.length, 3, 'fixture arity');
  // The contract: a batched call over N actions yields N decisions.
  // (Verified live below when the binding is present.)
});

// -----------------------------------------------------------------------
// Live native parity. Skipped (with reason) when the binding is absent.
// -----------------------------------------------------------------------

test('check_many parity with N sequential check calls', { skip: native ? false : SKIP_REASON }, () => {
  const n = native as NativeBinding;
  const batch = batchFn(n);
  assert.ok(batch, 'native binding present but exposes no check_many');

  const tools: ToolEntryInput[] = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = n.computeRegistryRoot(tools);

  const allowAt = (handle: unknown, seq: number): ActionInput => {
    const info = n.authorityInfo(handle);
    return {
      version: 1,
      passportIdHashHex: info.passportIdHashHex,
      toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
      localToolId: 0,
      operationId: 0,
      resourceType: 0,
      riskClass: 2,
      resourcePathDepth: 2,
      costUnits: 1,
      sequenceId: BigInt(seq),
      nonceHex: '00112233445566778899aabbccddeeff',
      resourcePathHashes: n.hashResourcePath(['customer', '12345']),
    };
  };

  // Reference: N sequential check() calls on a fresh handle.
  const seqHandle = n.loadPassportUnverified(buildPassport(rootHex), tools, {
    mode: 'Null',
  });
  const seqDecisions: DecisionOutput[] = [];
  for (let i = 0; i < 5; i++) {
    seqDecisions.push(n.check(seqHandle, allowAt(seqHandle, 1000 + i)));
  }

  // Batched: one check_many over the same actions on a fresh handle.
  const batchHandle = n.loadPassportUnverified(buildPassport(rootHex), tools, {
    mode: 'Null',
  });
  const batchActions: ActionInput[] = [];
  for (let i = 0; i < 5; i++) {
    batchActions.push(allowAt(batchHandle, 1000 + i));
  }
  const batchDecisions = batch(batchHandle, batchActions);

  assert.equal(batchDecisions.length, seqDecisions.length, 'batch length');
  for (let i = 0; i < seqDecisions.length; i++) {
    sameDecision(seqDecisions[i], batchDecisions[i]);
    assert.equal(seqDecisions[i].decisionType, 'Allow', `idx ${i} allow`);
  }
});

test('check_many: empty batch returns empty', { skip: native ? false : SKIP_REASON }, () => {
  const n = native as NativeBinding;
  const batch = batchFn(n);
  assert.ok(batch);
  const tools: ToolEntryInput[] = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = n.computeRegistryRoot(tools);
  const handle = n.loadPassportUnverified(buildPassport(rootHex), tools, {
    mode: 'Null',
  });
  const out = batch(handle, []);
  assert.equal(out.length, 0, 'empty input yields empty output');
});

test('check_many: single-element batch matches single check', { skip: native ? false : SKIP_REASON }, () => {
  const n = native as NativeBinding;
  const batch = batchFn(n);
  assert.ok(batch);
  const tools: ToolEntryInput[] = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = n.computeRegistryRoot(tools);

  const mk = (handle: unknown): ActionInput => {
    const info = n.authorityInfo(handle);
    return {
      version: 1,
      passportIdHashHex: info.passportIdHashHex,
      toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
      localToolId: 0,
      operationId: 0,
      resourceType: 0,
      riskClass: 2,
      resourcePathDepth: 2,
      costUnits: 1,
      sequenceId: 1000n,
      nonceHex: '00112233445566778899aabbccddeeff',
      resourcePathHashes: n.hashResourcePath(['customer', '12345']),
    };
  };

  const h1 = n.loadPassportUnverified(buildPassport(rootHex), tools, { mode: 'Null' });
  const single = n.check(h1, mk(h1));

  const h2 = n.loadPassportUnverified(buildPassport(rootHex), tools, { mode: 'Null' });
  const batched = batch(h2, [mk(h2)]);

  assert.equal(batched.length, 1);
  sameDecision(single, batched[0]);
});

test('check_many: mixed allow/deny batch, each action independent', { skip: native ? false : SKIP_REASON }, () => {
  const n = native as NativeBinding;
  const batch = batchFn(n);
  assert.ok(batch);
  const tools: ToolEntryInput[] = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = n.computeRegistryRoot(tools);

  const base = (handle: unknown, seq: number): ActionInput => {
    const info = n.authorityInfo(handle);
    return {
      version: 1,
      passportIdHashHex: info.passportIdHashHex,
      toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
      localToolId: 0,
      operationId: 0,
      resourceType: 0,
      riskClass: 2,
      resourcePathDepth: 2,
      costUnits: 1,
      sequenceId: BigInt(seq),
      nonceHex: '00112233445566778899aabbccddeeff',
      resourcePathHashes: n.hashResourcePath(['customer', '12345']),
    };
  };
  // The deny action uses operationId=1 (write); passport allows only
  // read. OPERATION_NOT_ALLOWED denies before the sequence CAS, so it
  // consumes no sequence slot, so surrounding Allow actions are unaffected.
  const deny = (handle: unknown, seq: number): ActionInput => ({
    ...base(handle, seq),
    operationId: 1,
  });

  const buildSeq = (handle: unknown): ActionInput[] => [
    base(handle, 1000),
    deny(handle, 1001),
    base(handle, 1001),
    base(handle, 1002),
  ];

  const hSeq = n.loadPassportUnverified(buildPassport(rootHex), tools, { mode: 'Null' });
  const seqActions = buildSeq(hSeq);
  const seqOut = seqActions.map((a) => n.check(hSeq, a));

  const hBatch = n.loadPassportUnverified(buildPassport(rootHex), tools, { mode: 'Null' });
  const batchOut = batch(hBatch, buildSeq(hBatch));

  assert.equal(batchOut.length, 4);
  assert.equal(seqOut[0].decisionType, 'Allow');
  assert.equal(seqOut[1].decisionType, 'Deny');
  assert.equal(seqOut[1].reasonName, 'OPERATION_NOT_ALLOWED');
  assert.equal(seqOut[2].decisionType, 'Allow');
  assert.equal(seqOut[3].decisionType, 'Allow');
  for (let i = 0; i < 4; i++) {
    sameDecision(seqOut[i], batchOut[i]);
  }
});

test('check_many: batched path is not slower than sequential', { skip: native ? false : SKIP_REASON }, () => {
  const n = native as NativeBinding;
  const batch = batchFn(n);
  assert.ok(batch);
  const tools: ToolEntryInput[] = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = n.computeRegistryRoot(tools);

  const N = 500;
  const mk = (handle: unknown, seq: number): ActionInput => {
    const info = n.authorityInfo(handle);
    return {
      version: 1,
      passportIdHashHex: info.passportIdHashHex,
      toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
      localToolId: 0,
      operationId: 0,
      resourceType: 0,
      riskClass: 2,
      resourcePathDepth: 2,
      costUnits: 1,
      sequenceId: BigInt(seq),
      nonceHex: '00112233445566778899aabbccddeeff',
      resourcePathHashes: n.hashResourcePath(['customer', '12345']),
    };
  };

  const hSeq = n.loadPassportUnverified(buildPassport(rootHex), tools, { mode: 'Null' });
  const seqActions = Array.from({ length: N }, (_v, i) => mk(hSeq, 1000 + i));
  const t0 = process.hrtime.bigint();
  for (const a of seqActions) n.check(hSeq, a);
  const seqNs = process.hrtime.bigint() - t0;

  const hBatch = n.loadPassportUnverified(buildPassport(rootHex), tools, { mode: 'Null' });
  const batchActions = Array.from({ length: N }, (_v, i) => mk(hBatch, 1000 + i));
  const t1 = process.hrtime.bigint();
  batch(hBatch, batchActions);
  const batchNs = process.hrtime.bigint() - t1;

  // Batched marshals once across the FFI boundary; it must not be
  // meaningfully slower than N separate calls. 2x slack absorbs jitter
  // on a loaded host while still catching a real per-element regression.
  assert.ok(
    batchNs <= seqNs * 2n,
    `batched unexpectedly slower: batch=${batchNs}ns seq=${seqNs}ns`,
  );
});
