// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Conformance golden negative-fixture generator
// ══════════════════════════════════════════════════════════════════
// This module materializes a frozen set of golden fixtures that a
// conformant verifier MUST agree on:
//
//   - GOLDEN VALID fixtures: a receipt that verifies clean. The
//     canonical JCS preimage and its SHA-256 receipt_id are pinned in
//     the fixture so a third-party implementation can byte-match.
//   - NEGATIVE fixtures: each one is constructed to fail verification
//     for exactly one stated reason. The reason is part of the fixture
//     so the conformance test can assert WHY the rejection happened,
//     not merely THAT it happened.
//
// Everything here is deterministic. Keys and timestamps are pinned so
// re-running the generator reproduces the same bytes. The generator
// reuses the shipped SDK construct/verify functions; it does not
// re-implement signing or canonicalization. This keeps the fixtures
// honest: they are signed by the same code path production uses.
//
// SCOPE OF CLAIM (dogfooded):
//   Proves: the negatives below are rejected by the cited verifier for
//     the cited reason, and the golden valid fixture verifies under the
//     shipped Ed25519 + RFC 8785 JCS code path.
//   Does NOT prove: that a real-world agent behaved well, that the
//     signer's key was honestly held, or that the action the receipt
//     describes actually happened off-protocol. A receipt is a signed
//     declaration, not a causal proof.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../src/crypto/keys.js'
import { createActionReceipt } from '../../src/v2/accountability/construct/action.js'
import { verifyActionReceipt } from '../../src/v2/accountability/verify/action.js'
import type { ActionReceipt } from '../../src/v2/accountability/types/action.js'
import type { ScopeOfClaim } from '../../src/v2/accountability/types/base.js'

// ── Pinned deterministic key material (test-only, never production) ──
// 32-byte Ed25519 private keys, hex. Distinct signer and principal so
// the wrong-principal negative is expressible.
export const SIGNER_PRIV =
  '1111111111111111111111111111111111111111111111111111111111111111'
export const PRINCIPAL_PRIV =
  '2222222222222222222222222222222222222222222222222222222222222222'
export const ATTACKER_PRIV =
  '3333333333333333333333333333333333333333333333333333333333333333'

export const SIGNER_DID = publicKeyFromPrivate(SIGNER_PRIV)
export const PRINCIPAL_DID = publicKeyFromPrivate(PRINCIPAL_PRIV)
export const ATTACKER_DID = publicKeyFromPrivate(ATTACKER_PRIV)

// Frozen clock so timestamp-sensitive fixtures are reproducible.
export const FIXED_NOW = '2026-05-01T12:00:00.000Z'

const SCOPE: ScopeOfClaim = {
  asserts:
    'aps:action:v1. the gateway observed the agent issue this action under the cited delegation chain.',
  does_not_assert: [
    'that the off-protocol side effect actually completed',
    'that the agent understood the consequences of the action',
    'that the underlying business outcome was correct',
  ],
  capture_mode: 'gateway_observed',
  completeness: 'complete',
  self_attested: false,
}

// ── Reasons a conformant verifier rejects a receipt ─────────────────
// The crypto layer (verifyActionReceipt) closes three modes directly.
// The remaining modes are CONTEXT rejections: the signature is fine but
// the receipt is being used outside the envelope it was issued for. A
// conformant verifier MUST apply both layers.
export type RejectReason =
  // crypto-layer (verifyActionReceipt)
  | 'INVALID_CLAIM_TYPE'
  | 'RECEIPT_ID_MISMATCH' // mismatched-hash / tampered body
  | 'SIGNATURE_INVALID' // invalid signature
  // context-layer (verifyReceiptContext)
  | 'DELEGATION_EXPIRED' // expired delegation
  | 'DELEGATION_REVOKED' // revoked / stale revocation not honored
  | 'OVER_BUDGET' // over-budget action
  | 'WRONG_PRINCIPAL' // wrong-principal: receipt principal != asserted beneficiary
  | 'STALE_POLICY' // policy version evaluated is older than the active one
  | 'REPLAYED' // receipt_id already seen in this verification window
  | 'WRONG_CLAIM' // valid receipt presented as proof of a claim it does not make
  | 'POLICY_NOT_EXECUTED' // policy evaluated but execution never happened

// Context an external verifier checks the receipt against. None of this
// is inside the signed bytes; it is the verifier's own ground truth.
export interface ReceiptContext {
  now: string
  /** Delegation chain root the verifier currently treats as authoritative. */
  active_delegation_root: string
  /** Delegation expiry, ISO 8601. Receipt timestamp must be at or before this. */
  delegation_expires_at: string
  /** Delegation roots the verifier has seen revoked. */
  revoked_delegation_roots: string[]
  /** Budget ceiling, integer base units. */
  budget_base_units: bigint
  /** Cost the receipt's action draws against the budget, base units. */
  action_cost_base_units: bigint
  /** Principal the verifier expects to be accountable. */
  expected_principal_did: string
  /** Policy version the verifier currently enforces. */
  active_policy_version: number
  /** Policy version actually evaluated, carried in the receipt's policy_ref. */
  evaluated_policy_version: number
  /** receipt_ids the verifier has already accepted in this window. */
  seen_receipt_ids: string[]
  /** The claim the receipt is being presented to support. */
  presented_as_claim_type: string
  /** Whether an execution attestation accompanies the policy decision. */
  execution_attested: boolean
}

export interface ContextVerifyResult {
  valid: boolean
  reason?: RejectReason
}

/**
 * Context-layer verification. Runs the crypto verifier first, then the
 * verifier-responsibility checks an external party MUST apply before
 * treating a receipt as authoritative. Order matters: a tampered or
 * unsigned receipt is rejected before any context is consulted.
 */
export function verifyReceiptContext(
  receipt: ActionReceipt,
  ctx: ReceiptContext,
): ContextVerifyResult {
  const crypto = verifyActionReceipt(receipt)
  if (!crypto.valid) {
    return { valid: false, reason: crypto.reason as RejectReason }
  }

  // wrong-claim: the receipt is sound but does not make the claim it is
  // being presented to support.
  if (ctx.presented_as_claim_type !== receipt.claim_type) {
    return { valid: false, reason: 'WRONG_CLAIM' }
  }

  // wrong-principal: receipt accountable party is not the expected one.
  if (receipt.agent_did !== ctx.expected_principal_did) {
    return { valid: false, reason: 'WRONG_PRINCIPAL' }
  }

  // revoked delegation: cascade revocation must be honored even if the
  // receipt itself is older than the revocation event.
  if (ctx.revoked_delegation_roots.includes(receipt.delegation_chain_root)) {
    return { valid: false, reason: 'DELEGATION_REVOKED' }
  }

  // expired delegation: the receipt was issued after the chain expired.
  if (receipt.timestamp > ctx.delegation_expires_at) {
    return { valid: false, reason: 'DELEGATION_EXPIRED' }
  }

  // over-budget: the action draws more than the ceiling allows.
  if (ctx.action_cost_base_units > ctx.budget_base_units) {
    return { valid: false, reason: 'OVER_BUDGET' }
  }

  // stale-policy: the policy version evaluated is older than the active
  // one the verifier now enforces.
  if (ctx.evaluated_policy_version < ctx.active_policy_version) {
    return { valid: false, reason: 'STALE_POLICY' }
  }

  // replay: the receipt_id has already been accepted in this window.
  if (ctx.seen_receipt_ids.includes(receipt.receipt_id)) {
    return { valid: false, reason: 'REPLAYED' }
  }

  // policy-evaluated-but-never-executed: a policy decision is not a
  // proof that the gated action ran. Without an execution attestation
  // the receipt cannot be treated as proof of execution.
  if (!ctx.execution_attested) {
    return { valid: false, reason: 'POLICY_NOT_EXECUTED' }
  }

  return { valid: true }
}

// ── Golden fixture shapes ───────────────────────────────────────────

export interface GoldenValidFixture {
  kind: 'golden_valid'
  id: string
  description: string
  receipt: ActionReceipt
  /** The exact JCS preimage SHA-256'd to produce receipt_id. */
  canonical_preimage_for_id: string
  /** Pinned SHA-256 of the preimage above. Equals receipt.receipt_id. */
  expected_receipt_id_sha256: string
  /** The exact JCS preimage the Ed25519 signature is computed over. */
  canonical_preimage_for_signature: string
}

export interface NegativeFixture {
  kind: 'negative'
  id: string
  description: string
  /** The reason a conformant verifier MUST reject this fixture. */
  expected_reject_reason: RejectReason
  /** Which verification layer surfaces the rejection. */
  layer: 'crypto' | 'context'
  receipt: ActionReceipt
  /** Verifier context the receipt is checked against (context layer). */
  context: ReceiptContext
}

// Baseline cost and budget kept well inside limits so the valid path
// and most negatives do not trip the budget gate unless they intend to.
const BASE_COST = 1_000n
const BASE_BUDGET = 1_000_000n

function baseContext(receipt: ActionReceipt): ReceiptContext {
  return {
    now: FIXED_NOW,
    active_delegation_root: receipt.delegation_chain_root,
    delegation_expires_at: '2027-01-01T00:00:00.000Z',
    revoked_delegation_roots: [],
    budget_base_units: BASE_BUDGET,
    action_cost_base_units: BASE_COST,
    expected_principal_did: PRINCIPAL_DID,
    active_policy_version: 3,
    evaluated_policy_version: 3,
    seen_receipt_ids: [],
    presented_as_claim_type: 'aps:action:v1',
    execution_attested: true,
  }
}

const DELEGATION_ROOT =
  '4444444444444444444444444444444444444444444444444444444444444444'

/** Build the canonical golden valid receipt with pinned inputs. */
function buildValidReceipt(): ActionReceipt {
  return createActionReceipt(
    {
      timestamp: FIXED_NOW,
      scope_of_claim: SCOPE,
      agent_did: PRINCIPAL_DID,
      delegation_chain_root: DELEGATION_ROOT,
      policy_ref: 'policy:v3',
      action: {
        kind: 'http_post',
        target: 'https://api.example.test/orders',
        parameters: { amount: '1000', currency: 'USD' },
      },
      side_effect_classes: ['financial', 'external_message'],
    },
    SIGNER_PRIV,
  )
}

/** Recompute the canonical preimages for a finished receipt. */
function preimages(receipt: ActionReceipt): {
  forId: string
  forSig: string
  idHash: string
} {
  const forIdDraft = { ...receipt, receipt_id: '', signature: '' }
  const forId = canonicalizeJCS(forIdDraft)
  const idHash = createHash('sha256').update(forId, 'utf8').digest('hex')
  const forSig = canonicalizeJCS({ ...receipt, signature: '' })
  return { forId, forSig, idHash }
}

export function buildGoldenValid(): GoldenValidFixture {
  const receipt = buildValidReceipt()
  const { forId, forSig, idHash } = preimages(receipt)
  return {
    kind: 'golden_valid',
    id: 'GOLD-VALID-001',
    description:
      'A clean aps:action:v1 receipt. Verifies under the shipped Ed25519 + RFC 8785 JCS path. receipt_id equals sha256 of the empty-id, empty-signature canonical form.',
    receipt,
    canonical_preimage_for_id: forId,
    expected_receipt_id_sha256: idHash,
    canonical_preimage_for_signature: forSig,
  }
}

export function buildNegatives(): NegativeFixture[] {
  const valid = buildValidReceipt()
  const negatives: NegativeFixture[] = []

  // 1. invalid signature. flip the last hex nibble of the signature.
  {
    const lastChar = valid.signature.slice(-1)
    const flipped = lastChar === '0' ? '1' : '0'
    const receipt: ActionReceipt = {
      ...valid,
      signature: valid.signature.slice(0, -1) + flipped,
    }
    negatives.push({
      kind: 'negative',
      id: 'NEG-SIGNATURE-INVALID',
      description:
        'Signature byte flipped. The Ed25519 signature no longer verifies under signer_did.',
      expected_reject_reason: 'SIGNATURE_INVALID',
      layer: 'crypto',
      receipt,
      context: baseContext(receipt),
    })
  }

  // 2. mismatched hash. mutate the action body after signing without
  //    recomputing receipt_id. receipt_id no longer matches the body.
  {
    const receipt: ActionReceipt = {
      ...valid,
      action: { ...valid.action, target: 'https://evil.example.test/drain' },
    }
    negatives.push({
      kind: 'negative',
      id: 'NEG-MISMATCHED-HASH',
      description:
        'Action target rewritten after signing. receipt_id no longer equals sha256 of the canonical body.',
      expected_reject_reason: 'RECEIPT_ID_MISMATCH',
      layer: 'crypto',
      receipt,
      context: baseContext(receipt),
    })
  }

  // 3. wrong claim type. present a non-action receipt as aps:action:v1.
  {
    const tampered = { ...valid, claim_type: 'aps:custody:v1' } as unknown as ActionReceipt
    negatives.push({
      kind: 'negative',
      id: 'NEG-WRONG-CLAIM-TYPE',
      description:
        'claim_type changed to aps:custody:v1. The action verifier rejects a receipt that is not aps:action:v1.',
      expected_reject_reason: 'INVALID_CLAIM_TYPE',
      layer: 'crypto',
      receipt: tampered,
      context: baseContext(tampered),
    })
  }

  // 4. expired delegation. receipt issued after the chain expired.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.delegation_expires_at = '2026-04-01T00:00:00.000Z' // before FIXED_NOW
    negatives.push({
      kind: 'negative',
      id: 'NEG-DELEGATION-EXPIRED',
      description:
        'Cryptographically sound receipt issued at 2026-05-01 against a delegation that expired 2026-04-01.',
      expected_reject_reason: 'DELEGATION_EXPIRED',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 5. stale revocation. the delegation root is on the revoked list and
  //    the verifier MUST honor that even though the receipt predates it.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.revoked_delegation_roots = [receipt.delegation_chain_root]
    negatives.push({
      kind: 'negative',
      id: 'NEG-STALE-REVOCATION',
      description:
        'The receipt is valid but its delegation chain root was revoked. A verifier that ignores stale revocation state would wrongly accept it.',
      expected_reject_reason: 'DELEGATION_REVOKED',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 6. over-budget. action cost exceeds the ceiling.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.budget_base_units = 500n
    ctx.action_cost_base_units = 1_000n
    negatives.push({
      kind: 'negative',
      id: 'NEG-OVER-BUDGET',
      description:
        'Action draws 1000 base units against a 500 base-unit ceiling. The spend gate rejects it.',
      expected_reject_reason: 'OVER_BUDGET',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 7. wrong principal. the receipt's accountable party is not the one
  //    the verifier expects to be on the hook.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.expected_principal_did = ATTACKER_DID
    negatives.push({
      kind: 'negative',
      id: 'NEG-WRONG-PRINCIPAL',
      description:
        'The receipt names PRINCIPAL_DID as accountable, but it is presented to discharge a duty owed by a different principal.',
      expected_reject_reason: 'WRONG_PRINCIPAL',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 8. stale policy. the evaluated policy version is older than active.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.active_policy_version = 5
    ctx.evaluated_policy_version = 3
    negatives.push({
      kind: 'negative',
      id: 'NEG-STALE-POLICY',
      description:
        'The decision was made against policy v3 while the verifier now enforces v5. A stale-policy decision is not authoritative.',
      expected_reject_reason: 'STALE_POLICY',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 9. replayed. the receipt_id has already been accepted this window.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.seen_receipt_ids = [receipt.receipt_id]
    negatives.push({
      kind: 'negative',
      id: 'NEG-REPLAYED',
      description:
        'A previously accepted receipt is replayed. The verifier MUST reject a receipt_id it has already honored in the window.',
      expected_reject_reason: 'REPLAYED',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 10. wrong claim. a valid receipt presented as proof of something it
  //     does not assert (e.g. a policy decision presented as execution).
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.presented_as_claim_type = 'aps:payment_receipt:v1'
    negatives.push({
      kind: 'negative',
      id: 'NEG-WRONG-CLAIM',
      description:
        'A sound aps:action:v1 receipt is presented as an aps:payment_receipt:v1. A valid receipt does not prove a claim it never made.',
      expected_reject_reason: 'WRONG_CLAIM',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 11. policy evaluated but execution never happened.
  {
    const receipt = valid
    const ctx = baseContext(receipt)
    ctx.execution_attested = false
    negatives.push({
      kind: 'negative',
      id: 'NEG-POLICY-NOT-EXECUTED',
      description:
        'A policy decision exists but no execution attestation accompanies it. A permit is not a proof that the action ran.',
      expected_reject_reason: 'POLICY_NOT_EXECUTED',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  // 12. unverified external evidence. a receipt that self-attests an
  //     external fact with no independent attestation. We surface this by
  //     marking scope_of_claim.self_attested true and routing it as a
  //     wrong-claim when presented as gateway-observed evidence.
  {
    const selfAttestedScope: ScopeOfClaim = {
      ...SCOPE,
      capture_mode: 'self_attested',
      self_attested: true,
      asserts:
        'aps:action:v1. the agent self-declares it took this action. No gateway or runtime attestation backs it.',
    }
    const receipt = createActionReceipt(
      {
        timestamp: FIXED_NOW,
        scope_of_claim: selfAttestedScope,
        agent_did: PRINCIPAL_DID,
        delegation_chain_root: DELEGATION_ROOT,
        policy_ref: 'policy:v3',
        action: {
          kind: 'external_oracle_read',
          target: 'https://oracle.example.test/price',
          parameters: { claim: 'price=100' },
        },
        side_effect_classes: ['internal_only'],
      },
      SIGNER_PRIV,
    )
    const ctx = baseContext(receipt)
    // Presented as gateway-observed evidence, but it is self-attested.
    ctx.presented_as_claim_type = 'aps:gateway_observed:v1'
    negatives.push({
      kind: 'negative',
      id: 'NEG-UNVERIFIED-EXTERNAL-EVIDENCE',
      description:
        'A self-attested oracle read is presented as gateway-observed evidence. self_attested receipts carry lower evidentiary weight and must not be promoted to observed evidence.',
      expected_reject_reason: 'WRONG_CLAIM',
      layer: 'context',
      receipt,
      context: ctx,
    })
  }

  return negatives
}
