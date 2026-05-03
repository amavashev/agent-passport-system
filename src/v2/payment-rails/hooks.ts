// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — composable governance hooks
// ══════════════════════════════════════════════════════════════════
// preAuthorize, emitReceipt, emitDenial. Pure functions; no DB,
// no event bus, no env. Rails embed these (or a custom GovernanceHooks
// implementation) to satisfy the contract from types.ts.
//
// Verification helpers verifyPaymentReceipt + verifyPaymentDenial
// reproduce the receipt_id and check the Ed25519 signature against
// the stored signer_did. Mirrors the failure-mode taxonomy in
// src/v2/accountability/verify/*.ts: INVALID_CLAIM_TYPE,
// RECEIPT_ID_MISMATCH, SIGNATURE_INVALID, plus payment-specific
// INVALID_DENIAL_REASON for denial verification.
// ══════════════════════════════════════════════════════════════════

import { sign, publicKeyFromPrivate, verify as edVerify } from '../../crypto/keys.js'
import {
  canonicalizeDenialForId,
  canonicalizeDenialForSig,
  canonicalizeReceiptForId,
  canonicalizeReceiptForSig,
  sha256Hex,
} from './canonicalize.js'
import type {
  DenialReason,
  EmitDenialInput,
  EmitReceiptInput,
  GovernanceHooks,
  PaymentDenial,
  PaymentRail,
  PaymentReceipt,
  PreAuthorizeInput,
  PreAuthorizeResult,
} from './types.js'

const VALID_DENIAL_REASONS: readonly DenialReason[] = [
  'no_commerce_scope',
  'spend_limit_exceeded',
  'wallet_revoked',
  'time_window_violation',
  'rail_error',
]

function _nowIso(): string {
  const d = new Date()
  return d.toISOString()
}

// ── preAuthorize ──────────────────────────────────────────────────

/**
 * Decide whether a delegation may authorize the requested spend on
 * the given rail. Pure function; no I/O.
 *
 * Order of checks (matches the denial_reason taxonomy precedence):
 *   1. wallet_revoked       — rail.isWalletRevoked(delegation.wallet_id)
 *   2. no_commerce_scope    — required_scope not in delegation.scope
 *   3. time_window_violation — outside [not_before, not_after]
 *   4. spend_limit_exceeded — amount > delegation.spend_limit_base_units
 *      OR currency mismatch between delegation and request
 *
 * Currency mismatch maps to spend_limit_exceeded (the spend limit is
 * denominated in delegation.currency; a request in a different
 * currency cannot be measured against it). Rail integrators that
 * want a separate error code can wrap preAuthorize and re-route.
 */
export function preAuthorize(
  input: PreAuthorizeInput,
  rail: PaymentRail,
): PreAuthorizeResult {
  const { delegation, required_scope, amount_base_units, currency } = input

  if (rail.isWalletRevoked(delegation.wallet_id)) {
    return { ok: false, denial_reason: 'wallet_revoked' }
  }

  if (!delegation.scope.includes(required_scope)) {
    return {
      ok: false,
      denial_reason: 'no_commerce_scope',
      reason_detail: `scope '${required_scope}' not in delegation`,
    }
  }

  const now = input.now ?? new Date()
  if (delegation.not_before !== undefined) {
    const nb = Date.parse(delegation.not_before)
    if (!Number.isNaN(nb) && now.getTime() < nb) {
      return {
        ok: false,
        denial_reason: 'time_window_violation',
        reason_detail: `not_before=${delegation.not_before}`,
      }
    }
  }
  if (delegation.not_after !== undefined) {
    const na = Date.parse(delegation.not_after)
    if (!Number.isNaN(na) && now.getTime() > na) {
      return {
        ok: false,
        denial_reason: 'time_window_violation',
        reason_detail: `not_after=${delegation.not_after}`,
      }
    }
  }

  if (delegation.currency !== currency) {
    return {
      ok: false,
      denial_reason: 'spend_limit_exceeded',
      reason_detail: `currency mismatch: delegation=${delegation.currency} request=${currency}`,
    }
  }

  // Compare base-unit strings as BigInt to handle values above 2^53.
  let limit: bigint
  let amount: bigint
  try {
    limit = BigInt(delegation.spend_limit_base_units)
    amount = BigInt(amount_base_units)
  } catch {
    return {
      ok: false,
      denial_reason: 'rail_error',
      reason_detail: 'amount_base_units or spend_limit_base_units not a valid integer string',
    }
  }
  if (amount > limit) {
    return {
      ok: false,
      denial_reason: 'spend_limit_exceeded',
      reason_detail: `amount=${amount} limit=${limit}`,
    }
  }

  return { ok: true }
}

// ── emitReceipt ───────────────────────────────────────────────────

export function emitReceipt(
  input: EmitReceiptInput,
  issuerPrivateKeyHex: string,
): PaymentReceipt {
  const signer_did = publicKeyFromPrivate(issuerPrivateKeyHex)
  const issued_at = input.issued_at ?? _nowIso()

  const draft: PaymentReceipt = {
    claim_type: 'aps:payment_receipt:v1',
    receipt_id: '',
    signer_did,
    issued_at,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: input.rail_name,
    amount_base_units: input.amount_base_units,
    currency: input.currency,
    tx_proof: input.tx_proof,
    signature: '',
  }
  if (input.invoice_id !== undefined) {
    draft.invoice_id = input.invoice_id
  }

  const receipt_id = sha256Hex(canonicalizeReceiptForId(draft))
  const withId: PaymentReceipt = { ...draft, receipt_id }
  const signature = sign(canonicalizeReceiptForSig(withId), issuerPrivateKeyHex)
  return { ...withId, signature }
}

// ── emitDenial ────────────────────────────────────────────────────

export function emitDenial(
  input: EmitDenialInput,
  issuerPrivateKeyHex: string,
): PaymentDenial {
  if (!VALID_DENIAL_REASONS.includes(input.denial_reason)) {
    throw new Error(
      `emitDenial: denial_reason must be one of ${VALID_DENIAL_REASONS.join(' | ')}, got '${input.denial_reason}'`,
    )
  }
  const signer_did = publicKeyFromPrivate(issuerPrivateKeyHex)
  const issued_at = input.issued_at ?? _nowIso()

  const draft: PaymentDenial = {
    claim_type: 'aps:payment_denial:v1',
    receipt_id: '',
    signer_did,
    issued_at,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: input.rail_name,
    amount_base_units: input.amount_base_units,
    currency: input.currency,
    denial_reason: input.denial_reason,
    signature: '',
  }
  if (input.reason_detail !== undefined) {
    draft.reason_detail = input.reason_detail
  }

  const receipt_id = sha256Hex(canonicalizeDenialForId(draft))
  const withId: PaymentDenial = { ...draft, receipt_id }
  const signature = sign(canonicalizeDenialForSig(withId), issuerPrivateKeyHex)
  return { ...withId, signature }
}

// ── Verification ──────────────────────────────────────────────────

export type ReceiptVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'

export interface ReceiptVerifyResult {
  valid: boolean
  reason?: ReceiptVerifyReason
}

export function verifyPaymentReceipt(receipt: PaymentReceipt): ReceiptVerifyResult {
  if (receipt.claim_type !== 'aps:payment_receipt:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  const expectedId = sha256Hex(canonicalizeReceiptForId(receipt))
  if (receipt.receipt_id !== expectedId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }
  if (!edVerify(canonicalizeReceiptForSig(receipt), receipt.signature, receipt.signer_did)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}

export type DenialVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'INVALID_DENIAL_REASON'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'

export interface DenialVerifyResult {
  valid: boolean
  reason?: DenialVerifyReason
}

export function verifyPaymentDenial(denial: PaymentDenial): DenialVerifyResult {
  if (denial.claim_type !== 'aps:payment_denial:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  if (!VALID_DENIAL_REASONS.includes(denial.denial_reason)) {
    return { valid: false, reason: 'INVALID_DENIAL_REASON' }
  }
  const expectedId = sha256Hex(canonicalizeDenialForId(denial))
  if (denial.receipt_id !== expectedId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }
  if (!edVerify(canonicalizeDenialForSig(denial), denial.signature, denial.signer_did)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}

// ── Composable GovernanceHooks bundle ─────────────────────────────

/**
 * Default GovernanceHooks implementation. Rails that want the
 * standard preAuthorize/emit semantics can use this; rails with
 * custom rules implement GovernanceHooks themselves.
 */
export function createDefaultGovernanceHooks(): GovernanceHooks {
  return {
    preAuthorize,
    emitReceipt,
    emitDenial,
  }
}
