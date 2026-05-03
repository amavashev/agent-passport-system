// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ACP — Agentic Commerce Protocol adapter (OpenAI + Stripe)
// ══════════════════════════════════════════════════════════════════
// Public functions:
//   preAuthorizeAcpCheckout(req, delegation)  → permit | deny+reason
//   apsToAcpError(reason)                     → AcpErrorType + AcpErrorCode
//   signAcpReceipt(input, privateKeyHex)      → AcpReceipt
//   verifyAcpReceipt(receipt, signerPubHex)   → AcpVerifyResult
//   signAcpDenial(input, privateKeyHex)       → AcpDenial
//   verifyAcpDenial(denial, signerPubHex)     → AcpVerifyResult
//   delegationToAcpAllowed(delegation)        → { allowed_merchants, allowed_currencies, max_total }
//   acpSessionToDelegationHints(session)      → partial V2Delegation derivation
//
// Spec-ambiguity calls (also documented in docs/governance/acp-interop.md):
//   - V2Delegation.scope.action_categories does not map 1:1 to ACP
//     items (ACP is line-item based, APS is action-class based). We
//     surface allowed_merchants and a max_total cents budget; line-
//     item filtering is gateway product, not protocol primitive.
//   - ACP idempotency conflicts produce a deterministic
//     'idempotency_conflict' denial mapped to the ACP error type
//     'request_not_idempotent' with code 'invalid'. Caller maintains
//     the idempotency cache; this adapter only emits the receipt.
//   - Receipt session_state captures whatever the merchant returned;
//     we don't synthesize a session ourselves.
// ══════════════════════════════════════════════════════════════════

import { createHash, randomUUID } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { publicKeyFromPrivate, sign, verify as edVerify } from '../../../crypto/keys.js'
import type { V2Delegation } from '../../types.js'
import {
  ACP_API_VERSION,
} from './types.js'
export { ACP_API_VERSION } from './types.js'
import type {
  AcpCheckoutSession,
  AcpCreateCheckoutSessionRequest,
  AcpDenial,
  AcpDenialReason,
  AcpErrorCode,
  AcpErrorType,
  AcpOp,
  AcpReceipt,
  AcpUpdateCheckoutSessionRequest,
  AcpVerifyResult,
} from './types.js'

// ── Internal canonical helpers ────────────────────────────────────

function sha256Hex(bytes: Uint8Array | string): string {
  const buf = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : Buffer.from(bytes)
  return createHash('sha256').update(buf).digest('hex')
}

function canonicalDigest(obj: unknown): string {
  return sha256Hex(canonicalizeJCS(obj))
}

function nowIso(): string {
  return new Date().toISOString()
}

// Internal: parse CSV-typed constraint values into trimmed string arrays.
function csvToList(s: string | undefined): string[] {
  if (!s) return []
  return s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

// ── APS ↔ ACP error mapping ───────────────────────────────────────

/**
 * Deterministic mapping from an APS denial reason to the ACP error
 * envelope a merchant would have returned. This is the reverse of
 * the merchant's view: when APS gates an ACP call BEFORE it reaches
 * the merchant, we still emit the ACP-shaped error so the caller can
 * surface it identically to a real merchant response.
 */
export function apsToAcpError(reason: AcpDenialReason): {
  type: AcpErrorType
  code: AcpErrorCode
  /** Optional JSONPath into the ACP request body. */
  param?: string
} {
  switch (reason) {
    case 'spend_limit_exceeded':
      return { type: 'invalid_request', code: 'invalid', param: '$.items' }
    case 'merchant_not_allowed':
      return { type: 'invalid_request', code: 'invalid', param: '$.items[0].id' }
    case 'delegation_expired':
      return { type: 'invalid_request', code: 'requires_sign_in' }
    case 'currency_mismatch':
      return { type: 'invalid_request', code: 'invalid', param: '$.currency' }
    case 'wallet_revoked':
      return { type: 'invalid_request', code: 'payment_declined' }
    case 'no_commerce_scope':
      return { type: 'invalid_request', code: 'requires_sign_in' }
    case 'idempotency_conflict':
      return { type: 'request_not_idempotent', code: 'invalid' }
    case 'invalid_session_state':
      return { type: 'invalid_request', code: 'invalid', param: '$.status' }
    case 'api_version_mismatch':
      return { type: 'service_unavailable', code: 'invalid' }
  }
}

// ── Crosswalk: V2Delegation → ACP authorization envelope ──────────

export interface AcpAllowedFromDelegation {
  /** Merchant identifiers (PSP merchant ids, domains, or platform ids). */
  allowed_merchants: string[]
  /** ISO 4217 lowercase. Empty = no currency constraint. */
  allowed_currencies: string[]
  /** Hard cap in minor units across all line items. null = no cap. */
  max_total: number | null
  /** Token expiry — ISO 8601 of policy_context.valid_until if set. */
  valid_until?: string
}

/**
 * Project a V2Delegation into the subset of ACP context it permits.
 * Used by preAuthorizeAcpCheckout and by callers that want to render
 * a delegation as a buyer-facing summary before initiating a session.
 *
 * Field sourcing (matches Stripe-Issuing and AP2 conventions):
 *   - max_total ← scope.resource_limits.spend_limit_cents (preferred,
 *     number-typed) OR scope.resource_limits['commerce.spend_limit']
 *     OR scope.constraints.spend_limit_cents (string fallback, parsed)
 *   - allowed_merchants ← scope.constraints.allowed_merchants (CSV)
 *   - allowed_currencies ← scope.constraints.allowed_currencies (CSV)
 *   - valid_until ← policy_context.valid_until
 */
export function delegationToAcpAllowed(delegation: V2Delegation): AcpAllowedFromDelegation {
  const limits = delegation.scope?.resource_limits ?? {}
  const constraints = delegation.scope?.constraints ?? {}

  let maxTotal: number | null = null
  if (typeof limits.spend_limit_cents === 'number' && Number.isFinite(limits.spend_limit_cents)) {
    maxTotal = limits.spend_limit_cents
  } else if (
    typeof limits['commerce.spend_limit'] === 'number' &&
    Number.isFinite(limits['commerce.spend_limit'])
  ) {
    maxTotal = limits['commerce.spend_limit']
  } else if (constraints.spend_limit_cents) {
    const parsed = Number(constraints.spend_limit_cents)
    if (Number.isFinite(parsed) && parsed >= 0) maxTotal = parsed
  }

  return {
    allowed_merchants: csvToList(constraints.allowed_merchants),
    allowed_currencies: csvToList(constraints.allowed_currencies).map((s) => s.toLowerCase()),
    max_total: maxTotal,
    valid_until: delegation.policy_context?.valid_until,
  }
}

// ── Crosswalk: ACP CheckoutSession → V2Delegation hints ───────────

/**
 * One-way derivation: given a CheckoutSession the merchant returned,
 * compute the V2Delegation fields a downstream gateway could pin
 * against. Lossy by design — line-item content does not survive.
 */
export function acpSessionToDelegationHints(session: AcpCheckoutSession): {
  scope: {
    action_categories: string[]
    constraints: {
      allowed_merchants?: string[]
      allowed_currencies: string[]
      spend_limit_cents: number
    }
  }
  notes: string[]
} {
  const totalEntry = session.totals.find((t) => t.type === 'total')
  const totalAmount = totalEntry?.amount ?? 0
  const merchant = session.payment_provider?.provider
  return {
    scope: {
      action_categories: ['commerce'],
      constraints: {
        allowed_merchants: merchant ? [merchant] : undefined,
        allowed_currencies: [session.currency.toLowerCase()],
        spend_limit_cents: totalAmount,
      },
    },
    notes: [
      'lossy: line-item content not preserved in V2Delegation derivation',
      'PSP merchant identifier may differ from settlement merchant id',
    ],
  }
}

// ── Pre-authorization gate ────────────────────────────────────────

export type AcpPreAuthorizeResult =
  | { allow: true }
  | { allow: false; reason: AcpDenialReason; detail?: string }

/**
 * Decide whether a checkout-session request is permitted under a
 * delegation BEFORE the agent calls the merchant. Pure function;
 * no I/O, no side effects, no state. Intended to be the rail-side
 * hook that emits a signed receipt or denial after this returns.
 */
export function preAuthorizeAcpCheckout(
  request: AcpCreateCheckoutSessionRequest | AcpUpdateCheckoutSessionRequest,
  delegation: V2Delegation,
  /** Currency of the merchant's catalog; ACP carries this only on the response. */
  expectedCurrency?: string,
): AcpPreAuthorizeResult {
  // 1. Delegation must include a 'commerce' action category.
  const actionCategories = delegation.scope?.action_categories ?? []
  if (!actionCategories.includes('commerce')) {
    return { allow: false, reason: 'no_commerce_scope', detail: 'delegation lacks commerce scope' }
  }

  // 2. Delegation must not be expired.
  const validUntil = delegation.policy_context?.valid_until
  if (validUntil) {
    const expiresAt = Date.parse(validUntil)
    if (Number.isFinite(expiresAt) && Date.now() > expiresAt) {
      return { allow: false, reason: 'delegation_expired', detail: validUntil }
    }
  }

  const allowed = delegationToAcpAllowed(delegation)

  // 3. Currency check — only if the call provides expectedCurrency.
  if (expectedCurrency && allowed.allowed_currencies.length > 0) {
    if (!allowed.allowed_currencies.includes(expectedCurrency.toLowerCase())) {
      return {
        allow: false,
        reason: 'currency_mismatch',
        detail: `${expectedCurrency} not in [${allowed.allowed_currencies.join(',')}]`,
      }
    }
  }

  // 4. Empty items → invalid session state. Real spend gating runs
  // at session-complete time when authoritative totals are present.
  if ('items' in request && Array.isArray(request.items) && allowed.max_total !== null) {
    const qtyTotal = request.items.reduce((acc, it) => acc + (it.quantity ?? 0), 0)
    if (qtyTotal === 0) {
      return { allow: false, reason: 'invalid_session_state', detail: 'no items' }
    }
  }

  return { allow: true }
}

/**
 * Final spend check, run when a session has been retrieved or
 * completed and authoritative totals are in hand. Separate from
 * preAuthorizeAcpCheckout because totals are a server-side property.
 */
export function checkAcpSessionUnderBudget(
  session: AcpCheckoutSession,
  delegation: V2Delegation,
): AcpPreAuthorizeResult {
  const allowed = delegationToAcpAllowed(delegation)
  if (allowed.max_total === null) return { allow: true }

  const totalEntry = session.totals.find((t) => t.type === 'total')
  if (!totalEntry) {
    return { allow: false, reason: 'invalid_session_state', detail: 'no total entry' }
  }
  if (totalEntry.amount > allowed.max_total) {
    return {
      allow: false,
      reason: 'spend_limit_exceeded',
      detail: `${totalEntry.amount} > ${allowed.max_total}`,
    }
  }

  if (allowed.allowed_currencies.length > 0) {
    if (!allowed.allowed_currencies.includes(session.currency.toLowerCase())) {
      return {
        allow: false,
        reason: 'currency_mismatch',
        detail: `${session.currency} not allowed`,
      }
    }
  }

  return { allow: true }
}

// ── Sign / verify receipts ────────────────────────────────────────

export interface SignAcpReceiptInput {
  op: AcpOp
  session_id: string
  /** Raw ACP request body (will be canonicalized + digested). */
  request_body: unknown
  /** Authoritative session state at receipt mint time. */
  session_state: AcpCheckoutSession
  delegation_ref?: string
  agent_id: string
}

export function signAcpReceipt(
  input: SignAcpReceiptInput,
  signerPrivateKeyHex: string,
): AcpReceipt {
  const signerPub = publicKeyFromPrivate(signerPrivateKeyHex)
  const requestDigest = canonicalDigest(input.request_body)

  const unsigned: Omit<AcpReceipt, 'signature'> = {
    receipt_id: `acpr_${randomUUID()}`,
    receipt_kind: 'acp.checkout_session_op',
    acp_version: ACP_API_VERSION,
    op: input.op,
    session_id: input.session_id,
    delegation_ref: input.delegation_ref,
    agent_id: input.agent_id,
    signer: signerPub,
    session_state: input.session_state,
    request_digest: requestDigest,
    issued_at: nowIso(),
  }

  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

const VALID_OPS: ReadonlySet<AcpOp> = new Set([
  'create',
  'update',
  'complete',
  'cancel',
  'retrieve',
])

export interface VerifyAcpReceiptOptions {
  now?: Date
  ttl_seconds?: number
  expected_signer?: string
}

export function verifyAcpReceipt(
  receipt: AcpReceipt,
  options: VerifyAcpReceiptOptions = {},
): AcpVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (receipt.acp_version !== ACP_API_VERSION) {
    return {
      valid: false,
      reason: 'INVALID_API_VERSION',
      detail: `expected ${ACP_API_VERSION} got ${receipt.acp_version}`,
    }
  }
  if (receipt.receipt_kind !== 'acp.checkout_session_op') {
    return { valid: false, reason: 'INVALID_RECEIPT_KIND', detail: receipt.receipt_kind }
  }
  if (!VALID_OPS.has(receipt.op)) {
    return { valid: false, reason: 'INVALID_OP', detail: receipt.op }
  }
  if (!receipt.session_id || !receipt.agent_id || !receipt.signer) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD' }
  }

  if (options.expected_signer && receipt.signer !== options.expected_signer) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'signer mismatch' }
  }

  const issuedMs = Date.parse(receipt.issued_at)
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'issued_at' }
  }
  const nowMs = (options.now ?? new Date()).getTime()
  if (nowMs - issuedMs > ttl * 1000) {
    return { valid: false, reason: 'EXPIRED', detail: `older than ${ttl}s` }
  }

  // signature verify — strip sig, canonicalize, verify
  const { signature, ...rest } = receipt
  const sigBytes = canonicalizeJCS(rest)
  if (!edVerify(sigBytes, signature, receipt.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

// ── Sign / verify denials ─────────────────────────────────────────

export interface SignAcpDenialInput {
  op: AcpOp
  session_id?: string
  request_body: unknown
  reason: AcpDenialReason
  delegation_ref?: string
  agent_id: string
}

export function signAcpDenial(
  input: SignAcpDenialInput,
  signerPrivateKeyHex: string,
): AcpDenial {
  const signerPub = publicKeyFromPrivate(signerPrivateKeyHex)
  const requestDigest = canonicalDigest(input.request_body)
  const mapped = apsToAcpError(input.reason)

  const unsigned: Omit<AcpDenial, 'signature'> = {
    denial_id: `acpd_${randomUUID()}`,
    denial_kind: 'acp.checkout_session_denial',
    acp_version: ACP_API_VERSION,
    op: input.op,
    session_id: input.session_id,
    delegation_ref: input.delegation_ref,
    agent_id: input.agent_id,
    signer: signerPub,
    reason: input.reason,
    acp_error_code: mapped.code,
    acp_error_type: mapped.type,
    acp_error_param: mapped.param,
    request_digest: requestDigest,
    issued_at: nowIso(),
  }

  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

export function verifyAcpDenial(
  denial: AcpDenial,
  options: VerifyAcpReceiptOptions = {},
): AcpVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (denial.acp_version !== ACP_API_VERSION) {
    return { valid: false, reason: 'INVALID_API_VERSION' }
  }
  if (denial.denial_kind !== 'acp.checkout_session_denial') {
    return { valid: false, reason: 'INVALID_RECEIPT_KIND' }
  }
  if (!VALID_OPS.has(denial.op)) {
    return { valid: false, reason: 'INVALID_OP' }
  }
  if (!denial.agent_id || !denial.signer || !denial.reason) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD' }
  }

  if (options.expected_signer && denial.signer !== options.expected_signer) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'signer mismatch' }
  }

  const issuedMs = Date.parse(denial.issued_at)
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'issued_at' }
  }
  const nowMs = (options.now ?? new Date()).getTime()
  if (nowMs - issuedMs > ttl * 1000) {
    return { valid: false, reason: 'EXPIRED' }
  }

  // mapping invariant: stored fields must match deterministic apsToAcpError
  const expected = apsToAcpError(denial.reason)
  if (denial.acp_error_code !== expected.code || denial.acp_error_type !== expected.type) {
    return {
      valid: false,
      reason: 'SIGNATURE_INVALID',
      detail: 'denial mapping mismatch (tampered or version drift)',
    }
  }

  const { signature, ...rest } = denial
  const sigBytes = canonicalizeJCS(rest)
  if (!edVerify(sigBytes, signature, denial.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}
