// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — public surface
// ══════════════════════════════════════════════════════════════════
// Generalized PaymentRail interface + composable governance hooks
// (preAuthorize, emitReceipt, emitDenial) + signed PaymentReceipt
// and PaymentDenial primitives + Nano reference adapter.
//
// SDK scope: interface, hooks, canonicalization, signature
// verification, reference adapter. Out of scope: custodial wallet,
// credential storage, tx routing, processor accounts. Those live in
// the private gateway.
// ══════════════════════════════════════════════════════════════════

export type {
  CreateInvoiceOpts,
  DelegationView,
  DenialReason,
  EmitDenialInput,
  EmitReceiptInput,
  GovernanceHooks,
  InvoiceStatus,
  PaymentDenial,
  PaymentInvoice,
  PaymentRail,
  PaymentReceipt,
  PreAuthorizeInput,
  PreAuthorizeResult,
  SendPaymentOpts,
  VerifyTransactionResult,
} from './types.js'

export {
  canonicalizeDenialForId,
  canonicalizeDenialForSig,
  canonicalizeInvoice,
  canonicalizeReceiptForId,
  canonicalizeReceiptForSig,
  invoiceDigest,
  sha256Hex as paymentRailsSha256Hex,
} from './canonicalize.js'

export {
  createDefaultGovernanceHooks,
  emitDenial,
  emitReceipt,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentReceipt,
} from './hooks.js'
export type {
  DenialVerifyReason,
  DenialVerifyResult,
  ReceiptVerifyReason,
  ReceiptVerifyResult,
} from './hooks.js'

export {
  createNanoRail,
  NanoPaymentRail,
  rawToXno,
  xnoToRaw,
} from './nano.js'
export type {
  FetchBlockInfo,
  FetchHistory,
  NanoBlockInfo,
  NanoHistoryEntry,
  NanoRailConfig,
} from './nano.js'

// ── Stripe Issuing reference adapter (agent-scoped virtual cards) ──
// Implements PaymentRail by minting one-time virtual cards via the
// Stripe Issuing API and intercepting issuing_authorization.request
// webhooks to enforce APS delegation gates BEFORE Stripe approves.
// Reference adapter is sk_test_ only; refuses sk_live_ in constructor.

export {
  createStripeIssuingRail,
  defaultMapDelegationToSpendingControls,
  StripeIssuingRail,
  verifyStripeSignature,
} from './stripe-issuing/index.js'
export type {
  Authorization as StripeAuthorization,
  AuthorizationDecision as StripeAuthorizationDecision,
  AuthorizationEvent as StripeAuthorizationEvent,
  CardholderRef as StripeCardholderRef,
  DelegationLookup as StripeDelegationLookup,
  FetchLike as StripeFetchLike,
  MerchantData as StripeMerchantData,
  SpendingControls as StripeSpendingControls,
  SpendingControlsMapper as StripeSpendingControlsMapper,
  SpendingLimit as StripeSpendingLimit,
  SpendingLimitInterval as StripeSpendingLimitInterval,
  StripeIssuingConfig,
  VirtualCard as StripeVirtualCard,
} from './stripe-issuing/index.js'
