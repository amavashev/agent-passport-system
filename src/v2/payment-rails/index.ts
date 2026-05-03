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

// ── AP2 v0.2 interop adapter (Google Agent Payments Protocol) ────
// Pinned to AP2 v0.2 (April 2026). Maps APS V2Delegation to AP2
// mandate dicts (CheckoutMandate / OpenCheckoutMandate / PaymentMandate
// / OpenPaymentMandate) and back.

export {
  AP2_VERSION,
  ap2MandateToApsDelegation,
  apsToAp2CartMandate,
  apsToAp2IntentMandate,
  apsToAp2OpenPaymentMandate,
  apsToAp2PaymentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
} from './ap2/index.js'

export type {
  AP2AllowedMerchantsConstraint,
  AP2AllowedPayeesConstraint,
  AP2AllowedPaymentInstrumentsConstraint,
  AP2Amount,
  AP2AmountRangeConstraint,
  AP2BudgetConstraint,
  AP2CheckoutConstraint,
  AP2CheckoutMandate,
  AP2Cnf,
  AP2Item,
  AP2LineItemRequirement,
  AP2LineItemsConstraint,
  AP2Mandate,
  AP2Merchant,
  AP2OpenCheckoutMandate,
  AP2OpenPaymentMandate,
  AP2PaymentConstraint,
  AP2PaymentInstrument,
  AP2PaymentMandate,
  AP2PaymentReferenceConstraint,
  AP2Pisp,
  AP2VctCheckout,
  AP2VctOpenCheckout,
  AP2VctOpenPayment,
  AP2VctPayment,
  Ap2VerifyReason,
  Ap2VerifyResult,
  Ap2ToApsOptions,
  ApsToAp2CartOptions,
  ApsToAp2IntentOptions,
  ApsToAp2OpenPaymentOptions,
  ApsToAp2PaymentOptions,
  CartDetails,
  CartMandate,
  IntentMandate,
  SignedAP2Mandate,
  VerifyAp2MandateOptions,
} from './ap2/index.js'

// ── Conformance harness ───────────────────────────────────────────
// Standard scenarios any third-party PaymentRail adapter can run to
// claim conformance to the APS governance contract. See
// docs/governance/payment-rail-conformance.md for the full guide.

export {
  HARNESS_FIXED_NOW,
  HARNESS_ISSUER_PRIV,
  runConformance,
  STANDARD_SCENARIOS,
} from './conformance/index.js'

export type {
  ConformanceContext,
  ConformanceReport,
  ConformanceScenario,
  RunConformanceOpts,
  ScenarioOutcome,
  ScenarioReport,
} from './conformance/index.js'
