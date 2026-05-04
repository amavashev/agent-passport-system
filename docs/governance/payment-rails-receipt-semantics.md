# Payment-Rails Receipt Semantics — Negative Evidentiary Boundary

> Audience: rail-adapter authors, gateway implementors, APSBundle aggregator authors, paper reviewers.

## Why this exists

Phase 4.1 / Q1 binds the five rail receipt types into the APS accountability evidence canon. A signed `PaymentReceipt`, `AcpReceipt`, `MppApsReceipt`, `SignedAP2Mandate`, or Stripe-Issuing receipt now extends `AccountabilityReceiptBase` and registers in [`src/v2/claim-evidence-types.ts`](../../src/v2/claim-evidence-types.ts). That gives them all the downstream affordances of accountability evidence: APSBundle aggregation, drift detection, replay engines, contestability cascades.

It also creates a failure mode the architecture must explicitly prevent: **receipt laundering**. A `PaymentReceipt` in an APSBundle is mechanically valid evidence, and it's tempting for verifiers to read that as "the recipient earned the money." The receipt does NOT prove that. It proves something narrower. The boundary needs to be codified in the type, in the doc, and in aggregator UX so the narrower meaning survives composition.

This doc states the negative evidentiary semantic for each rail. Cited verbatim from JSDoc on each receipt type — the JSDoc is canonical; this doc is the cross-rail summary.

## What every rail receipt proves and does NOT prove

### Foundation `PaymentReceipt` (Nano + any rail riding `emitReceipt`)

**Claim type:** `rail.payment.v1` (legacy: `aps:payment_receipt:v1`)

A `PaymentReceipt` proves:
- A payment instruction reached the rail under V2Delegation D
- The rail returned the recorded outcome (`tx_proof` anchors it)
- The instruction was canonically signed by the issuer

It does NOT prove:
- The recipient earned the value (use AttributionReceipt or DeliveryReceipt)
- The contribution backing the payment was valid
- Settlement is final (rails have refund / dispute / chargeback windows)
- The counterparty's legal identity is what they claim

### `AcpReceipt` (Agentic Commerce Protocol — OpenAI + Stripe)

**Claim type:** `rail.acp.v1`

An `AcpReceipt` proves:
- An ACP checkout-session operation (`create`/`update`/`complete`/`cancel`/`retrieve`) was issued under a V2Delegation scoped to it
- The canonical request body digest was bound to the `delegation_ref`
- The merchant's frozen `session_state` was captured at receipt mint time

It does NOT prove:
- Funds settled successfully (an ACP op may complete and still be reversed)
- The merchant's legal identity is what `payment_provider.provider` claims
- The buyer received the goods or services
- Idempotency was enforced (caller maintains the idempotency cache)

### `MppApsReceipt` (Machine Payments Protocol — Stripe + Tempo + Visa)

**Claim type:** `rail.mpp.v1`

An `MppApsReceipt` proves:
- An MPP 402 challenge was satisfied by an `Authorization: Payment` proof
- The chosen `method_type`, `currency`, and `amount` fell inside the V2Delegation's allow-list and per-charge cap at gate time
- The resource server returned a `Payment-Receipt` header

It does NOT prove:
- On-chain or processor-side settlement finality (Tempo / Lightning preimages and card chargeback windows are out of scope)
- The resource served was what the buyer expected
- Replay was prevented (caller maintains the nonce cache)
- The counterparty's legal identity matches the resource URL

### `SignedAP2Mandate` (Google Agent Payments Protocol v0.2)

**Claim type:** `rail.ap2.mandate.v1`

A `SignedAP2Mandate` proves:
- An AP2 mandate dict was issued and signed by the named APS signer
- The mandate's authority (`cnf`, `iat`, `exp`, `vct`) is byte-bound by the Ed25519 signature over `canonicalize_jcs(mandate)`
- At signing time, the cited V2Delegation's spend cap and validity window were honored by the construction function

It does NOT prove:
- A payment occurred — a mandate is a permission, not a settlement (use `PaymentReceipt` or rail-specific receipts for settlement evidence)
- The merchant accepted the mandate at the wire layer (AP2 v0.2 wire format is SD-JWT; the APS shape is for cross-impl audit only)
- The buyer's identity is what `cnf.jwk` claims (cnf is a key, not an identity)
- Future mandate use will fall inside scope (replay is gateway product)

### Stripe-Issuing receipt (rides foundation)

**Claim type:** `rail.payment.v1` with `rail_name: 'stripe-issuing'`

A Stripe-Issuing rail receipt is a foundation `PaymentReceipt` minted by `handleAuthorizationWebhook` after APS gates pass and Stripe is told to approve. It carries `tx_proof = auth.id`. The negative evidentiary semantic of the foundation `PaymentReceipt` applies in full. Additional Stripe-specific notes:

It additionally does NOT prove:
- The Stripe authorization was final (Stripe authorizations can still be reversed by the network or merchant)
- The cardholder's KYC matches the agent's identity (gateway product)
- The merchant's MCC code reflects what was actually sold

## What APSBundle aggregators MUST enforce

A `PaymentReceipt` (or any rail receipt above) inside an `APSBundle` says **"money moved on the rail"**, NOT **"the recipient earned it."** Aggregators that surface the bundle to a downstream verifier must propagate this distinction. Concretely:

- A `BATCH_ATTESTED` claim resolved by a bundle that contains only rail receipts is NOT sufficient evidence for `AUTHORITY_TO_EXECUTE` (which requires `AuthorityBoundaryReceipt`) or for any contribution-validity claim.
- The `forbiddenSubstitutions` map in [`claim-evidence-types.ts`](../../src/v2/claim-evidence-types.ts) is the authoritative wire — extend it as new claim types are added.
- A rail receipt's `scope_of_claim.does_not_assert[]` is enumerated for a reason. Verifiers that want to make a stronger claim must collect additional evidence (an `AttributionReceipt` for entitlement, a `DeliveryReceipt` for fulfillment, a `SettlementRecord` for contribution-backed payment finality).

## Compatibility-superset migration

The Phase 4.1 / Q1 fields (`claim_type`, `timestamp`, `scope_of_claim`) are **optional** on every rail receipt type. Receipts minted by the new accountability-aligned signing path populate them. Legacy receipts (no `claim_type`, no `timestamp`, no `scope_of_claim`) continue to verify under the existing per-rail verifier path.

Opt-in mechanism per rail:

| Rail | Opt-in |
|---|---|
| Foundation (`emitReceipt` / `emitDenial`) | `EmitReceiptInput.accountability_shape: true` OR supply `scope_of_claim` |
| ACP (`signAcpReceipt`) | `SignAcpReceiptInput.accountability_shape: true` OR supply `scope_of_claim` |
| MPP (`signMppReceipt`) | `SignMppReceiptInput.accountability_shape: true` OR supply `scope_of_claim` |
| AP2 (`signAp2Mandate`) | `SignAp2MandateOptions.accountability_shape: true` OR supply `scope_of_claim` |
| Stripe-Issuing | `StripeIssuingConfig.accountabilityShape: true` (rides foundation) |

When the new shape is in use, the verifier additionally enforces:
- `claim_type` matches the rail's expected literal (e.g. `'rail.payment.v1'`)
- `timestamp === issued_at` (consistency check)
- `scope_of_claim.asserts` is a non-empty string

When the new shape is NOT in use (legacy receipt), the verifier path is unchanged. This is the compatible-superset contract: existing fixtures, existing receipts, existing tests all continue to verify.

## Reference

- [`src/v2/accountability/types/base.ts`](../../src/v2/accountability/types/base.ts) — `AccountabilityReceiptBase` + `ScopeOfClaim`
- [`src/v2/claim-evidence-types.ts`](../../src/v2/claim-evidence-types.ts) — `RecordType` enum + `RAIL_RECEIPT_CLAIM_TYPES` map
- [`docs/governance/payment-rails-denial-vocabulary.md`](./payment-rails-denial-vocabulary.md) — Tier-1 / Tier-2 denial taxonomy
- Audit B (private) — P2 finding that surfaced this gap
- DECISIONS.md `2026-05-04 — Phase 4 architecture` entry — Q1 spec
