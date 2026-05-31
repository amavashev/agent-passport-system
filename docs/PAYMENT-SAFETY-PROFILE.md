# Payment Safety Profile

*Status: Production-Extension.*

This is a profile, not a new primitive. It names a set of requirements an agent-initiated payment flow MUST satisfy to claim conformance to the APS payment safety bar. Every requirement here is already expressible with shipped APS fields. The profile is the checklist that ties them together so a verifier and an operator agree on what "safe" means before money moves.

A payment flow conforms to this profile when it satisfies every MUST below. Partial conformance is not conformance: a flow that matches amounts but skips replay protection is outside the profile.

## P-1: Wallet binding is mandatory

The acting passport MUST have the target wallet bound before any payment is authorized. The action carries a `walletRef`, and `commercePreflight()` denies with `WALLET_NOT_BOUND` unless that wallet is currently bound to the acting passport.

- MUST: every payment action references a `walletRef`.
- MUST: the gateway runs the structural wallet-binding check at preflight.
- A payment flow that authorizes against an unbound wallet does not conform.

## P-2: Idempotency is mandatory

Every payment action MUST carry an idempotency key, and the flow MUST honor it. A retried request with the same key returns the original outcome rather than authorizing a second payment.

- MUST: the action carries an `idempotencyKey`.
- MUST: the flow consults an idempotency store within a declared window before authorizing.
- MUST: a duplicate key inside the window returns the first decision, not a new charge.

## P-3: Payment evidence is signature-verified

Every payment receipt and denial MUST be verified, not trusted on receipt. A verifier runs the receipt through the crypto layer (claim type, `receipt_id` recomputation, Ed25519 signature) before relying on it.

- MUST: the verifier calls the payment receipt verifier on every receipt it relies on.
- MUST: a receipt that fails verification is treated as no evidence at all.
- MUST: denials carry a closed-taxonomy reason and are verified the same way.

## P-4: Amount, currency, and recipient match across intent, decision, and receipt

The three records that bracket a payment MUST agree on the money. The amount in base units, the currency, and the recipient declared at intent MUST equal those in the policy decision and in the final receipt.

- MUST: `amount_base_units` is identical across intent, decision, and receipt.
- MUST: `currency` is identical across all three.
- MUST: the recipient (wallet or address) is identical across all three.
- A mismatch on any of the three is a refusal, not a rounding note. The intent the principal approved is the only one that may settle.

## P-5: Replay protection is explicit

Replay protection MUST be a stated property of the flow, not an accident of timing. The flow declares a replay window and records accepted `receipt_id` values within it.

- MUST: the flow declares its replay window.
- MUST: a `receipt_id` already accepted in the window is rejected with `REPLAYED`.
- MUST: idempotency (P-2) and replay protection are treated as distinct controls. Idempotency stops a duplicate request from charging twice; replay protection stops an old receipt from being re-presented as fresh.

## P-6: High-value transactions require human approval

Above a declared threshold, a payment MUST carry an owner confirmation. The rail denies with `requires_owner_confirmation` until a valid, in-scope, unexpired confirmation signed by the delegator accompanies the action.

- MUST: the flow declares a high-value threshold.
- MUST: actions at or above the threshold carry an owner confirmation signed by the delegator.
- MUST: the confirmation is checked for scope, expiry, and action match, not merely presence.

## Conformance

A flow claiming this profile SHOULD point to the negatives it rejects. The conformance package under `tests/conformance/` carries fixtures for over-budget, wrong-principal, replayed, and stale-revocation cases that a payment verifier must refuse. A payment flow that passes the relevant negatives and satisfies P-1 through P-6 conforms to the Payment Safety Profile.

## Scope of claim

Proves: this profile specifies the controls a conformant agent-payment flow must satisfy, each expressible with shipped APS fields, and ties them to the negatives a verifier must reject.

Does not prove: that a payment delivered value, that the recipient was the one the principal truly intended beyond the matched intent, or that the rail itself settled honestly. The profile bounds what APS checks before authorization. It does not reach past the rail.
