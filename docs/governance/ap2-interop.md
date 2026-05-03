# AP2 v0.2 interop

This module maps APS `V2Delegation` to and from AP2 mandate dicts. AP2 is Google's Agent Payments Protocol; v0.2 was published in April 2026. The pin lives in `AP2_VERSION = '0.2'` and in fixture META files. Bump it when the upstream schema changes and re-run the fixture generator.

Source schemas: `https://github.com/google-agentic-commerce/AP2` under `code/sdk/schemas/ap2/`.

## What ships

Four AP2 v0.2 mandate types:

| AP2 vct | TypeScript type | Purpose |
|---|---|---|
| `mandate.checkout.open.1` | `AP2OpenCheckoutMandate` (alias `IntentMandate`) | Open intent. Authorizes a future checkout against constraints. |
| `mandate.checkout.1` | `AP2CheckoutMandate` (alias `CartMandate`) | Closed cart. Locks specific items + total at purchase time. |
| `mandate.payment.open.1` | `AP2OpenPaymentMandate` | Open payment authorization. Carries budget + constraints. |
| `mandate.payment.1` | `AP2PaymentMandate` | Closed payment authorization against a specific instrument. |

Crosswalk functions:

```ts
apsToAp2IntentMandate(delegation, opts)        // V2Delegation → OpenCheckoutMandate
apsToAp2CartMandate(delegation, cart, opts)    // V2Delegation + cart → CheckoutMandate
apsToAp2OpenPaymentMandate(delegation, opts)   // V2Delegation → OpenPaymentMandate
apsToAp2PaymentMandate(delegation, opts)       // V2Delegation + amount → PaymentMandate
ap2MandateToApsDelegation(mandate, opts)       // any AP2 mandate → V2Delegation
signAp2Mandate(mandate, privateKeyHex)         // returns SignedAP2Mandate
verifyAp2Mandate(signed, opts?)                // returns Ap2VerifyResult
```

## Field mapping

| APS `V2Delegation` field | AP2 mandate field | Direction | Notes |
|---|---|---|---|
| `delegatee` (Ed25519 hex pubkey) | `cnf.jwk = { kty: 'OKP', crv: 'Ed25519', x: base64url(pubkey_bytes) }` | both | RFC 7800 §3.1 confirmation key. |
| `policy_context.valid_from` (ISO 8601) | `iat` (Unix epoch seconds) | both | |
| `policy_context.valid_until` (ISO 8601) | `exp` (Unix epoch seconds) | both | |
| `scope.action_categories` | encoded into `OpenCheckoutMandate.constraints[]` (`allowed_merchants`, `line_items`) and `OpenPaymentMandate.constraints[]` (`allowed_payees`, `allowed_payment_instruments`, `payment_reference`) | APS → AP2 with caller-supplied detail; AP2 → APS recovers category but not full constraint shape | The APS `action_categories` is a flat string list; AP2 uses typed constraint objects. The forward direction needs caller input to enumerate merchants/items; the reverse direction collapses constraints into `scope.constraints` string fields for audit. |
| `scope.resource_limits['commerce.spend_limit']` | `OpenPaymentMandate.constraints[]` of type `payment.budget` (open) or `PaymentMandate.payment_amount` (closed) or `CheckoutMandate.total` (closed) | both | Override key via `opts.spend_limit_key` when callers use a non-default name. |
| `delegator` (DID) | not directly mapped | APS → AP2 only | AP2 v0.2 has no explicit "payer" field. The user/principal who signed the original APS delegation is implicit; the SD-JWT subject (cnf-bound holder) is `delegatee`. The reverse direction takes `delegator_did` as a caller-provided option. |
| `payee` (cart payee / merchant) | `CheckoutMandate.payee` / `PaymentMandate.payee` | one-way (APS does not carry merchant identity in delegation; caller supplies the cart) | |
| `signature` (Ed25519 hex over canonical-JCS) | `SignedAP2Mandate.signature` (Ed25519 hex over canonicalize_jcs(mandate)) | both | APS-flavored signing. AP2 v0.2 wire signing is JWS (see Limitations). |

## Signing

Two signing layers exist. The SDK ships layer (1); layer (2) is gateway product.

### 1. APS-flavored: Ed25519 over RFC 8785 JCS

`signAp2Mandate(mandate, privateKeyHex)` canonicalizes the mandate dict via the SDK's `canonicalizeJCS` and signs with Ed25519. Result is `SignedAP2Mandate { mandate, signer_did, signature }`. Verification consults the mandate's `cnf.jwk` for the holder pubkey or accepts an explicit `expected_signer_did`. This is the cross-impl APS audit path.

### 2. Wire-level JWS (NOT in this SDK)

AP2 v0.2 actually uses SD-JWT for the `CheckoutMandate.checkout_jwt` field and JWS for the outer mandate envelope. To produce wire-compatible mandates that interoperate with Google's reference implementation, the gateway integration layer wraps the dict shape this module produces in a JWS envelope with the appropriate JOSE headers.

The dict shape is wire-compatible at the field level. The signature layer is not. Callers building APS audit trails use `signAp2Mandate`. Callers shipping mandates to AP2-compliant counterparties use the gateway's JWS encoder on top.

## Limitations

| Limitation | Why | Workaround |
|---|---|---|
| Cart contents lost on `CheckoutMandate → V2Delegation` | APS `V2Delegation.scope` carries categories + spend limits, not item lists. | Callers who need cart preservation persist the original `CheckoutMandate` separately and reference it from APS-side audit. |
| AP2 → APS recovers a "shape" delegation, not a fully-signed one | AP2 mandates don't carry APS policy provenance (`policy_version`, `values_floor_version`, `trust_epoch`, `issuer_id`). | Pass these via `Ap2ToApsOptions`; the result is then passed through the SDK's standard delegation-construction pipeline to produce a signed `V2Delegation`. |
| Holder identity is `cnf.jwk` only | AP2 v0.2 has no top-level `payer` field. The SD-JWT subject is the `cnf`-bound holder. | The reverse direction accepts `delegator_did` as a caller option to populate `V2Delegation.delegator`. |
| `CheckoutMandate.checkout_jwt` defaults to `''` in APS-only mode | This SDK does not produce JWTs; the merchant-signed JWT is gateway product. | Callers who need wire-compatible mandates fill `checkout_jwt` and `checkout_hash` via the gateway integration layer before emitting. |
| AP2 constraint types not 1:1 with APS scope | AP2 has typed constraint objects (`payment.budget`, `payment.amount_range`, etc.) where APS uses flat strings. | The reverse direction surfaces constraint metadata through `scope.constraints` string fields (`scope.constraints.currency`, `scope.constraints.payee_id`, etc.) for audit. The forward direction emits structured constraints from caller input. |
| `risk_data` not carried in APS delegations | AP2 `PaymentMandate.risk_data` is a free-form map collected at mandate time; APS delegation `scope.constraints` is flat string-to-string. | When converting AP2 → APS, `risk_data` is dropped. Callers who need the risk signals persist the original AP2 mandate alongside the APS delegation. |

## Pinned version

`AP2_VERSION = '0.2'`. This module assumes:

- Mandate `vct` strings: `'mandate.checkout.1'`, `'mandate.checkout.open.1'`, `'mandate.payment.1'`, `'mandate.payment.open.1'`
- Open-checkout constraints: `'checkout.allowed_merchants'`, `'checkout.line_items'`
- Open-payment constraints: `'payment.budget'`, `'payment.amount_range'`, `'payment.allowed_payees'`, `'payment.allowed_payment_instruments'`, `'payment.payment_reference'`
- Timestamps as Unix epoch seconds (`iat`, `exp`)
- Hash digests as base64url (`checkout_hash`, `transaction_id`)

When AP2 v0.3 lands, bump `AP2_VERSION` and re-run the fixture generator. The crosswalk functions are forward-compatible at the field level; new constraint types or fields land as additive changes. Vct value bumps require a code change in `verifyAp2Mandate`'s `VALID_VCTS` set.

## Fixtures

`src/v2/payment-rails/ap2/fixtures/` carries three APS↔AP2 pairs documenting the round-trip. `_generate.ts` regenerates them deterministically (pinned signer seed `0x99...`, pinned timestamps). `META.json` lists the pairs and notes per-pair limitations.

| Pair | Direction | Note |
|---|---|---|
| 001 | APS delegation ↔ OpenCheckoutMandate | Full round-trip including `cnf.jwk`, `iat`, `exp`. Constraints regenerated from caller-supplied merchant + line-item input on the forward direction. |
| 002 | APS delegation + cart → CheckoutMandate | One-way: cart contents not preserved on reverse trip. |
| 003 | APS delegation + amount → PaymentMandate | Reverse trip carries amount + payee + instrument back into `scope.constraints`. |

## Out of scope

- SD-JWT encoding/decoding (used by AP2 v0.2 for `checkout_jwt`).
- JWS envelope around the mandate (AP2 v0.2 wire format).
- Selective-disclosure (`x-selectively-disclosable-field`, `x-selectively-disclosable-array`) handling.
- Revocation / mandate refresh workflows.
- Live integration with the Google reference impl test suite (those run against the gateway, not the SDK).

These all live in the private `aeoess-gateway` integration layer.
