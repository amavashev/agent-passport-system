# MPP draft-httpauth-payment-00 interop

This module binds APS V2 governance to the Machine Payments Protocol — an HTTP authentication scheme for machine-initiated payments co-authored by Stripe, Tempo, and Visa, announced March 18 2026 at mpp.dev / paymentauth.org. The IETF Internet-Draft `draft-httpauth-payment-00` was posted March 30 2026. The pin lives in `MPP_VERSION = 'draft-httpauth-payment-00'`. Bump it when the draft revision changes.

Reference: [mpp.dev](https://mpp.dev), [paymentauth.org](https://paymentauth.org), `developers.cloudflare.com/agents/agentic-payments/mpp/`.

## What MPP is

MPP is a 402 challenge / 200 receipt round-trip carried in HTTP authentication headers. The defining property is that payment methods are first-class protocol extensions rather than baked-in scheme assumptions — a single resource server can advertise Tempo stablecoin, Visa MPP card, and Bitcoin Lightning in the same challenge and let the client pick. New methods (SEPA Instant, ACH, FedNow) bolt on as new method-type variants without changing the envelope.

| Step | HTTP | Body / header |
|---|---|---|
| 1 | `GET /resource` | (no auth) |
| 2 | `402 Payment Required` | `WWW-Authenticate: Payment ...` carrying `MppPaymentChallenge` |
| 3 | (client fulfills one method off-band: signs a chain tx, runs Visa MPP card auth, or settles a bolt11 invoice) | |
| 4 | `GET /resource` | `Authorization: Payment ...` carrying `MppAuthorization` |
| 5 | `200 OK` | `Payment-Receipt: ...` carrying `MppPaymentReceipt` |

The wire-level receipt is unsigned. APS wraps it in a signed `MppApsReceipt` so the audit trail is verifiable independently of the resource server.

## How MPP differs from x402

x402 (Coinbase) presumes a USDC-on-EVM facilitator and a single `exact` scheme. MPP is method-agnostic: there is no facilitator, no canonical settlement chain, and no scheme other than the method-type discriminator. APS treats both the same way at the governance boundary — gate the challenge against a delegation, sign the receipt — but the type model is broader.

## APS ↔ MPP boundary

This adapter binds APS V2 governance at the 402 challenge-response boundary:

- **Pre-authorization gate** (`preAuthorizeMppPayment`): given a challenge and a delegation, decide whether at least one offered method is permitted. Pure function, no I/O.
- **Receipt signing** (`signMppReceipt`): after a successful round-trip, mint an Ed25519-signed `MppApsReceipt` over the canonical-JCS bytes of the receipt envelope.
- **Denial signing** (`signMppDenial`): when the gate refuses, mint a signed `MppDenial` carrying both the APS reason and the deterministic HTTP error envelope (`http_status` + `www_authenticate_error`) so the resource server can re-emit the wire-level 402/403/410/503.

The adapter does NOT perform live HTTP intercept, on-chain verification, escrow session orchestration, or multi-method routing policy. Those live in the gateway product.

## Surface

```ts
preAuthorizeMppPayment(challenge, delegation, opts?)   // → permit | deny+reason
apsToMppHttpError(reason)                              // → { http_status, www_authenticate_error }
delegationToMppAllowed(delegation)                     // → { allowed_methods, allowed_currencies, max_amount_per_charge, valid_until }
signMppReceipt(input, privateKeyHex)                   // → MppApsReceipt
verifyMppReceipt(receipt, opts?)                       // → MppVerifyResult
signMppDenial(input, privateKeyHex)                    // → MppDenial
verifyMppDenial(denial, opts?)                         // → MppVerifyResult
```

## Field crosswalk: V2Delegation → MPP allowed envelope

| APS `V2Delegation` field | MPP allowed envelope | Notes |
|---|---|---|
| `scope.action_categories` | gate input — must include `'payment'` | denial reason `no_payment_scope` if absent |
| `scope.resource_limits.spend_limit_cents` (number) | `max_amount_per_charge` | tier-1: canonical numeric (resolver default) |
| `scope.resource_limits['commerce.spend_limit']` (number) | `max_amount_per_charge` | tier-2: AP2-mandate alias, honored by every rail |
| `scope.constraints.spend_limit_cents` (string) | `max_amount_per_charge` | tier-3: string fallback, parsed via `Number()` |
| `scope.constraints.allowed_payment_methods` (CSV) | `allowed_methods` | trimmed, empty filtered |
| `scope.constraints.allowed_currencies` (CSV) | `allowed_currencies` | trimmed, lower-cased |
| `policy_context.valid_until` (ISO 8601) | `valid_until` | gate enforces against `options.now` |

The allow-list semantics are union, not intersection: a delegation that lists `tempo,card` and a challenge offering `tempo,card,lightning` matches the first method that satisfies method + currency + amount, and ignores the rest. Currency comparison is exact-string and lower-cased — Tempo's currency-as-contract-address (e.g. `0x20c0...`) must appear verbatim in `allowed_currencies` to match.

## Denial → HTTP error mapping

`apsToMppHttpError` is the deterministic inverse of the wire-level error a resource server would return. The gate calls it BEFORE the resource is touched; the resource server (or the gateway in front of it) re-emits the same envelope so callers see a well-formed 402/403/410/503 instead of a transport failure.

| APS `MppDenialReason` | `http_status` | `www_authenticate_error` |
|---|---|---|
| `spend_limit_exceeded` | 402 | `insufficient_funds` |
| `method_not_allowed` | 403 | `invalid_request` |
| `currency_not_allowed` | 403 | `invalid_request` |
| `delegation_expired` | 410 | `expired` |
| `no_payment_scope` | 403 | `invalid_token` |
| `challenge_expired` | 402 | `expired` |
| `invalid_authorization` | 402 | `invalid_token` |
| `session_replay` | 403 | `invalid_request` |
| `wallet_revoked` | 410 | `invalid_token` |
| `mpp_version_mismatch` | 503 | `invalid_request` |

The `www_authenticate_error` token follows RFC 6750 §3.1 conventions. Status-code split: 402 for retryable payment failures, 403 for hard policy denials, 410 for revoked-or-gone resources, 503 for version-drift conditions where the gate cannot decide.

The mapping invariant is enforced in `verifyMppDenial`: a denial whose stored `http_status` or `www_authenticate_error` disagrees with the deterministic mapping for its `reason` is rejected as `SIGNATURE_INVALID` (tampered or version drift). Bumping the table is a breaking change to denial verifiability and requires an `MPP_VERSION` bump.

## Method-type extension model

`MppMethodType` is `'tempo' | 'card' | 'lightning' | (string & {})`. The open string tail is intentional: callers shipping new methods (SEPA Instant, ACH, FedNow, account-to-account, on-platform credit) extend the union by:

1. Adding a new `MppMethod*` variant interface with `method_type: 'sepa-instant'` (or whatever).
2. Threading the new variant into `MppMethod`.
3. Extending `methodComparableAmount` and `methodCurrency` in `index.ts` so the per-charge cap and currency allow-list comparisons fire correctly for the new variant.

Receipts and denials are method-agnostic — the existing `MppApsReceipt.method_type` and `MppDenial.method_type` fields carry the new value with no schema change.

## Signing

Ed25519 over RFC 8785 JCS canonical bytes, identical to the AP2, ACP, and Stripe-Issuing adapter conventions. `signMppReceipt` and `signMppDenial` strip the `signature` field (or never include it), canonicalize the remaining envelope, and sign. `verifyMppReceipt` and `verifyMppDenial` reverse the process and additionally enforce the version pin, receipt-kind match, TTL (default 24h), and the denial mapping invariant.

The wire-level MPP signature scheme — when the IETF draft adds one — is gateway product. APS-flavored signing remains the cross-impl audit path.

## Limitations

| Limitation | Why | Workaround |
|---|---|---|
| No on-chain verification of Tempo / Lightning settlement proofs | Adapter is a governance gate, not a settlement engine. | Gateway integration verifies tx hashes and preimages against the relevant chain or Lightning node before mint. |
| Per-challenge cap only — no rolling window | APS `spend_limit_cents` is a per-charge value, not a window aggregate. | Gateway product layers session/window aggregates on top of per-charge gates. |
| `session_replay` is signaled but not detected | Replay detection requires nonce state across challenges; the gate is pure. | Caller maintains a nonce cache and emits `session_replay` denials when it matches a previously-settled `challenge_id` + `nonce`. |
| `wallet_revoked` is signaled but not detected | Wallet revocation is gateway state. | Caller checks the agent's wallet status before invoking the gate; emits `wallet_revoked` denial if revoked. |
| Tempo amounts not compared against per-charge cap | Tempo uses native token decimals, not minor units; comparison would require per-token decimal awareness. | Callers who need Tempo-amount gating supply a normalized minor-unit value via the gateway before the gate runs. |
| No multi-method preference signal | The gate returns allow:true on the first matching method; it does not rank by cost or carbon. | Routing policy is gateway product — call the gate per-method if you need a per-method decision. |

## Out of scope

These all live in the private gateway integration layer.

- Live HTTP intercept (parsing `WWW-Authenticate: Payment` and minting `Authorization: Payment`).
- On-chain settlement verification (Tempo tx hashes, Bitcoin Lightning preimages).
- Visa MPP card-spec acceptance flow (3DS, ACS, brand routing).
- Escrow session settlement.
- Multi-method routing policy and cost optimization.
- Dispute orchestration and chargeback handling.
- Wire-level signature scheme on `MppPaymentReceipt` (when the IETF draft adds one).
