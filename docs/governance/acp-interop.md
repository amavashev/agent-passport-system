# ACP v2025-09-29 interop

This module binds APS V2 governance to the Agentic Commerce Protocol (Apache 2.0, maintained by OpenAI and Stripe). The pin lives in `ACP_API_VERSION = '2025-09-29'`. Bump it when the upstream `agentic_checkout` RFC schema changes and re-run the conformance suite.

ACP is line-item based and merchant-centric: an agent calls a merchant's `POST /checkout_sessions` endpoint, mutates the session via `update`/`complete`/`cancel`/`retrieve`, and the merchant returns an authoritative `CheckoutSession` carrying totals and status. APS gates run **before** the agent reaches the merchant so a delegation-violating call surfaces as a well-formed ACP error, not a transport failure.

## What ships

The reference adapter is a pure-function gate plus signed receipt/denial primitives — no transport, no webhook routing, no merchant onboarding. Those are gateway product.

```ts
preAuthorizeAcpCheckout(req, delegation, expectedCurrency?)  // permit | deny+reason
checkAcpSessionUnderBudget(session, delegation)              // post-totals spend gate
delegationToAcpAllowed(delegation)                           // V2Delegation projection
acpSessionToDelegationHints(session)                         // partial reverse derivation
apsToAcpError(reason)                                        // AcpDenialReason → AcpErrorType+code
signAcpReceipt(input, privateKeyHex)                         // Ed25519 over JCS
verifyAcpReceipt(receipt, opts?)                             // returns AcpVerifyResult
signAcpDenial(input, privateKeyHex)                          // signed deny envelope
verifyAcpDenial(denial, opts?)                               // returns AcpVerifyResult
```

`preAuthorizeAcpCheckout` is the boundary call — pure, no I/O — and is intended to sit behind the rail's `preAuthorize` hook in the generalized `PaymentRail` interface. Final spend enforcement runs in `checkAcpSessionUnderBudget` once the merchant has returned authoritative totals.

## V2Delegation → ACP authorization envelope

`delegationToAcpAllowed(delegation)` projects a V2Delegation into the subset of ACP context it permits.

| `V2Delegation` field | `AcpAllowedFromDelegation` field | Notes |
|---|---|---|
| `scope.resource_limits.spend_limit_cents` (number) | `max_total` | Preferred. Hard cap in minor units across all line items. |
| `scope.resource_limits['commerce.spend_limit']` (number) | `max_total` | Fallback. |
| `scope.constraints.spend_limit_cents` (CSV string) | `max_total` | Final fallback, parsed to number. `null` when none of the above are set. |
| `scope.constraints.allowed_merchants` (CSV) | `allowed_merchants` | PSP merchant ids, domains, or platform ids. Empty list = no merchant filter. |
| `scope.constraints.allowed_currencies` (CSV) | `allowed_currencies` | Lowercased ISO 4217. Empty list = no currency constraint. |
| `policy_context.valid_until` (ISO 8601) | `valid_until` | Token expiry surfaced as-is for buyer-facing rendering. |
| `scope.action_categories` must include `'commerce'` | — | Otherwise `preAuthorizeAcpCheckout` denies with `no_commerce_scope`. |

Field sourcing matches the AP2 and Stripe-Issuing reference adapters exactly so a single delegation governs all three rails identically.

## APS denial → ACP error mapping

`apsToAcpError(reason)` produces the error envelope a merchant would have returned had APS not gated the call first. Caller surfaces it identically to a real merchant response.

| `AcpDenialReason` | `AcpErrorType` | `AcpErrorCode` | `param` |
|---|---|---|---|
| `spend_limit_exceeded` | `invalid_request` | `invalid` | `$.items` |
| `merchant_not_allowed` | `invalid_request` | `invalid` | `$.items[0].id` |
| `delegation_expired` | `invalid_request` | `requires_sign_in` | — |
| `currency_mismatch` | `invalid_request` | `invalid` | `$.currency` |
| `wallet_revoked` | `invalid_request` | `payment_declined` | — |
| `no_commerce_scope` | `invalid_request` | `requires_sign_in` | — |
| `idempotency_conflict` | `request_not_idempotent` | `invalid` | — |
| `invalid_session_state` | `invalid_request` | `invalid` | `$.status` |
| `api_version_mismatch` | `service_unavailable` | `invalid` | — |

`requires_sign_in` is used for both `delegation_expired` and `no_commerce_scope` because ACP's error code vocabulary collapses both into "the buyer must re-authenticate against an authority that can issue a fresh delegation."

## Signing

`signAcpReceipt` and `signAcpDenial` produce signed envelopes via Ed25519 over RFC 8785 JCS canonical bytes — same primitive used by AP2 mandates and Stripe Issuing receipts. Verification strips the `signature` field, re-canonicalizes the rest, and verifies against the embedded `signer` (or an explicit `expected_signer`). TTL defaults to 24h on receipts and 1h on denials. `acp_version` is pinned at mint time and verification fails on mismatch.

`request_digest` on receipts is `sha256(canonicalize_jcs(request_body))` so the receipt commits to the exact bytes that crossed the wire.

## Spec-ambiguity calls

| Call | Resolution |
|---|---|
| `V2Delegation.scope.action_categories` does not map 1:1 to ACP line items | ACP is line-item-based; APS is action-class-based. The adapter surfaces `allowed_merchants` and a `max_total` cents budget; per-line-item filtering is gateway product. |
| Idempotency conflicts | The adapter does not maintain an idempotency cache. When the caller's cache reports a replay, deny with `idempotency_conflict` → ACP `request_not_idempotent` / `invalid`. The receipt itself is the source of truth for replay detection. |
| Receipt `session_state` | Captures whatever the merchant returned in its `CheckoutSession` response. The adapter does not synthesize a session — there is no "what the session would have been" for denied calls. |
| Reverse derivation `acpSessionToDelegationHints` is lossy | Line-item content does not survive into a V2Delegation. The PSP merchant identifier on the session may differ from the settlement merchant id. Both notes are returned in the `notes[]` field for caller awareness. |

## Pinned version

`ACP_API_VERSION = '2025-09-29'`. This module assumes the ACP `agentic_checkout` RFC at that version:

- Operations: `create`, `update`, `complete`, `cancel`, `retrieve`
- Status enum: ACP `CheckoutSession.status` values
- Totals: typed entries with a `'total'` row carrying authoritative cart total in minor units
- Currency: ISO 4217 lowercase strings on the session
- Error envelope: `{ type: AcpErrorType, code: AcpErrorCode, param?: JSONPath, message? }`

When ACP bumps the API version, update `ACP_API_VERSION` and the version-mismatch test in `tests/v2/payment-rails/acp.test.ts`. Field-level additive changes are forward-compatible. Breaking enum changes require a code change in `VALID_OPS` and the error-mapping switch.

## Out of scope

These all live in the private gateway integration layer, not this SDK:

- Live HTTP transport to merchant `/checkout_sessions` endpoints
- Webhook routing for asynchronous session updates
- Multi-tenant merchant onboarding and credential storage
- Settlement orchestration (PSP-side; ACP only carries the buyer-facing session)
- Dispute, refund, and chargeback orchestration
- Idempotency-key cache (caller maintains; adapter only emits the receipt)

The split mirrors AP2 and Stripe-Issuing: the SDK ships the governance contract, the wire-shaped envelopes, and the deterministic crosswalk; the gateway ships the operational fabric.
