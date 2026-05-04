# Payment-Rails Denial Vocabulary — Two-Tier Taxonomy

> Audience: rail-adapter authors, gateway implementors, conformance reviewers.

## Why this exists

A delegation that satisfies any one APS payment rail's spend cap must
satisfy all of them — that invariant is enforced by
[`resolveSpendLimitCents()`](../../src/v2/payment-rails/scope-resolution.ts).
The denial surface is different. Different rails surface
**genuinely different** failure modes to consumers:

- **Nano / x402 / Stripe-Issuing** report failures through small,
  protocol-shaped vocabularies (HTTP error, settlement failure,
  Stripe API error) that compress cleanly into the foundation's
  five-reason taxonomy.
- **ACP** must surface the merchant's exact ACP error type/code
  envelope (`request_not_idempotent` / `invalid` / `processing_error`
  / etc.) so calling agents can pattern-match on the protocol's own
  contract.
- **MPP** must surface the WWW-Authenticate `error=` token plus the
  HTTP 402/403/410/503 status so HTTP clients can route the failure
  to the right retry path.

Compressing those into a generic `rail_error` would lose the signal
clients depend on. So denial vocabulary is **two-tier**.

## Tier 1 — foundation `DenialReason`

Defined in [`src/v2/payment-rails/types.ts`](../../src/v2/payment-rails/types.ts).
Closed union that **every** rail's `emitDenial()` hook MUST be able
to map a refusal into:

```ts
export type DenialReason =
  | 'no_commerce_scope'
  | 'spend_limit_exceeded'
  | 'wallet_revoked'
  | 'time_window_violation'
  | 'rail_error'
  | 'requires_owner_confirmation'  // added by Audit B P9
```

This is the contract a generic gateway, audit log, or downstream
consumer relies on. It is the **minimum** vocabulary every rail
implements. `requires_owner_confirmation` was added in the Audit B
P9 fix to surface HumanEscalationFlag denials at Tier 1 — every rail
honors `delegation.scope.escalation_requirements` and emits this
reason when the action class needs an OwnerConfirmation that wasn't
supplied or didn't verify.

Examples that flow through Tier 1:
- Nano: all five reasons natively
- x402: emits `'rail_error'` on settlement failure, foundation
  reasons on pre-flight rejection
- Stripe-Issuing: foundation reasons on pre-auth, `'rail_error'` on
  Stripe API failure

## Tier 2 — rail-specific extensions

A rail MAY define its own closed union of denial reasons that
expresses the underlying protocol's richer surface. ACP and MPP do.

```ts
// src/v2/payment-rails/acp/types.ts
export type AcpDenialReason =
  | 'spend_limit_exceeded'      // Tier 1 carryover
  | 'merchant_not_allowed'      // ACP-specific: constraint mismatch
  | 'delegation_expired'        // ACP-specific: maps to Tier 1 'time_window_violation'
  | 'currency_mismatch'         // ACP-specific
  | 'wallet_revoked'            // Tier 1 carryover
  | 'no_commerce_scope'         // Tier 1 carryover
  | 'idempotency_conflict'      // ACP-specific: maps to ACP error 'request_not_idempotent'
  | 'invalid_session_state'     // ACP-specific
  | 'api_version_mismatch'      // ACP-specific
```

```ts
// src/v2/payment-rails/mpp/types.ts
export type MppDenialReason =
  | 'spend_limit_exceeded'
  | 'method_not_allowed'        // MPP-specific
  | 'currency_not_allowed'
  | 'delegation_expired'
  | 'no_payment_scope'
  | 'challenge_expired'         // MPP-specific
  | 'invalid_authorization'     // MPP-specific
  | 'session_replay'            // MPP-specific
  | 'wallet_revoked'
  | 'mpp_version_mismatch'      // MPP-specific
```

Each Tier-2 reason MUST round-trip to a Tier-1 reason — that is the
rail adapter's responsibility. Generic gateways read Tier 1; rail-aware
clients can read Tier 2.

## Tier-2 → Tier-1 mapping

The round-trip is implemented as a pure function per rail. Audit B P5
made it executable: prior versions of this doc described the
round-trip in prose only.

### ACP — `mapAcpDenialToFoundation()`

Exported from `src/v2/payment-rails/acp/index.ts` (and re-exported
from the package barrel). Deterministic; total over the
`AcpDenialReason` union.

| Tier-2 `AcpDenialReason` | Tier-1 `DenialReason` | Notes |
|---|---|---|
| `spend_limit_exceeded` | `spend_limit_exceeded` | direct carryover |
| `wallet_revoked` | `wallet_revoked` | direct carryover |
| `no_commerce_scope` | `no_commerce_scope` | direct carryover |
| `delegation_expired` | `time_window_violation` | foundation models all expiry as time-window failures |
| `merchant_not_allowed` | `rail_error` | no exact Tier-1 analog |
| `currency_mismatch` | `rail_error` | no exact Tier-1 analog |
| `idempotency_conflict` | `rail_error` | no exact Tier-1 analog |
| `invalid_session_state` | `rail_error` | no exact Tier-1 analog |
| `api_version_mismatch` | `rail_error` | no exact Tier-1 analog |
| `requires_owner_confirmation` | `requires_owner_confirmation` | direct carryover (Audit B P9 added this Tier-1 reason) |

### MPP — `mapMppDenialToFoundation()`

Exported from `src/v2/payment-rails/mpp/index.ts` (and re-exported
from the package barrel). Deterministic; total over the
`MppDenialReason` union.

| Tier-2 `MppDenialReason` | Tier-1 `DenialReason` | Notes |
|---|---|---|
| `spend_limit_exceeded` | `spend_limit_exceeded` | direct carryover |
| `wallet_revoked` | `wallet_revoked` | direct carryover |
| `no_payment_scope` | `no_commerce_scope` | semantic equivalent (MPP groups `payment` under the foundation `commerce` scope-lineage) |
| `delegation_expired` | `time_window_violation` | foundation models all expiry as time-window failures |
| `challenge_expired` | `time_window_violation` | same |
| `method_not_allowed` | `rail_error` | no exact Tier-1 analog |
| `currency_not_allowed` | `rail_error` | no exact Tier-1 analog |
| `invalid_authorization` | `rail_error` | no exact Tier-1 analog |
| `session_replay` | `rail_error` | no exact Tier-1 analog |
| `mpp_version_mismatch` | `rail_error` | no exact Tier-1 analog |
| `requires_owner_confirmation` | `requires_owner_confirmation` | direct carryover (Audit B P9 added this Tier-1 reason) |

Both functions are total over their input unions. The TypeScript
compiler enforces totality via the closed `switch` discriminator: if
a future commit adds a Tier-2 reason without updating the mapping,
the rail's `index.ts` fails to compile. Per-rail tests additionally
assert the mapping is deterministic and that every union value
produces a Tier-1 reason that exists in the foundation enum.

## What about AP2?

AP2 mandates are **verified**, not **denied**, in the APS pipeline.
The verification surface is its own closed union (`SIGNATURE_INVALID`
/ `NOT_YET_VALID` / `EXPIRED` / `MISSING_REQUIRED_FIELD` / etc.) —
that's a different layer of the contract. AP2 still emits Tier-1
denials when its mandate-issuance pre-auth fails (no commerce scope,
spend cap exceeded, etc.).

## Rail authors — checklist

When adding a new payment rail:

1. **Always** support emitting Tier-1 `DenialReason` through the
   `emitDenial()` hook from `../hooks.js`. This is the minimum
   contract a generic gateway expects.
2. **Optionally** define a Tier-2 `XxxDenialReason` closed union if
   the underlying protocol has richer signals worth exposing. If you
   do:
   - Document the round-trip mapping (Tier-2 → Tier-1) in this file.
   - The Tier-2 reasons go in `xxx/types.ts`, exported alongside the
     adapter's other types.
   - Tests must cover every Tier-2 reason with a deterministic
     reproduction path.
3. **Never** invent new Tier-1 reasons. The five-reason taxonomy is
   stable. If your protocol genuinely emits a refusal that doesn't
   compress into one of the five, that's a Tier-2 reason.
4. **Never** silently downgrade. A rail that only ever emits
   `'rail_error'` is hiding signal — surface it through Tier-2 if
   the protocol gives you the bits.

## Why two tiers and not one

A single big union sounds cleaner — until the next rail ships. Card
networks have `acquirer_decline`, Lightning has `route_not_found`,
SWIFT has wire-rejection codes that are themselves dozens of reasons
deep. Forcing one big union creates a churn surface every rail-add
disturbs. Foundation Tier 1 stays stable because it's small.
Per-rail Tier 2 unions evolve at the speed of their protocol.

The financial-grade invariant the gateway depends on is: every rail
emits **at least** Tier 1. Anything richer is gravy.
