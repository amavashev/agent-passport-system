# Payment Rails

Two tiers of conformance ship in this directory. Both run from
`./conformance/`.

## Tier-1 — `PaymentRail` interface

The foundation interface (`./types.ts → PaymentRail`) describes
`createInvoice`, `checkStatus`, `verifyTransaction`, `revokeWallet`,
and `isWalletRevoked`. The Nano reference (`./nano.ts`) is the
canonical implementation.

`./conformance/harness.ts` exports `runConformance(rail, hooks)`,
which exercises 10 standard scenarios covering pre-authorization,
denial-emit, receipt-emit, JSON round-trip, and revocation cascade.
Third-party rails that implement `PaymentRail` claim Tier-1
conformance by passing `STANDARD_SCENARIOS` against their
implementation.

Canonical test vectors live at `./conformance/fixtures/SCN-*.fixture.json`.

## Tier-2 — binding adapters

The five binding adapters (`./ap2`, `./x402`, `./stripe-issuing`,
`./acp`, `./mpp`) bind APS V2 governance to external wire
protocols. They do NOT share a uniform `PaymentRail` interface;
each has its own surface (mandate dicts for AP2, requirement
shapes for x402, spending controls for Stripe-Issuing, allowed
envelopes for ACP and MPP).

`./conformance/binding-harness.ts` exports
`runBindingConformance(adapters, fixtures)`, which exercises three
cross-rail invariants:

| Invariant | What it pins |
|---|---|
| `field_name_resolution` | All adapters resolve a V2Delegation's spend cap to the same numeric value via `resolveSpendLimitCents()`. |
| `denial_round_trip` | Each rail's per-rail denial taxonomy projects into the closed foundation `DenialReason` enum. |
| `resolver_determinism` | Two calls on the same delegation produce byte-identical canonical JSON. |
| `cross_rail_byte_parity` | The serialized cap is byte-identical across every rail for shared scenario ids. |

Canonical test vectors live at
`./conformance/binding-fixtures/<rail>.fixture.json`. Third parties
implementing a sixth binding adapter validate against these
vectors by writing a `BindingRailAdapter` wrapper for their
implementation and running `runBindingConformance()` against the
shared fixture set.
