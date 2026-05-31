# Normative Proof Boundary: What an APS Receipt Proves

> Audience: verifier implementors, relying-party policy authors, rail-adapter authors, paper reviewers.
>
> Status: normative. This section specifies the boundary every APS receipt sits inside. It does not change protocol behavior. No signing path, canonical preimage, or `action_ref` computation is altered by anything here.

## Why this exists

An APS receipt is a signed declaration about mechanical facts the system observed. The recurring failure mode across every relying party is to read more out of a receipt than its signature supports: to treat a sound signature as a sound claim, or to treat a number the issuer wrote as a fact the verifier checked. This section states the boundary once, in normative language, so that the narrower meaning survives composition into bundles, dashboards, and downstream policy.

Two companion surfaces carry the same boundary in code and in catalog form:

- The `ScopeOfClaim` type ([`src/v2/accountability/types/base.ts`](../../src/v2/accountability/types/base.ts)) makes every accountability receipt declare `asserts` and `does_not_assert` inline, so the boundary travels with the receipt.
- The per-receipt and per-rail proof boxes in [`README.md`](../../README.md) and [`docs/governance/payment-rails-receipt-semantics.md`](./payment-rails-receipt-semantics.md) enumerate the boundary for each concrete receipt type.

This document is the general rule those surfaces instantiate. It does not re-enumerate per-type boundaries; it specifies what is common to all of them and the one rule that governs how assurance is derived.

## What an APS receipt proves

An APS receipt reports mechanical facts and nothing more. A receipt that verifies asserts, at most:

- Which signing key (which DID) signed which claim, and that the signed body has not changed since signing.
- The observation basis of the claim: whether the fact was gateway-observed, runtime-attested, or self-attested, as declared in `capture_mode`.
- Which delegation chain the claim was issued under, where one applies.
- Any witness facts the receipt commits to: which witnesses signed, whether their statements conflict, and whether the signers are independent of the key and DID graph behind the claim.

These are facts about signatures, observation, and graph structure. They are checkable by anyone holding the receipt and the relevant public keys, without trusting the issuer's self-description.

## What an APS receipt does not prove

A receipt does not assert any of the following unless a separate, named receipt with the matching `claim_type` carries that evidence:

- That an off-protocol side effect completed. A signed instruction is not a completed effect. A payment receipt does not assert that funds settled; settlement finality requires settlement evidence (a `SettlementRecord` or rail-specific finality proof), and rails carry refund, dispute, and chargeback windows.
- That the agent understood the consequences of the action, or that the business outcome was correct.
- That a counterparty's legal identity matches what a key or URL suggests. A key is not an identity.
- That no path around a checked boundary exists. An authority-boundary receipt asserts that a check ran and returned a verdict, not that the scope was configured correctly.
- That a self-attested statement is observed evidence. `self_attested` evidence MUST NOT be promoted to gateway-observed or runtime-attested evidence by a verifier.

The boundary is enumerated per type in the companion proof boxes. A verifier that wants a stronger claim than a receipt makes MUST collect additional evidence of the matching claim type rather than reading the stronger claim out of the receipt it holds.

## Assurance is verifier-derived, never issuer-asserted

This is the load-bearing rule of this section.

**Assurance is an output a verifier computes. It is never an input an issuer writes.** There is no issuer-written assurance field, evidence-grade field, or trust-score field anywhere in an APS receipt, and a conformant verifier MUST NOT read one if a non-conformant issuer adds one. A receipt reports the mechanical facts above. The verifier reads those facts and derives whatever assurance its relying-party policy calls for.

The mechanism is the verifier-derived descriptor specified in the companion module (W2-A1). The descriptor is computed by the verifier from the receipt's mechanical facts. It is a lattice or set consistent with the four-valued constraint status (`pass`, `fail`, `not_applicable`, `unknown`) used across the constraint architecture ([`src/types/gateway.ts`](../../src/types/gateway.ts)), not a scalar ladder. It records, for the claim under evaluation: which DID signed which part, the observation basis, whether witnesses conflict, and whether the signers are independent.

Independence is the sharp metric in that descriptor. Witnesses that share the gateway's root of trust are still a form of self-attestation, however many signatures they carry: a key cannot independently witness a claim that its own root vouches for. Independence is therefore derived from the key and DID graph, through a `sharesRoot` relation over signers, and is verifier-computable from material the verifier already resolves. The descriptor reports independence as a fact about that graph, not as a number the issuer chose.

A relying party MAY compute, on top of the descriptor, at most one verifier-derived advisory scalar that summarizes the descriptor for its own policy. If it does, that scalar is a relying-party-policy output, labeled as such, computed by the verifier, and never read from the receipt. Two relying parties reading the same receipt may compute different advisory scalars from the same descriptor without either receipt being wrong, because the scalar belongs to the policy, not to the claim.

### Normative requirements

- An issuer MUST NOT write an assurance, evidence-grade, or trust-score field into a receipt. A receipt carries mechanical facts and a `scope_of_claim`; it does not carry a self-graded verdict.
- A verifier MUST derive assurance from the descriptor computed over the receipt's mechanical facts, not from any issuer-supplied grade.
- A verifier MUST treat `capture_mode` and `self_attested` as part of the claim, not as advisory metadata, and MUST NOT promote self-attested evidence to observed evidence.
- A verifier MUST derive signer independence from the key and DID graph (the `sharesRoot` relation), and MUST NOT count witnesses that share a root of trust as independent.
- Where a relying party emits an advisory scalar, it MUST label that scalar a relying-party-policy output and MUST NOT persist it back into the receipt or present it as an issuer-asserted fact.

## How this composes

The companion catalog ([`README.md`](../../README.md), [`docs/governance/payment-rails-receipt-semantics.md`](./payment-rails-receipt-semantics.md)) tells a verifier what each receipt type asserts and does not assert. This section tells the verifier that the assurance it attaches to any of them is its own derivation, not the issuer's. A bundle ([`aps:bundle:v1`](../../README.md)) is an envelope: it asserts that its members verify on their own and nothing more, so the descriptor a verifier computes over a bundle is the composition of the descriptors over its members, not a new and higher grade conferred by aggregation.

## Proof box

> **Proves:** This section specifies the proof boundary common to all APS receipts and the rule that assurance is verifier-derived from the descriptor (W2-A1) and never issuer-asserted.
>
> **Does NOT prove:** It does not change protocol behavior, does not alter any signing path, canonical preimage, or `action_ref` computation, and does not itself evaluate any receipt. It is a specification of meaning, not an evaluation.

## Reference

- [`src/v2/accountability/types/base.ts`](../../src/v2/accountability/types/base.ts): `ScopeOfClaim`, `CaptureMode`, `AccountabilityReceiptBase`.
- [`src/types/gateway.ts`](../../src/types/gateway.ts): `ConstraintStatus` (the four-valued status the descriptor is consistent with).
- [`README.md`](../../README.md): per-receipt-type proof boxes and the misuse cases a verifier must reject.
- [`docs/governance/payment-rails-receipt-semantics.md`](./payment-rails-receipt-semantics.md): per-rail negative evidentiary boundary.
- W2-A1: verifier-derived descriptor module (the surface that computes the descriptor this section specifies). Built against its interface; see the module note on composition status.
