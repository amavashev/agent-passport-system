# Hash-and-Pointer Payloads + Field-Disclosure Profile (W2-B6)

A receipt should never embed a raw sensitive payload. This module ships an
additive, versioned receipt slot that commits to a payload by hash plus a URI
pointer, with a per-field disclosure policy. Hash-bound fields stay in the
signed body so the receipt signature still validates over the profile.

## What it ships

- `FieldDisclosurePolicy` - `public | hash_only | encrypted | redacted`.
- `HashPointerPayload` - `{ algorithm, payload_sha256, uri, content_type?, committed_at }`.
  Commits to a payload by SHA-256 and points at where it lives. Does not fetch it.
- `DisclosedField` - one field with a per-field policy and a hash binding that
  survives redaction.
- `FieldDisclosureProfile` - the additive slot. A receipt that omits it is
  byte-identical to one built before this module existed, because the canonical
  serializer strips `undefined` keys.
- `buildFieldDisclosureProfile` - builder. Rejects a raw value for any field
  marked sensitive (no `public` policy on a sensitive field), so raw PII cannot
  reach the signed body.
- `verifyFieldDisclosureProfile` - verifier. Checks internal consistency, and
  optionally re-hashes a supplied cleartext value or full payload against the
  bindings. Reports mechanical facts; makes no availability claim.
- `bbsProofToFieldDisclosureRef` / `fieldDisclosureRefToBbsProof` - structural
  bridge to the isolated `@aeoess/aps-bbs-credentials` package. Carries a BBS
  selective-disclosure proof by reference without importing the package into
  core, preserving that package's isolation.

## Reuse

- `canonicalHash` / `canonicalize` from `src/core/canonical.ts` for hashing.
- The `'[REDACTED]'` sentinel and the "hash chain and signature preserved"
  invariant from `src/storage/volatile-backend.ts`.
- The `TransformationType` vocabulary (`hashing`, `redaction`) from
  `src/types/cross-chain.ts`.
- The `EvidenceCommitment` hash-and-pointer convention from
  `src/types/bilateral-receipt.ts`. The bilateral receipt builder gains an
  additive optional `fieldDisclosureProfile` slot; `verifyBilateralReceipt`
  already reconstructs the full signed body, so the same multi-signature
  verifier covers the profile with no new checker.
- `@aeoess/aps-bbs-credentials` for the selective-disclosure subset proof,
  composed by structural interface only.

## Proof box

**Specified, tested, validated.**

**Proves:** A field-disclosure profile commits a receipt to a payload by hash
plus a pointer (URI) without embedding the raw payload, and binds each field by
hash so a redacted or hidden field still leaves the receipt signature
verifiable. The builder rejects a raw value for any field marked sensitive.

**Does NOT prove:**

- That the payload at the URI is available or unchanged. That requires resolving
  the URI and re-hashing (compose the resolver, W2-A2). A present URI is not an
  availability claim.
- That a hidden field's value is narrow or harmless. A hash binding hides the
  value; it says nothing about what the value is.
- That an `encrypted` field is actually encrypted, or with what key. This module
  never encrypts; it carries caller-supplied ciphertext opaquely.
- Truth of the field values. A binding is a commitment to a value, not a
  statement that the value is true.

The BBS reference inherits the proof box of `@aeoess/aps-bbs-credentials`, which
is EXPERIMENTAL, ISOLATED, and NOT core-reviewed cryptography this round; the
crypto-review burden there is outstanding.
