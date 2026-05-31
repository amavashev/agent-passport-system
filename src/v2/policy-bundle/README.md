# Signed policy-bundle primitive

A content-addressed, signed bundle FORMAT and VERIFIER for policy file sets.

A policy-bundle is three things carried together:

1. a deterministic tar (POSIX ustar) of policy files,
2. a JCS-canonical manifest that pins each file by sha256 and pins the whole
   tar by sha256, with `changeType` governance metadata,
3. an Ed25519 detached signature over the canonical manifest.

The bundle is content-addressed: its identity is
`sha256(canonicalizeJCS(manifest))`. The same files always serialize to the
same tar bytes and the same manifest hash.

## What this is and is not

This module is FORMAT and VERIFIER only. It reuses existing protocol
primitives and builds no service:

- JCS canonicalization: `src/core/canonical-jcs.ts`
- Ed25519 sign/verify: `src/crypto/keys.ts`
- did:aps derivation: `src/core/did.ts`
- `changeType` strengthening/weakening vocabulary: `src/types/governance.ts`
- aps.txt revocation anchor: `src/core/aps-txt.ts`
- `ScopeOfClaim` honest-scope declaration: `src/v2/accountability/types/base.ts`

Out of scope, and intentionally not built here: a registry, a resolver
protocol, a lockfile service, a transparency-log backend. Those are product
concerns, not protocol primitives.

## Usage

```ts
import {
  createPolicyBundle,
  verifyPolicyBundle,
} from 'agent-passport-system/dist/src/v2/policy-bundle/index.js'

const envelope = createPolicyBundle({
  bundleId: 'acme-data-policy',
  files: [
    { path: 'policy.json', content: JSON.stringify({ rule: 'deny-by-default' }) },
    { path: 'README.md', content: '# Policy set' },
  ],
  signerPrivateKey,
  signerPublicKey,
})

const result = verifyPolicyBundle(envelope, { apsTxt }) // apsTxt optional
// result.valid, result.weakeningFlagged, result.revoked, result.reasons
```

Revocation reuses the existing aps.txt path-override mechanism. A bundle is
treated as revoked when the publisher's aps.txt resolves a fully-prohibited
terms set for the bundle's anchor path (default `/<bundleId>`). No registry or
resolver service is involved; the caller supplies the aps.txt document.

A `weakening` (or `mixed`) `changeType` is surfaced as `weakeningFlagged` and a
`GOVERNANCE_WEAKENING` reason. It is advisory: a well-formed signed weakening
bundle still verifies structurally so the caller can apply its own approval
policy on top.

## Proof box

**Proves.** A valid policy-bundle proves the bundle contents match the signed
manifest hash and that the signer authorized this exact bundle. The tar bytes
hash to `manifest.tarSha256`, every file inside hashes to its manifest pin, and
the Ed25519 signature over the canonical manifest verifies under the declared
signer key.

**Does not prove.** It does not prove that the policy inside the bundle is
correct, sound, or safe. It does not prove the signer is currently authorized
beyond the supplied aps.txt revocation check. It does not prove anything about
who authored the policy versus who signed the bundle.

Language is deliberate: integrity and authorization here are tested and
validated, not proved-as-truth.
