# Tool Registry & Discovery Integrity — conformance vectors

Cross-language conformance vectors for the APS implementation of the CoSAI
control `controlToolRegistryandDiscoveryIntegrity`
([cosai-oasis/secure-ai-tooling#162](https://github.com/cosai-oasis/secure-ai-tooling/issues/162)).

Module under test: `src/core/tool-integrity.ts`.

## Files

- `conformance-vectors-v1.json` — the vectors.
- `_generate.ts` — deterministic generator (fixed keypairs + fixed timestamp).
  Regenerate with `npx tsx fixtures/tool-registry-integrity/_generate.ts`.

## What a vector contains

Each entry under `vectors[]`:

| field | meaning |
|---|---|
| `input` | the object that gets canonicalized |
| `canonical_bytes_hex` | hex of the utf-8 canonical bytes (APS `canonicalize()`) |
| `canonical_sha256` | SHA-256 of the canonical bytes |
| `metadata_hash` | (metadata vector only) `sha256:` + `canonical_sha256` |
| `ed25519_pubkey_hex` | (signed vectors) the 32-byte public key |
| `ed25519_signature_over_canonical_hex` | (signed vectors) Ed25519 signature over the canonical bytes |
| `expected_verification` | (signed vectors) whether the signature must verify |

## How to verify in any language

For every vector:

1. Canonicalize `input` with your implementation's canonical-JSON routine
   (sorted keys, null-stripped) and confirm the utf-8 bytes equal
   `canonical_bytes_hex`.
2. SHA-256 those bytes and confirm it equals `canonical_sha256`.
3. For signed vectors, Ed25519-verify `ed25519_signature_over_canonical_hex`
   over the canonical bytes with `ed25519_pubkey_hex` and confirm the result
   equals `expected_verification`.

The TypeScript reference run lives in
`tests/tool-registry-integrity.test.ts` (the `Part 4 — conformance vectors`
suite). A second-language run against the same JSON is what makes the
"cross-language conformance vectors" claim true; until that exists the claim
is single-language and must be stated as such.

## Determinism

Ed25519 is deterministic (RFC 8032). With the fixed keypairs and the fixed
`verifiedAt` baked into `_generate.ts`, regenerating the file reproduces it
byte-for-byte.
