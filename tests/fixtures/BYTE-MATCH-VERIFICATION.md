# Reciprocal byte-match verification

External, independent verifiers reproduce APS canonical JSON output
byte-for-byte. Anyone can clone, install, and re-run them.

## Verifiers

- **APS bilateral-delegation byte-match**
  https://github.com/arian-gogani/nobulex/blob/main/scripts/verify-aps-byte-match.mjs
  Reads `fixtures/bilateral-delegation/canonicalize-fixture-v1.json` from
  this repo (10 JCS vectors, RFC 8785). Canonicalizes via
  `@nobulex/crypto`'s `canonicalizeJson`, sha256s the output, and
  compares against each vector's pinned `canonical_sha256`. Exit 0 on
  full match; exit 1 on any drift.

- **CTEF v0.3.1 byte-match**
  https://github.com/arian-gogani/nobulex/blob/main/scripts/verify-ctef-byte-match.mjs
  Reads `https://agentgraph.co/.well-known/cte-test-vectors.json` (4
  inline vectors: 2 positive + 2 negative with pinned error codes).
  Same canonicalize-and-compare contract.

## Reproducing

```bash
git clone --depth 1 https://github.com/arian-gogani/nobulex
cd nobulex
npm install
# stage the APS fixture so the APS verifier skips the network fetch:
cp ../agent-passport-system/fixtures/bilateral-delegation/canonicalize-fixture-v1.json aps-fixture-v1.json
node scripts/verify-aps-byte-match.mjs
node scripts/verify-ctef-byte-match.mjs
```

Both write JSON receipts (`aps-byte-match-receipt.json`,
`ctef-byte-match-receipt.json`) on success.

## Most recent run

2026-05-02. **14/14 checks pass** (10 APS + 4 CTEF). Receipts archived
locally at `/tmp/aps-byte-match-receipts-2026-05-02/SUMMARY.md` for the
session that ran the verification.

## Why this lives here

APS's own test suite verifies internal byte-parity. The nobulex verifiers
verify the same canonical bytes from a *different* canonicalizer
implementation. When both produce the same sha256 over the same
inputs, that's reciprocal evidence the canonicalization is
implementation-independent — a stronger claim than any single SDK
testing itself.
