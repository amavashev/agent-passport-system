# Drift-Denial Demo

**Ten-second pitch.** The Cursor public CVE class
(GHSA-4cxx-hrm3-49rm, GHSA-vqv7-vq92-x87f, CVE-2025-54135 / CurXecute, NomShub)
shares one shape: an agent ingests a `README`, `.cursor/rules/*`, or `CLAUDE.md`
file mid-session, the file silently changes, and the agent acts on the
attacker's instructions because nothing was bound to *which* instructions the
delegation was issued under. The APS Instruction Provenance Receipt (IPR,
v0.2) binds the delegation to a content-addressed `context_root` over the
agent's discovered instruction files and re-checks the root immediately before
each action. A swap → mismatch → structural deny.

This demo runs both paths side-by-side and verifies its canonicalization
against the IPR module's published fixture vectors.

## Run

```bash
npx tsx demo.ts
```

Expected output is checked in at [`expected-output.txt`](./expected-output.txt).
The demo is fully deterministic — every hash, including `context_root` at
issuance and at action time, is reproducible byte-for-byte across machines.

## What the demo does

1. Issues an APS delegation `D` for action classes `github.merge_pr` and
   `send_payment`.
2. The agent walks `discovery_patterns: ["./CLAUDE.md", "./.cursor/rules/*.md"]`,
   reads the matched files (the bundled `CLAUDE.md` and `.cursor/rules/security.md`),
   and emits an `InstructionProvenanceReceipt v0.2` with
   `recompute_at_action: true` and `attestation_tier: self-asserted`.
3. Mid-session, the demo swaps `.cursor/rules/security.md` with the
   `.attack` companion file (`.cursor/rules/security.md.attack`), simulating
   the README/rules-file injection vector from the Cursor CVEs.
4. The agent attempts `send_payment` under `D`, recomputes
   `context_root_at_action_time` over the same discovery patterns.
5. The verifier compares the action-time root against the root in the IPR.
   The two differ → it emits a `context_drift` event and rejects the action.
6. The original `.cursor/rules/security.md` content is restored in a
   `try/finally`, so the demo is idempotent.

A second pass through the demo runs all six positive fixture vectors from
[`fixtures/instruction-provenance/canonicalize-fixture-v1.json`](../../fixtures/instruction-provenance/canonicalize-fixture-v1.json)
through the same canonicalizer used by the demo itself, and asserts:

- `canonicalize_envelope(envelope)` matches each vector's `canonical_bytes_hex`
- `sha256` of those bytes matches each vector's `canonical_sha256` and `receipt_id`
- `compute_context_root(instruction_files)` matches each vector's `context_root`

If any vector drifts, the demo exits non-zero. Today it prints
`6/6 vectors PASS`.

## Files

| Path | Purpose |
|---|---|
| `demo.ts` | One-shot scenario runner. Run with `npx tsx demo.ts`. |
| `CLAUDE.md` | Initial benign instruction file ingested by the agent. |
| `.cursor/rules/security.md` | Initial benign rules file ingested by the agent. |
| `.cursor/rules/security.md.attack` | The injected version that gets swapped in mid-session. |
| `expected-output.txt` | Byte-exact expected stdout from `npx tsx demo.ts`. |

## What this is not

- Not a generic prompt-injection detector. The IPR mitigates the specific
  class where the *attacker controls a file the agent re-reads after
  delegation issuance*. It does not, on its own, cover injection in
  conversational user input or upstream model output.
- Not a payment system. `send_payment` is a stand-in for any post-delegation
  action whose authority would be falsely escalated by injected instructions.
- Not a substitute for the protocol pieces around it: delegation issuance,
  cascade revocation, and decision receipts still apply.
