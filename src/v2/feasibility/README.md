# Feasibility: proof_ref slot + IR compiler

Two additive protocol primitives. Both are solver free. No solver dependency is
introduced this round.

## 1. proof_ref slot

`PolicyReceipt.proof_ref` (optional, absent by default) names an external
soundness proof by content hash. The field is format agnostic on purpose: it
commits to no cross-system proof object schema. That work is tracked separately
(A2A#1463).

```ts
import { buildProofRef, validateProofRef } from './proof-ref.js'

const ref = buildProofRef({ artifact: smtLibString, proofSystem: 'smtlib2' })
// ref = { algorithm: 'sha256', hash: '<64 hex>', proofSystem: 'smtlib2' }

const receipt: PolicyReceipt = { /* ... */, proof_ref: ref, signature }
```

When a receipt carries a `proof_ref`, the emitter SHOULD add
`proofRefScopeNote()` to the receipt's `scope_of_claim.does_not_assert`, so the
receipt stays honest about what was and was not validated.

## 2. Feasibility IR compiler

`compileFeasibility({ policy, delegation })` compiles a requested action plus a
delegation envelope into a deterministic `FeasibilityIR`: declared variables and
the conjunction of scope, spend, depth, temporal-window, and revocation
constraints the action must satisfy. `emitSmtLib(ir)` renders the IR as an
SMT-LIB 2 script. `compileToSmtLib(input)` does both.

```ts
import { compileToSmtLib } from './compiler.js'

const smt = compileToSmtLib({
  policy: { scopeRequired: 'data:read', spend: 10 },
  delegation: {
    scope: ['data:read', 'data:write'],
    spendLimit: 100, spentAmount: 5,
    maxDepth: 3, currentDepth: 1,
    expiresAt: '2026-12-31T00:00:00Z',
  },
})
// smt is a (set-logic ...) (declare-const ...) (assert ...) (check-sat) script.
```

The output is deterministic: a fixed input always produces byte-identical IR and
byte-identical SMT-LIB. No clock, randomness, or ambient state is read.

## Proof box

**proof_ref**

- Proves: a `proof_ref` names an external proof artifact by content hash.
  Attaching one to a receipt proves only that the receipt points at that
  artifact.
- Does not prove: that the referenced proof is valid, sound, or even
  retrievable. Validation of the artifact is out of band and out of scope this
  round.

**Feasibility IR compiler**

- Proves: the compiled IR specifies the feasibility obligation for the action
  against the delegation envelope.
- Does not prove: that the obligation is satisfiable. The compiler does not
  decide feasibility. Nothing here solves the obligation, and no solver is
  introduced this round.

## Boundary

These are protocol primitives: type shapes and pure functions. They build no
service, no hosted registry, no resolution endpoint, and no aggregation. A
solver, a proof validator, or a hosted feasibility service would be separate
product surface and is out of scope here.
