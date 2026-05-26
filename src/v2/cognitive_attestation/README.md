# cognitive_attestation (signal_type, v0.1)

TypeScript reference implementation for the `cognitive_attestation` signal_type defined in [PR #104](https://github.com/aeoess/agent-governance-vocabulary/pull/104) of the agent-governance-vocabulary.

## Scope

This module implements the v0.1 envelope for three determinability classes:

- `precondition_set`: the set of preconditions evaluated before issuing a decision
- `candidate_set`: the set of candidates considered, with elimination reasons
- `decision_path`: the chosen reasoning path with confidence and per-step hashes

Each envelope is single-signer (Ed25519), JCS-canonicalized (RFC 8785), signature-elided during canonicalization.

## Public surface

- `signCognitiveAttestation(privateKey, envelope)`
- `verifyCognitiveAttestation(envelope)` → `{ valid, reason? }`
- `isCognitiveAttestation(value)` runtime guard
- Per-class payload guards: `isPreconditionSetPayload`, `isCandidateSetPayload`, `isDecisionPathPayload`
- Types via `types.ts`: discriminated union `CognitiveAttestationEnvelope`, per-class envelope shapes, unsigned counterparts, six structured reason codes

## What this attests

The envelope attests **what was reasoned over**, not whether a policy passed or whether the reasoning was sound. The truth of the `class_payload` claim is a downstream consumer responsibility (see PR #104 notes).

## v0.1 scope held

These are deferred to v0.2 and **not** implemented here:

- `pre_commit_chain` class (requires tighter model-loop integration)
- `(F, Ω, D)` triple at envelope level (vocabulary schema gap)
- Reduction-map syntax
- Verifier algorithm for `class_payload` truth
- Privacy posture

## Related module: paper-grade primitive

There is a separate module at `src/v2/cognitive-attestation/` (kebab-case) which is the **paper-grade primitive** from APS v2.1.0, tracking the Zenodo paper [10.5281/zenodo.19646276](https://doi.org/10.5281/zenodo.19646276). That module ships SAE feature-level fidelity, multi-signer with roles, three-stage verification with replay, and typed dispute primitives.

The two modules are different primitives that share a name root. They do not collide on exports and do not import each other. Pick the one that matches your use case:

- This module (`cognitive_attestation`): vocabulary-aligned signal_type for governance-track envelopes
- Paper-grade module (`cognitive-attestation`): feature-level model computation attestation per Paper 7
