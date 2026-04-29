# aps-fs-witness

An independent filesystem witness for the APS InstructionProvenanceReceipt
(IPR). Walks declared discovery patterns, hashes every matched file, and
emits a signed `WitnessedContextRoot` envelope.

The whole point of this package is operational independence. It is a
**separate process** with its own **locally-generated Ed25519 keypair**
(stored at `~/.aps-fs-witness/witness-key.json` on first run). It is
structurally distinct from any agent process, by design.

The witness's `context_root` is computed with a **byte-identical port** of
the IPR's `canonicalize.ts` (vendored at `vendor/canonicalize.ts`). Two
honest implementations walking the same files at the same instant must
produce the same digest — that is the only thing this witness asserts.

---

## Install / run

```sh
npm install
npm test

# One-shot witnessing (v0; no watch mode):
npm start -- --once \
  --working-root /abs/path/to/working_root \
  --discovery-patterns "./CLAUDE.md,./AGENTS.md,./.cursorrules" \
  --filesystem-mode case-sensitive \
  --independence-level separate-process
```

The CLI writes a signed `WitnessedContextRoot` JSON envelope to stdout.

The Ed25519 key is generated locally on first run. **Do not** copy or seed
this key from any agent's keypair — that would defeat the witness.

---

## What this proves

When `aps-fs-witness` returns a signed `WitnessedContextRoot`:

1. **An independent process observed the declared instruction files at
   observation time.** The witness ran in its own process, with its own
   Ed25519 keypair, structurally separate from the agent. The witness DID
   in `witness_did` is derived from a key the witness generated locally,
   not from an agent.
2. **The declared `discovery_patterns` matched exactly the files listed
   in `instruction_files`** at the moment recorded in `observed_at`. Each
   file's `digest` is the sha256 of its bytes at that moment.
3. **The `context_root` was computed via byte-identical canonicalization
   to the IPR module.** Anyone re-running the same canonicalization over
   the same `instruction_files` array will produce the same hex digest;
   our test suite asserts this against the IPR shared fixtures
   (`fixtures/instruction-provenance/canonicalize-fixture-v1.json`).
4. **The envelope is signed.** Verifiers who trust the witness's public
   key can confirm the envelope was not tampered with after issuance.

That is the whole claim. Every limitation below is intentional.

---

## What this does NOT prove

These are also signed into every envelope under `claim_limitations`, so
verifiers can render them to humans rather than silently treat the
envelope as a stronger guarantee than it is.

1. **The agent used only these instructions.** The witness has no
   visibility into the agent's runtime. The agent could read additional
   files, network resources, embedded prompts, or hard-coded instructions
   that this witness never saw.
2. **No other instructions influenced the action.** Even if the agent
   only opened the declared files, instruction-class content can reach
   the model through tool outputs, retrieved documents, conversation
   history, or operator system prompts — none of which a filesystem
   witness can observe.
3. **The model's attention respected the file content.** The witness
   confirms bytes-on-disk; it does not confirm the model conditioned on
   them, or weighted them as intended, or didn't override them with a
   prior from training.
4. **The agent did not read instruction-class content from outside the
   declared discovery patterns.** The witness only walks what it is
   told to walk. Files the agent reads from outside `working_root` or
   from paths not matching any declared glob are invisible here.
5. **File content at agent-execution time matches file content at
   witness-observation time.** Without `recompute_at_action` plus an
   action-time witness pass, drift between observation and execution is
   undetectable from this envelope alone.
6. **`discovery_patterns` are exhaustive over the working root.** The
   witness signs what the agent claimed to walk — it does not assert the
   agent's pattern set covers every instruction-class file in the
   directory tree.

If you need any of the claims above, this primitive is not enough on its
own — pair it with action-time recomputation, runtime attestation, model
provenance, or a stricter trust anchor. See the IPR spec
(`INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md`, ENFORCEMENT-TRUST-ANCHOR
Component 4) for the full tier model.

---

## Layout

```
src/
  index.ts          CLI entry. --once, --working-root, --discovery-patterns, ...
  witness.ts        walk + hash + sign pipeline; key load/create
  types.ts          WitnessedContextRoot envelope type
vendor/
  canonical-jcs.ts  RFC 8785 JCS, byte-identical to APS core/canonical-jcs.ts
  canonicalize.ts   byte-identical port of IPR canonicalize.ts
  types.ts          minimal IPR type subset reused by the vendored canonicalize
tests/
  fixtures/canonicalize-fixture-v1.json   vendored IPR shared fixture
  witness.test.ts                         parity, omission, drift, e2e
```

The `vendor/` tree is the byte-parity contract. Edits there silently
break IPR interoperability; only update them by re-vendoring from
`feat/v2-instruction-provenance` (or whatever branch carries the
canonical IPR module by then).

---

## Independence rules

1. The witness key is **generated locally on first run** with Node's
   `generateKeyPairSync('ed25519')`. No external entropy source, no
   shared key material with any agent.
2. The witness key file is mode 0600, in a directory mode 0700.
3. The witness CLI does **not** accept a private key from arguments,
   environment variables, or stdin — only from the on-disk key file.
4. The witness emits a `claim_limitations` array on every envelope.
   Removing or shortening that array is a downstream-verifier concern;
   the witness will not silently emit a stronger claim than it can back.

---

## License

Apache-2.0. See repository root LICENSE.
