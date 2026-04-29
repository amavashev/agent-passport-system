// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// WitnessedContextRoot — types
// ══════════════════════════════════════════════════════════════════
// A WitnessedContextRoot is what an independent filesystem witness emits
// after walking the agent-declared discovery patterns. It restates the
// IPR shape for `instruction_files` and `context_root`, and adds the
// witness's own DID, role, signing key, and a `claim_limitations` array
// that names everything this witness explicitly does NOT prove.
// ══════════════════════════════════════════════════════════════════

import type { FilesystemMode, InstructionFile } from '../vendor/types.js'

export type { FilesystemMode, InstructionFile } from '../vendor/types.js'

/** Operational independence level of the witness relative to the agent.
 *  The witness asserts how structurally separate it is — this is part of
 *  the signed envelope and audited downstream. */
export type WitnessIndependenceLevel =
  /** Same machine as the agent, separate process, separate keypair. */
  | 'separate-process'
  /** Different host than the agent. Separate process and keypair implied. */
  | 'separate-host'
  /** Operated by a different organization than the agent. */
  | 'separate-operator'

/** Witness role in the IPR ecosystem. v0 only emits 'filesystem-witness'. */
export type WitnessRole = 'filesystem-witness'

export interface WitnessedContextRoot {
  /** Witness DID. Independent from any agent DID. v0 emits did:key derived
   *  from the witness's locally-generated Ed25519 public key. */
  witness_did: string

  /** Always 'filesystem-witness' in v0. */
  witness_role: WitnessRole

  /** How structurally independent the witness is from the agent. The
   *  witness signs this claim; downstream verifiers can accept or reject. */
  independence_level: WitnessIndependenceLevel

  /** Wall-clock observation time, ISO 8601 with millisecond precision and
   *  Z suffix. The instant the witness finished walking and hashing. */
  observed_at: string

  /** Working root the witness walked. Absolute POSIX path. Mirrors the
   *  agent-declared `working_root` so verifiers can compare directly. */
  working_root: string

  /** Filesystem case mode used for path canonicalization. Mirrors IPR. */
  filesystem_mode: FilesystemMode

  /** Glob patterns the witness walked, exactly as supplied by the caller.
   *  Non-empty. POSIX globs relative to `working_root`. */
  discovery_patterns: string[]

  /** Files matched by `discovery_patterns`. Same shape as IPR's
   *  `instruction_files`. Sorted in canonical order by `path`. */
  instruction_files: InstructionFile[]

  /** sha256 of the JCS canonicalization of `instruction_files`, computed
   *  with the byte-identical IPR canonicalize.ts vendored alongside. */
  context_root: string

  /** Explicit, machine-readable list of what this witness does NOT claim.
   *  Verifiers are expected to surface these limits to humans rather than
   *  silently treat the envelope as a stronger guarantee than it is. */
  claim_limitations: string[]

  /** Ed25519 signing key fingerprint:
   *  `ed25519:<first-16-hex-of-public-key>`. */
  witness_signing_key_id: string

  /** Ed25519 over the JCS canonicalization of this object minus
   *  `witness_signature`. Hex, 128 chars. */
  witness_signature: string
}

export interface WitnessKeyMaterial {
  /** Ed25519 seed (private key), hex, 64 chars. */
  privateKeyHex: string
  /** Ed25519 public key, hex, 64 chars. */
  publicKeyHex: string
  /** ISO 8601 creation time. Recorded in the on-disk key file. */
  createdAt: string
}
