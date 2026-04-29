// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Minimal IPR type subset vendored for byte-parity canonicalization.
// Mirrors fields read by canonicalize.ts on feat/v2-instruction-provenance.
// Do not extend — keep aligned with IPR types.ts.
// ══════════════════════════════════════════════════════════════════

export type FilesystemMode = 'case-sensitive' | 'case-insensitive'

export type InstructionRole =
  | 'system_prompt'
  | 'agent_md'
  | 'user_md'
  | 'memory'
  | 'rules'
  | 'other'

export interface InstructionFile {
  path: string
  digest: string
  bytes: number
  role: InstructionRole
  is_symlink?: boolean
  symlink_target?: string
}

export interface InstructionProvenanceReceiptBoundTo {
  type: 'session' | 'action' | 'window'
  ref: string
}

export type AttestationTier = 'self-asserted' | 'witnessed' | 'verified'

export interface InstructionProvenanceReceipt {
  receipt_id: string
  delegation_chain_root: string
  agent_did: string
  discovery_patterns: string[]
  working_root: string
  filesystem_mode: FilesystemMode
  instruction_files: InstructionFile[]
  context_root: string
  attestation_tier: AttestationTier
  recompute_at_action: boolean
  issued_at: string
  expires_at?: string
  bound_to: InstructionProvenanceReceiptBoundTo
  signing_key_id: string
  signature: string
}
