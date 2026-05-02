// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Claim Verifier (Module 2 of 4) — pure registry type-checker
// ══════════════════════════════════════════════════════════════════
// verifyEvidenceClaim is a pure function. It checks an evidence bundle against
// the EvidenceProfile for a stated claim and returns a discriminated
// result. No I/O, no signing, no key resolution, no clock reads, no
// network, no mutation.
//
// What this module DOES check:
//   - claim.type is a known ClaimType present in the registry
//   - the registry entry for claim.type is populated (not a stub)
//   - APSBundle records are not silently substituted for leaf evidence
//     (a bundle is a Merkle commitment over receipt_ids; satisfying a
//     leaf claim from it requires an inclusion proof, which is out of
//     scope here)
//   - no forbidden substitution is being attempted (e.g. ActionReceipt
//     for BINDING_COMMITMENT)
//   - every required RecordType is present in the evidence list
//
// What this module does NOT check:
//   - signatures, receipt_id integrity, JCS canonicality
//   - timestamp freshness, expiry, key rotation, revocation
//   - delegation/authority chains
//   - contestation status of underlying receipts
//   - cross-receipt referential integrity (e.g. that the
//     AuthorityBoundaryReceipt.action_id matches an ActionReceipt
//     whose receipt_id appears in a sibling record)
//
// Those checks belong to Module 3 (gateway integration) and Module 4
// (contestation extension). Treat verifyEvidenceClaim as the static type-
// system of the protocol: it tells you whether a stated set of
// receipts could in principle satisfy a stated claim, given only the
// claim → evidence schema in the registry.
// ══════════════════════════════════════════════════════════════════

import {
  ClaimType,
  RecordType,
  EvidenceProfiles,
} from './claim-evidence-types.js'
import type { APSBundle } from './accountability/types/bundle.js'

export type ClaimVerificationResult =
  | { status: 'valid'; claimType: ClaimType; satisfiedBy: RecordType[] }
  | {
      status: 'missing_evidence'
      claimType: ClaimType
      missing: RecordType[]
      provided: RecordType[]
    }
  | {
      status: 'forbidden_substitution'
      claimType: ClaimType
      offendingRecord: RecordType
      reason: string
    }
  | { status: 'unsupported_claim_type'; claimType: ClaimType }
  | { status: 'profile_not_populated'; claimType: ClaimType }
  | {
      status: 'bundle_requires_inclusion_proof'
      claimType: ClaimType
      bundleRecord: APSBundle
    }

export interface ClaimVerificationInput {
  claim: { type: ClaimType; subject: string }
  evidence: Array<{ recordType: RecordType; record: unknown }>
}

export function verifyEvidenceClaim(input: ClaimVerificationInput): ClaimVerificationResult {
  const { claim, evidence } = input

  // 1. unsupported_claim_type — claim.type is not a registry key.
  const profile = (EvidenceProfiles as Record<string, typeof EvidenceProfiles[ClaimType]>)[
    claim.type
  ]
  if (profile === undefined) {
    return { status: 'unsupported_claim_type', claimType: claim.type }
  }

  // 2. profile_not_populated — registry entry is a stub.
  const hasRequired = profile.required.length > 0
  const hasForbidden = Object.keys(profile.forbiddenSubstitutions).length > 0
  if (!hasRequired && !hasForbidden) {
    return { status: 'profile_not_populated', claimType: claim.type }
  }

  // 3. bundle_requires_inclusion_proof — APSBundle slipped in for a non-batch claim.
  if (claim.type !== ClaimType.BATCH_ATTESTED) {
    const bundleEntry = evidence.find((e) => e.recordType === RecordType.APSBundle)
    if (bundleEntry !== undefined) {
      return {
        status: 'bundle_requires_inclusion_proof',
        claimType: claim.type,
        bundleRecord: bundleEntry.record as APSBundle,
      }
    }
  }

  // 4. forbidden_substitution — first match wins, in evidence order.
  for (const entry of evidence) {
    const reason = profile.forbiddenSubstitutions[entry.recordType]
    if (reason !== undefined) {
      return {
        status: 'forbidden_substitution',
        claimType: claim.type,
        offendingRecord: entry.recordType,
        reason,
      }
    }
  }

  // 5. missing_evidence — required types not present in evidence.
  const providedTypes = evidence.map((e) => e.recordType)
  const providedSet = new Set(providedTypes)
  const missing = profile.required.filter((r) => !providedSet.has(r))
  if (missing.length > 0) {
    return {
      status: 'missing_evidence',
      claimType: claim.type,
      missing,
      provided: providedTypes,
    }
  }

  // 6. valid.
  return {
    status: 'valid',
    claimType: claim.type,
    satisfiedBy: [...profile.required],
  }
}
