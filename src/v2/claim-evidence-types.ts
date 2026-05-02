// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Claim → Evidence types (skeleton)
// ══════════════════════════════════════════════════════════════════
// Names a closed set of claims an APS receipt can substantiate, the
// record types the protocol can produce, and the mapping between
// them. Receipts substantiate specific claims; not every receipt
// can substitute for another. This module is the static surface of
// that mapping. Verification logic lives elsewhere.
// ══════════════════════════════════════════════════════════════════

export enum ClaimType {
  IDENTITY_VERIFIED = 'IDENTITY_VERIFIED',
  AUTHORITY_TO_EXECUTE = 'AUTHORITY_TO_EXECUTE',
  ACTION_EXECUTED = 'ACTION_EXECUTED',
  BINDING_COMMITMENT = 'BINDING_COMMITMENT',
  EFFECT_SAFETY_ATTESTED = 'EFFECT_SAFETY_ATTESTED',
  DERIVATION_TRACED = 'DERIVATION_TRACED',
  CLAIM_CONTESTED = 'CLAIM_CONTESTED',
  CLAIM_RESOLVED = 'CLAIM_RESOLVED',
}

/**
 * Mirrors the existing record-producing primitives the SDK ships.
 * Names match the TypeScript interfaces / class shapes already in
 * the public surface (see src/index.ts). When new primitives are
 * added, extend this enum and update EvidenceProfiles accordingly.
 */
export enum RecordType {
  ActionReceipt = 'ActionReceipt',
  AuthorityBoundaryReceipt = 'AuthorityBoundaryReceipt',
  CustodyReceipt = 'CustodyReceipt',
  ContestabilityReceipt = 'ContestabilityReceipt',
  APSBundle = 'APSBundle',
  AccessReceipt = 'AccessReceipt',
  DerivationReceipt = 'DerivationReceipt',
  DecisionReceipt = 'DecisionReceipt',
  ProvisionalStatement = 'ProvisionalStatement',
  PromotionEvent = 'PromotionEvent',
  Withdrawal = 'Withdrawal',
  InstructionProvenanceReceipt = 'InstructionProvenanceReceipt',
  CognitiveAttestation = 'CognitiveAttestation',
}

export interface EvidenceProfile {
  required: RecordType[]
  optional?: RecordType[]
  forbiddenSubstitutions: Partial<Record<RecordType, string>>
}

export const EvidenceProfiles: Record<ClaimType, EvidenceProfile> = {
  [ClaimType.AUTHORITY_TO_EXECUTE]: {
    required: [RecordType.AuthorityBoundaryReceipt],
    optional: [RecordType.DecisionReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]:
        'Action receipts prove execution, not authority. The boundary ruling is a separate signer (the gateway/evaluator), and conflating them collapses the trust split that makes the audit chain meaningful.',
    },
  },

  [ClaimType.BINDING_COMMITMENT]: {
    required: [RecordType.PromotionEvent, RecordType.ProvisionalStatement],
    optional: [RecordType.DecisionReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]:
        'Action receipts prove execution or communication, not binding commitment.',
      [RecordType.ProvisionalStatement]:
        'A ProvisionalStatement on its own is non-binding by default; binding status requires an explicit PromotionEvent satisfying a PromotionPolicy.',
    },
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.IDENTITY_VERIFIED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.ACTION_EXECUTED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.EFFECT_SAFETY_ATTESTED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.DERIVATION_TRACED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.CLAIM_CONTESTED]: {
    required: [],
    forbiddenSubstitutions: {},
  },

  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.CLAIM_RESOLVED]: {
    required: [],
    forbiddenSubstitutions: {},
  },
}

export function requiredEvidenceFor(claim: ClaimType): EvidenceProfile {
  return EvidenceProfiles[claim]
}
