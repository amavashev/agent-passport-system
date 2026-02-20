// Agent Passport System — Public API v2.0
// The Agent Social Contract: Identity · Values · Attribution
//
// Layer 1: Cryptographic Identity & Accountability
// Layer 2: Human Values Floor
// Layer 3: Beneficiary Attribution

// ── Layer 1: Identity & Accountability ──
export { createPassport, signPassport, updatePassport, isExpired } from './core/passport.js'
export { canonicalize } from './core/canonical.js'
export { generateKeyPair, sign, verify, publicKeyFromPrivate } from './crypto/keys.js'
export { verifyPassport, createChallenge, verifyChallenge } from './verification/verify.js'
export { applyReputationEvent, calculateOverallScore } from './verification/reputation.js'

// v1.1 — Delegation, Receipts, Revocation
export {
  createDelegation, subDelegate, verifyDelegation,
  revokeDelegation, verifyRevocation,
  createReceipt, verifyReceipt,
  getReceipts, getRevocation, clearStores
} from './core/delegation.js'

// ── Layer 2: Human Values Floor ──
export {
  loadFloor, loadFloorFromFile,
  attestFloor, verifyAttestation,
  evaluateCompliance,
  negotiateCommonGround
} from './core/values.js'

// ── Layer 3: Beneficiary Attribution ──
export {
  hashReceipt,
  traceBeneficiary,
  computeAttribution, verifyAttributionReport,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
  computeCollaborationAttribution
} from './core/attribution.js'

// ── Types ──
export type {
  // Layer 1
  AgentPassport, SignedPassport, KeyPair, VerificationResult,
  Challenge, ChallengeResponse, ReputationScore, ReputationEvent,
  Delegation, RuntimeInfo, CreatePassportOptions,
  ActionReceipt, RevocationRecord, DelegationStatus,
  // Layer 2
  ValuesFloor, FloorPrinciple, FloorAttestation,
  ComplianceCheck, ComplianceReport, SharedGround, FloorReference,
  // Layer 3
  BeneficiaryInfo, BeneficiaryTrace, DelegationHop,
  AttributionEntry, AttributionReport,
  MerkleProof, MerkleProofNode
} from './types/passport.js'

// Re-export collaboration attribution type
export type { CollaborationAttribution } from './core/attribution.js'
