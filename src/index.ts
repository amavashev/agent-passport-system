// Agent Passport System — Public API v1.1
// Cryptographic identity, trust scoring, delegation, receipts & revocation

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

// Re-export types
export type {
  AgentPassport, SignedPassport, KeyPair, VerificationResult,
  Challenge, ChallengeResponse, ReputationScore, ReputationEvent,
  Delegation, RuntimeInfo, CreatePassportOptions,
  ActionReceipt, RevocationRecord, DelegationStatus
} from './types/passport.js'
