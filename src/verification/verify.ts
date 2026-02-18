// Passport Verification — validate signatures and integrity

import { verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import { isExpired } from '../core/passport.js'
import type { SignedPassport, VerificationResult, Challenge } from '../types/passport.js'
import { randomBytes } from 'node:crypto'
import { v4 as uuidv4 } from 'uuid'

export function verifyPassport(signed: SignedPassport): VerificationResult {
  const errors: string[] = []
  const warnings: string[] = []

  // Check required fields
  if (!signed.passport || !signed.signature) {
    return { valid: false, errors: ['Missing passport or signature'], warnings }
  }

  const { passport, signature } = signed

  // Verify cryptographic signature
  const canonical = canonicalize(passport)
  const sigValid = verify(canonical, signature, passport.publicKey)
  if (!sigValid) {
    errors.push('Invalid signature — passport may have been tampered with')
  }

  // Check expiration
  if (isExpired(passport)) {
    errors.push(`Passport expired at ${passport.expiresAt}`)
  }

  // Check version
  if (!passport.version) {
    warnings.push('No version field')
  }

  // Check required identity fields
  if (!passport.agentId) errors.push('Missing agentId')
  if (!passport.publicKey) errors.push('Missing publicKey')
  if (!passport.capabilities || passport.capabilities.length === 0) {
    warnings.push('No capabilities declared')
  }

  // Check delegations
  for (const delegation of passport.delegations || []) {
    if (new Date(delegation.expiresAt) < new Date()) {
      warnings.push(`Delegation to ${delegation.delegatedTo} has expired`)
    }
    if (delegation.spendLimit && delegation.spentAmount &&
        delegation.spentAmount >= delegation.spendLimit) {
      warnings.push(`Delegation to ${delegation.delegatedTo} has exhausted spend limit`)
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    passport: errors.length === 0 ? passport : undefined
  }
}

export function createChallenge(expiresInSeconds = 300): Challenge {
  return {
    challengeId: uuidv4(),
    nonce: randomBytes(32).toString('hex'),
    timestamp: new Date().toISOString(),
    expiresAt: new Date(Date.now() + expiresInSeconds * 1000).toISOString()
  }
}

export function verifyChallenge(
  challenge: Challenge,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  // Check expiry
  if (new Date(challenge.expiresAt) < new Date()) return false
  // Verify signature over the nonce
  return verify(challenge.nonce, signatureHex, publicKeyHex)
}
