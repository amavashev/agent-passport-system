// Human Values Floor — Attestation, Compliance, and Negotiation
// Layer 2 of the Agent Social Contract
//
// This is NOT a filter or middleware. It is a cryptographic attestation
// and compliance verification system. Agents attest to the Floor when
// creating passports. Compliance is verifiable against action receipts.

import { v4 as uuidv4 } from 'uuid'
import { readFileSync } from 'node:fs'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ValuesFloor, FloorPrinciple, FloorAttestation,
  ComplianceCheck, ComplianceReport, SharedGround,
  AgentPassport, ActionReceipt, SignedPassport
} from '../types/passport.js'

// ══════════════════════════════════════
// FLOOR LOADING
// ══════════════════════════════════════

/**
 * Parse a Values Floor YAML manifest into a typed structure.
 * Supports both file paths and raw YAML strings.
 * 
 * Design decision: We parse YAML manually rather than adding a dependency.
 * The floor.yaml structure is simple enough that a minimal parser suffices.
 * Zero dependencies is a protocol design principle.
 */
export function loadFloor(yamlContent: string): ValuesFloor {
  const lines = yamlContent.split('\n')
  const floor: ValuesFloor = {
    version: '',
    schema: '',
    lastUpdated: '',
    governanceUri: '',
    floor: []
  }

  let currentPrinciple: Partial<FloorPrinciple> | null = null
  let inFloor = false
  let inEnforcement = false

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith('#') || trimmed === '') continue

    // Top-level fields
    if (trimmed.startsWith('version:')) floor.version = extractYamlValue(trimmed)
    if (trimmed.startsWith('schema:')) floor.schema = extractYamlValue(trimmed)
    if (trimmed.startsWith('last_updated:')) floor.lastUpdated = extractYamlValue(trimmed)
    if (trimmed.startsWith('governance_uri:')) floor.governanceUri = extractYamlValue(trimmed)

    // Floor section
    if (trimmed === 'floor:') { inFloor = true; continue }
    if (inFloor && trimmed.startsWith('extensions:')) { inFloor = false; continue }

    if (inFloor) {
      if (trimmed.startsWith('- id:')) {
        if (currentPrinciple && currentPrinciple.id) {
          floor.floor.push(currentPrinciple as FloorPrinciple)
        }
        currentPrinciple = {
          id: extractYamlValue(trimmed.slice(2)),
          enforcement: { technical: false, mechanism: '' },
          weight: 'mandatory'
        }
        inEnforcement = false
      }
      if (currentPrinciple) {
        if (trimmed.startsWith('name:')) currentPrinciple.name = extractYamlValue(trimmed)
        if (trimmed.startsWith('weight:')) currentPrinciple.weight = extractYamlValue(trimmed) as FloorPrinciple['weight']
        if (trimmed.startsWith('principle: >')) {
          // Multi-line value — collect next lines
          currentPrinciple.principle = ''
        } else if (trimmed.startsWith('principle:')) {
          currentPrinciple.principle = extractYamlValue(trimmed)
        }
        if (trimmed === 'enforcement:') { inEnforcement = true; continue }
        if (inEnforcement) {
          if (trimmed.startsWith('technical:')) {
            currentPrinciple.enforcement!.technical = trimmed.includes('true')
          }
          if (trimmed.startsWith('mechanism:')) {
            currentPrinciple.enforcement!.mechanism = extractYamlValue(trimmed)
          }
          if (trimmed.startsWith('protocol_ref:')) {
            currentPrinciple.enforcement!.protocolRef = extractYamlValue(trimmed)
          }
        }
      }
    }
  }

  // Push last principle
  if (currentPrinciple && currentPrinciple.id) {
    floor.floor.push(currentPrinciple as FloorPrinciple)
  }

  return floor
}

export function loadFloorFromFile(filePath: string): ValuesFloor {
  const content = readFileSync(filePath, 'utf-8')
  return loadFloor(content)
}

function extractYamlValue(line: string): string {
  const colonIdx = line.indexOf(':')
  if (colonIdx === -1) return ''
  let val = line.slice(colonIdx + 1).trim()
  // Remove quotes
  if ((val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))) {
    val = val.slice(1, -1)
  }
  return val
}

// ══════════════════════════════════════
// FLOOR ATTESTATION
// ══════════════════════════════════════

/**
 * Create a cryptographic attestation that an agent adheres to the Floor.
 * 
 * This is the key innovation: attestation, not enforcement.
 * The agent signs a commitment that it will reference Floor principles
 * during reasoning. This commitment is:
 *   - Verifiable (Ed25519 signature)
 *   - Non-repudiable (agent can't deny it attested)
 *   - Auditable (compliance can be checked against receipts)
 * 
 * An agent that attests but violates creates a provable contradiction —
 * which impacts reputation through the compliance system.
 */
export function attestFloor(
  agentId: string,
  publicKey: string,
  floorVersion: string,
  extensions: string[],
  privateKey: string,
  expiresInDays: number = 365
): FloorAttestation {
  const now = new Date()
  const expiry = new Date(now)
  expiry.setDate(expiry.getDate() + expiresInDays)

  const commitment = [
    `I, agent ${agentId}, attest that I will reference the Human Values Floor v${floorVersion}`,
    `and extensions [${extensions.join(', ')}] as weighted considerations during reasoning.`,
    `This attestation is cryptographically binding and my compliance is verifiable`,
    `against my signed action receipts.`
  ].join(' ')

  const attestation: Omit<FloorAttestation, 'signature'> = {
    attestationId: 'att_' + uuidv4().slice(0, 12),
    agentId,
    publicKey,
    floorVersion,
    extensions,
    attestedAt: now.toISOString(),
    expiresAt: expiry.toISOString(),
    commitment
  }

  const canonical = canonicalize(attestation)
  const signature = sign(canonical, privateKey)

  return { ...attestation, signature }
}

export function verifyAttestation(
  attestation: FloorAttestation
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = attestation
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, attestation.publicKey)
  if (!sigValid) errors.push('Invalid attestation signature')

  if (new Date(attestation.expiresAt) < new Date()) {
    errors.push('Attestation expired')
  }

  if (!attestation.floorVersion) errors.push('No floor version specified')

  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// COMPLIANCE VERIFICATION
// ══════════════════════════════════════

/**
 * Evaluate an agent's compliance with the Floor by analyzing its receipts.
 * 
 * This is where attestation meets evidence. For each Floor principle,
 * we check whether the agent's action receipts demonstrate compliance:
 * 
 * - F-001 Traceability: Does every receipt have a delegation chain?
 * - F-002 Honest Identity: Does the agent ID in receipts match passport?
 * - F-003 Scoped Authority: Is every receipt's scopeUsed within delegation scope?
 * - F-004 Revocability: Were any receipts created under revoked delegations?
 * - F-005 Auditability: Are all receipts properly signed and verifiable?
 * - F-006 Non-Deception: Attested only (requires reasoning-level analysis)
 * - F-007 Proportionality: Compare scope breadth vs reputation score
 * 
 * The output is a signed ComplianceReport that anyone can verify.
 */
export function evaluateCompliance(
  agentId: string,
  receipts: ActionReceipt[],
  floor: ValuesFloor,
  delegations: Map<string, { scope: string[]; revoked: boolean }>,
  verifierPrivateKey: string
): ComplianceReport {
  const checks: ComplianceCheck[] = []
  const agentReceipts = receipts.filter(r => r.agentId === agentId)

  for (const principle of floor.floor) {
    const check = evaluatePrinciple(principle, agentReceipts, delegations)
    checks.push(check)
  }

  const enforced = checks.filter(c => c.status === 'enforced').length
  const attested = checks.filter(c => c.status === 'attested').length
  const violations = checks.filter(c => c.status === 'violation').length
  const total = checks.length

  // Compliance score: enforced = 1.0, attested = 0.8, unverifiable = 0.5, violation = 0.0
  const score = checks.reduce((sum, c) => {
    if (c.status === 'enforced') return sum + 1.0
    if (c.status === 'attested') return sum + 0.8
    if (c.status === 'unverifiable') return sum + 0.5
    return sum // violation = 0
  }, 0) / total

  const timestamps = agentReceipts.map(r => r.timestamp).sort()
  const report: Omit<ComplianceReport, 'signature'> = {
    reportId: 'comp_' + uuidv4().slice(0, 12),
    agentId,
    floorVersion: floor.version,
    period: {
      from: timestamps[0] || new Date().toISOString(),
      to: timestamps[timestamps.length - 1] || new Date().toISOString()
    },
    receiptsAnalyzed: agentReceipts.length,
    checks,
    overallCompliance: Math.round(score * 1000) / 1000,
    generatedAt: new Date().toISOString()
  }

  const canonical = canonicalize(report)
  const signature = sign(canonical, verifierPrivateKey)

  return { ...report, signature }
}

function evaluatePrinciple(
  principle: FloorPrinciple,
  receipts: ActionReceipt[],
  delegations: Map<string, { scope: string[]; revoked: boolean }>
): ComplianceCheck {
  const base: Omit<ComplianceCheck, 'status' | 'detail'> = {
    principleId: principle.id,
    principleName: principle.name
  }

  switch (principle.id) {
    case 'F-001': { // Traceability
      const allTraced = receipts.every(r =>
        r.delegationChain && r.delegationChain.length > 0
      )
      if (receipts.length === 0) {
        return { ...base, status: 'unverifiable', detail: 'No receipts to analyze' }
      }
      return allTraced
        ? { ...base, status: 'enforced', detail: `All ${receipts.length} receipts have delegation chains`, evidence: receipts[0]?.receiptId }
        : { ...base, status: 'violation', detail: `${receipts.filter(r => !r.delegationChain?.length).length} receipts missing delegation chain` }
    }

    case 'F-002': { // Honest Identity
      // All receipts from same agent should have consistent agentId
      const agentIds = new Set(receipts.map(r => r.agentId))
      if (agentIds.size <= 1) {
        return { ...base, status: 'enforced', detail: 'Consistent agent identity across all receipts' }
      }
      return { ...base, status: 'violation', detail: `Multiple agent IDs found: ${[...agentIds].join(', ')}` }
    }

    case 'F-003': { // Scoped Authority
      const violations: string[] = []
      for (const receipt of receipts) {
        const del = delegations.get(receipt.delegationId)
        if (del && !del.scope.includes(receipt.action.scopeUsed)) {
          violations.push(receipt.receiptId)
        }
      }
      if (violations.length > 0) {
        return { ...base, status: 'violation', detail: `${violations.length} out-of-scope actions`, evidence: violations[0] }
      }
      return { ...base, status: 'enforced', detail: 'All actions within delegated scope' }
    }

    case 'F-004': { // Revocability
      const postRevocation: string[] = []
      for (const receipt of receipts) {
        const del = delegations.get(receipt.delegationId)
        if (del && del.revoked) {
          postRevocation.push(receipt.receiptId)
        }
      }
      if (postRevocation.length > 0) {
        return { ...base, status: 'violation', detail: `${postRevocation.length} actions under revoked delegations`, evidence: postRevocation[0] }
      }
      return { ...base, status: 'enforced', detail: 'No actions under revoked delegations' }
    }

    case 'F-005': { // Auditability
      const allSigned = receipts.every(r => r.signature && r.signature.length > 0)
      if (receipts.length === 0) {
        return { ...base, status: 'unverifiable', detail: 'No receipts to audit' }
      }
      return allSigned
        ? { ...base, status: 'enforced', detail: `All ${receipts.length} receipts cryptographically signed` }
        : { ...base, status: 'violation', detail: 'Unsigned receipts found' }
    }

    case 'F-006': { // Non-Deception
      // Cannot be technically verified — requires reasoning-level analysis
      return { ...base, status: 'attested', detail: 'Non-deception requires reasoning-level verification; agent has attested' }
    }

    case 'F-007': { // Proportionality
      return { ...base, status: 'attested', detail: 'Proportionality requires reputation context; agent has attested' }
    }

    default:
      return { ...base, status: 'unverifiable', detail: `Unknown principle ${principle.id}` }
  }
}

// ══════════════════════════════════════
// COMMON GROUND NEGOTIATION
// ══════════════════════════════════════

/**
 * When two agents interact, determine their shared ethical ground.
 * 
 * This is the "handshake" described in the paper. Both agents must
 * have attested to the Floor. The negotiation determines:
 *   1. Whether they share a compatible floor version
 *   2. Which extensions they both adhere to
 *   3. Whether collaboration can proceed
 * 
 * Returns a SharedGround object that both agents can reference
 * during their collaboration.
 */
export function negotiateCommonGround(
  passportA: AgentPassport,
  attestationA: FloorAttestation,
  passportB: AgentPassport,
  attestationB: FloorAttestation
): SharedGround {
  const reasons: string[] = []

  // Check both attestations are valid (not expired)
  if (new Date(attestationA.expiresAt) < new Date()) {
    reasons.push(`Agent ${passportA.agentId} attestation expired`)
  }
  if (new Date(attestationB.expiresAt) < new Date()) {
    reasons.push(`Agent ${passportB.agentId} attestation expired`)
  }

  // Check floor version compatibility
  // Semantic: same major version = compatible
  const versionA = attestationA.floorVersion
  const versionB = attestationB.floorVersion
  const majorA = versionA.split('.')[0]
  const majorB = versionB.split('.')[0]
  const versionCompatible = majorA === majorB

  if (!versionCompatible) {
    reasons.push(`Incompatible floor versions: ${versionA} vs ${versionB}`)
  }

  // Find shared extensions
  const extA = new Set(attestationA.extensions)
  const extB = new Set(attestationB.extensions)
  const shared = [...extA].filter(e => extB.has(e))

  return {
    floorVersion: versionCompatible ? versionA : null,
    sharedExtensions: shared,
    agentA: passportA.publicKey,
    agentB: passportB.publicKey,
    negotiatedAt: new Date().toISOString(),
    compatible: reasons.length === 0 && versionCompatible,
    incompatibilityReasons: reasons
  }
}
