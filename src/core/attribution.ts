// Beneficiary Attribution Protocol — Trace, Attribute, Prove
// Layer 3 of the Agent Social Contract
//
// This system produces EVIDENCE, not transactions.
// It traces agent work back to human beneficiaries through
// delegation chains and generates verifiable attribution reports
// with Merkle proofs for O(log n) verification at scale.
//
// Zero new dependencies. Merkle trees use SHA-256 from Node.js crypto.

import { v4 as uuidv4 } from 'uuid'
import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ActionReceipt, Delegation,
  BeneficiaryTrace, DelegationHop,
  AttributionEntry, AttributionReport,
  MerkleProof, MerkleProofNode,
  BeneficiaryInfo
} from '../types/passport.js'

// ══════════════════════════════════════
// CRYPTOGRAPHIC PRIMITIVES
// ══════════════════════════════════════

/**
 * SHA-256 hash — the atomic unit of the Merkle tree.
 * We use this rather than Ed25519 because we need a hash function,
 * not a signature scheme. SHA-256 is collision-resistant, fast,
 * and universally available.
 */
function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

/**
 * Hash a receipt into a leaf node for the Merkle tree.
 * Uses canonical serialization to ensure deterministic hashing —
 * the same receipt always produces the same hash regardless of
 * property ordering.
 */
export function hashReceipt(receipt: ActionReceipt): string {
  return sha256(canonicalize(receipt))
}

// ══════════════════════════════════════
// BENEFICIARY TRACING
// ══════════════════════════════════════

/**
 * Trace an action receipt back to its human beneficiary.
 * 
 * The delegation chain in a receipt contains public key fingerprints
 * from the human principal to the executing agent. This function
 * reconstructs the full path, verifying each hop.
 * 
 * This is the core of the economic model: every agent action is
 * traceable to a human. Not through logging. Through cryptography.
 */
export function traceBeneficiary(
  receipt: ActionReceipt,
  delegations: Delegation[],
  beneficiaryMap: Map<string, BeneficiaryInfo>  // publicKey -> beneficiary
): BeneficiaryTrace {
  const chain: DelegationHop[] = []

  // Walk the delegation chain from the receipt
  // The chain goes: [principal, ..., delegator, executor]
  const keyChain = receipt.delegationChain

  // Find delegations that connect each hop
  for (let i = 0; i < keyChain.length - 1; i++) {
    const from = keyChain[i]
    const to = keyChain[i + 1]

    // Find the delegation connecting these two keys
    const delegation = delegations.find(d =>
      d.delegatedBy === from && d.delegatedTo === to
    )

    chain.push({
      from,
      to,
      delegationId: delegation?.delegationId || 'unknown',
      scope: delegation?.scope || [],
      depth: i
    })
  }

  // The first key in the chain should map to a human beneficiary
  const principalKey = keyChain[0]
  const beneficiary = beneficiaryMap.get(principalKey)

  return {
    traceId: 'trace_' + uuidv4().slice(0, 12),
    receiptId: receipt.receiptId,
    executorAgent: receipt.agentId,
    beneficiary: beneficiary?.principalId || principalKey,
    chain,
    totalDepth: chain.length,
    verified: !!beneficiary && chain.every(h => h.delegationId !== 'unknown')
  }
}

// ══════════════════════════════════════
// ATTRIBUTION COMPUTATION
// ══════════════════════════════════════

/**
 * Weight factors for contribution scoring.
 * 
 * These weights determine how much each aspect of an action
 * contributes to the agent's attribution score. The weights
 * are designed to reward:
 *   - Higher-scope actions (more complex work)
 *   - Successful outcomes
 *   - Economic activity (spend)
 *   - Consistency (more receipts = more reliable)
 */
const SCOPE_WEIGHTS: Record<string, number> = {
  code_execution: 1.0,
  system_control: 0.9,
  web_search: 0.3,
  file_management: 0.5,
  git_operations: 0.7,
  email_management: 0.4,
  browser_automation: 0.5,
  data_analysis: 0.8,
  coordination: 0.6
}

const RESULT_MULTIPLIERS: Record<string, number> = {
  success: 1.0,
  partial: 0.5,
  failure: 0.0
}

/**
 * Compute attribution for a set of receipts.
 * 
 * Each receipt is weighted by:
 *   weight = scope_weight × result_multiplier × (1 + log(1 + spend))
 * 
 * The logarithmic spend factor prevents gaming by inflating spend.
 * Spending $10,000 doesn't give 100x more attribution than $100 —
 * it gives ~2.5x more. This is intentional: we want to reward
 * capability and outcome, not just capital deployment.
 */
export function computeAttribution(
  receipts: ActionReceipt[],
  agentId: string,
  beneficiary: string,
  privateKey: string
): AttributionReport {
  const agentReceipts = receipts.filter(r => r.agentId === agentId)

  const entries: AttributionEntry[] = agentReceipts.map(receipt => {
    const scopeWeight = SCOPE_WEIGHTS[receipt.action.scopeUsed] || 0.3
    const resultMult = RESULT_MULTIPLIERS[receipt.result.status] || 0
    const spend = receipt.action.spend?.amount || 0
    const spendFactor = 1 + Math.log(1 + spend)
    const weight = scopeWeight * resultMult * spendFactor

    return {
      receiptId: receipt.receiptId,
      agentId: receipt.agentId,
      action: receipt.action.type,
      scopeUsed: receipt.action.scopeUsed,
      spend,
      resultStatus: receipt.result.status,
      weight: Math.round(weight * 1000) / 1000,
      timestamp: receipt.timestamp
    }
  })

  const totalWeight = entries.reduce((sum, e) => sum + e.weight, 0)
  const timestamps = entries.map(e => e.timestamp).sort()

  // Generate Merkle root for all receipts
  const receiptHashes = agentReceipts.map(r => hashReceipt(r))
  const merkleRoot = buildMerkleRoot(receiptHashes)

  const report: Omit<AttributionReport, 'signature'> = {
    reportId: 'attr_' + uuidv4().slice(0, 12),
    beneficiary,
    agentId,
    period: {
      from: timestamps[0] || new Date().toISOString(),
      to: timestamps[timestamps.length - 1] || new Date().toISOString()
    },
    entries,
    totalWeight: Math.round(totalWeight * 1000) / 1000,
    receiptCount: agentReceipts.length,
    merkleRoot,
    generatedAt: new Date().toISOString()
  }

  const canonical = canonicalize(report)
  const signature = sign(canonical, privateKey)

  return { ...report, signature }
}

export function verifyAttributionReport(
  report: AttributionReport,
  publicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = report
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, publicKey)
  if (!sigValid) errors.push('Invalid attribution report signature')

  if (report.receiptCount !== report.entries.length) {
    errors.push(`Receipt count mismatch: ${report.receiptCount} vs ${report.entries.length} entries`)
  }

  // Verify total weight
  const expectedWeight = report.entries.reduce((sum, e) => sum + e.weight, 0)
  if (Math.abs(report.totalWeight - Math.round(expectedWeight * 1000) / 1000) > 0.001) {
    errors.push('Total weight does not match entry weights')
  }

  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// MERKLE TREE — O(log n) ATTRIBUTION PROOFS
// ══════════════════════════════════════

/**
 * A Merkle tree over action receipt hashes.
 * 
 * Why this matters:
 * An agent might produce 100,000 receipts over a year. To prove
 * attribution, you'd need to transmit all of them. With a Merkle
 * tree, you commit to ALL receipts with a single 32-byte root hash.
 * Then you can prove any individual receipt exists with ~17 hashes
 * (log2(100,000) ≈ 17). This is O(log n) verification for O(n) data.
 * 
 * The same structure Bitcoin uses to prove transactions exist in a
 * block. We use it to prove agent contributions exist in an
 * attribution period.
 * 
 * Properties:
 *   - Collision resistance: SHA-256 makes it infeasible to find two
 *     different receipt sets with the same root
 *   - Tamper evidence: changing any receipt changes the root
 *   - Inclusion proofs: prove one receipt without revealing others
 *   - Sorted leaves: receipts are sorted by hash for determinism
 */

/**
 * Build a Merkle root from an array of leaf hashes.
 * If the number of leaves is odd, the last leaf is duplicated.
 * Returns the root hash.
 */
export function buildMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) return sha256('empty')
  if (leafHashes.length === 1) return leafHashes[0]

  // Sort leaves for deterministic tree construction
  const sorted = [...leafHashes].sort()

  let level = sorted
  while (level.length > 1) {
    const nextLevel: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = i + 1 < level.length ? level[i + 1] : left // duplicate if odd
      nextLevel.push(sha256(left + right))
    }
    level = nextLevel
  }

  return level[0]
}

/**
 * Generate a Merkle proof for a specific receipt.
 * 
 * The proof is a path from the leaf to the root, containing
 * the sibling hashes at each level. A verifier can reconstruct
 * the root from the leaf hash and the proof, then compare
 * against the known root.
 * 
 * Proof size: O(log n) hashes — ~17 hashes for 100,000 receipts.
 */
export function generateMerkleProof(
  leafHashes: string[],
  targetHash: string
): MerkleProof | null {
  if (leafHashes.length === 0) return null

  const sorted = [...leafHashes].sort()
  const targetIndex = sorted.indexOf(targetHash)
  if (targetIndex === -1) return null

  const proof: MerkleProofNode[] = []
  let level = sorted
  let index = targetIndex

  while (level.length > 1) {
    const nextLevel: string[] = []
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1

    if (siblingIndex < level.length && siblingIndex !== index) {
      proof.push({
        hash: level[siblingIndex],
        position: index % 2 === 0 ? 'right' : 'left'
      })
    } else {
      // Duplicate case (odd number of nodes, last node paired with itself)
      proof.push({
        hash: level[index],
        position: 'right'
      })
    }

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = i + 1 < level.length ? level[i + 1] : left
      nextLevel.push(sha256(left + right))
    }

    level = nextLevel
    index = Math.floor(index / 2)
  }

  return {
    receiptHash: targetHash,
    root: level[0],
    proof,
    index: targetIndex
  }
}

/**
 * Verify a Merkle proof — confirm a receipt hash is committed
 * to by the given Merkle root.
 * 
 * This is the verification that a third party performs:
 *   1. Start with the receipt hash
 *   2. Combine with each proof node (respecting position)
 *   3. Compare final hash against the claimed root
 * 
 * If they match, the receipt is provably part of the committed set.
 * No other information about the set is revealed.
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  let currentHash = proof.receiptHash

  for (const node of proof.proof) {
    if (node.position === 'left') {
      currentHash = sha256(node.hash + currentHash)
    } else {
      currentHash = sha256(currentHash + node.hash)
    }
  }

  return currentHash === proof.root
}

// ══════════════════════════════════════
// MULTI-AGENT ATTRIBUTION AGGREGATION
// ══════════════════════════════════════

/**
 * When multiple agents collaborate on a task, compute relative
 * attribution across all participants.
 * 
 * Returns a map of agentId -> percentage of total contribution.
 * This is the primitive that payment systems consume:
 *   "Agent A did 40% of the work, Agent B did 35%, Agent C did 25%"
 * 
 * Each percentage is backed by signed receipts with Merkle proofs.
 */
export interface CollaborationAttribution {
  collaborationId: string
  participants: {
    agentId: string
    beneficiary: string
    weight: number
    percentage: number
    receiptCount: number
  }[]
  totalWeight: number
  merkleRoot: string           // Merkle root over ALL participants' receipts
  generatedAt: string
}

export function computeCollaborationAttribution(
  allReceipts: ActionReceipt[],
  beneficiaryMap: Map<string, string>  // agentId -> beneficiary
): CollaborationAttribution {
  // Group receipts by agent
  const byAgent = new Map<string, ActionReceipt[]>()
  for (const receipt of allReceipts) {
    const existing = byAgent.get(receipt.agentId) || []
    existing.push(receipt)
    byAgent.set(receipt.agentId, existing)
  }

  // Compute weight for each agent
  const participants: CollaborationAttribution['participants'] = []
  let totalWeight = 0

  for (const [agentId, receipts] of byAgent) {
    const agentWeight = receipts.reduce((sum, r) => {
      const scopeWeight = SCOPE_WEIGHTS[r.action.scopeUsed] || 0.3
      const resultMult = RESULT_MULTIPLIERS[r.result.status] || 0
      const spend = r.action.spend?.amount || 0
      return sum + scopeWeight * resultMult * (1 + Math.log(1 + spend))
    }, 0)

    totalWeight += agentWeight
    participants.push({
      agentId,
      beneficiary: beneficiaryMap.get(agentId) || 'unknown',
      weight: Math.round(agentWeight * 1000) / 1000,
      percentage: 0, // computed after totaling
      receiptCount: receipts.length
    })
  }

  // Compute percentages
  for (const p of participants) {
    p.percentage = totalWeight > 0
      ? Math.round((p.weight / totalWeight) * 10000) / 100
      : 0
  }

  // Sort by percentage descending
  participants.sort((a, b) => b.percentage - a.percentage)

  // Merkle root over all receipts
  const allHashes = allReceipts.map(r => hashReceipt(r))
  const merkleRoot = buildMerkleRoot(allHashes)

  return {
    collaborationId: 'collab_' + uuidv4().slice(0, 12),
    participants,
    totalWeight: Math.round(totalWeight * 1000) / 1000,
    merkleRoot,
    generatedAt: new Date().toISOString()
  }
}
