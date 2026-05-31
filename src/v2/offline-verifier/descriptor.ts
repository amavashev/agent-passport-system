// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Interim descriptor builder - standalone until W2-A1 merges
// ══════════════════════════════════════════════════════════════════
// The canonical Evidence Descriptor builder is owned by W2-A1
// (src/v2/assurance/descriptor.ts: buildEvidenceDescriptor). At authoring
// time A1 lived on a sibling branch not yet merged into this one, so this
// file ships an INTERIM builder that produces the identical
// EvidenceDescriptor shape from the same mechanical-fact logic A1 uses
// (signer set, sharesRoot independence over the key/DID graph, four-valued
// Belnap corroboration status).
//
// AT MERGE: delete this file's builder body and re-export A1's
// buildEvidenceDescriptor as `buildDescriptor`. The offline verifier is
// typed against the DescriptorBuilder contract in ./descriptor-interface,
// so its call site does not change. The composition note in the module's
// build report records this swap.
//
// ABSOLUTE RULE preserved: assurance is a verifier-derived OUTPUT. No
// field below is read from a receipt body as a grade. Independence is the
// sharp metric and is computed from the key/DID graph; the lattice point
// is the Belnap ConstraintStatus, never a scalar ladder.
// ══════════════════════════════════════════════════════════════════

import type { ConstraintStatus } from '../../types/gateway.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
import type {
  BuildDescriptorInput,
  EvidenceDescriptor,
  IndependenceRelation,
  SignerClaim,
  SignerGraph,
  SignerNode,
  WitnessObservationFact,
} from './descriptor-interface.js'

// ── sharesRoot: signer independence from the key/DID graph ──────────
// Reproduces A1 src/v2/assurance/shares-root.ts. Two signers share a
// root when their anchor closures intersect. Reflexive, symmetric, NOT
// transitive across signers. Reads only id/chainsTo, never an issuer field.

function buildAnchorUnion(anchorEdges?: Array<[string, string]>): (a: string) => string {
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    let root = x
    while (parent.has(root) && parent.get(root) !== root) {
      root = parent.get(root)!
    }
    let cur = x
    while (parent.has(cur) && parent.get(cur) !== root) {
      const next = parent.get(cur)!
      parent.set(cur, root)
      cur = next
    }
    return root
  }
  const union = (a: string, b: string): void => {
    if (!parent.has(a)) parent.set(a, a)
    if (!parent.has(b)) parent.set(b, b)
    const ra = find(a)
    const rb = find(b)
    if (ra !== rb) {
      if (ra < rb) parent.set(rb, ra)
      else parent.set(ra, rb)
    }
  }
  for (const [a, b] of anchorEdges ?? []) union(a, b)
  return (a: string): string => (parent.has(a) ? find(a) : a)
}

function anchorClosure(node: SignerNode, canonical: (a: string) => string): Set<string> {
  const anchors = node.chainsTo && node.chainsTo.length > 0 ? node.chainsTo : [node.id]
  const out = new Set<string>()
  for (const a of anchors) out.add(canonical(a))
  return out
}

function sharesRoot(
  a: SignerNode,
  b: SignerNode,
  graph?: Pick<SignerGraph, 'anchorEdges'>,
): IndependenceRelation {
  const canonical = buildAnchorUnion(graph?.anchorEdges)
  const closureA = anchorClosure(a, canonical)
  const closureB = anchorClosure(b, canonical)
  const shared: string[] = []
  for (const anchor of closureA) {
    if (closureB.has(anchor)) shared.push(anchor)
  }
  shared.sort()
  return {
    signerA: a.id,
    signerB: b.id,
    independent: shared.length === 0,
    sharedRoots: shared,
  }
}

function allPairwiseIndependence(graph: SignerGraph): IndependenceRelation[] {
  const seen = new Map<string, SignerNode>()
  for (const node of graph.nodes) {
    if (!seen.has(node.id)) seen.set(node.id, node)
  }
  const nodes = [...seen.values()].sort((x, y) =>
    x.id < y.id ? -1 : x.id > y.id ? 1 : 0,
  )
  const relations: IndependenceRelation[] = []
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      relations.push(sharesRoot(nodes[i], nodes[j], graph))
    }
  }
  return relations
}

function independentSignerCount(graph: SignerGraph): number {
  const seen = new Map<string, SignerNode>()
  for (const node of graph.nodes) {
    if (!seen.has(node.id)) seen.set(node.id, node)
  }
  const nodes = [...seen.values()]
  if (nodes.length <= 1) return nodes.length
  let count = 0
  for (let i = 0; i < nodes.length; i++) {
    let independentOfAll = true
    for (let j = 0; j < nodes.length; j++) {
      if (i === j) continue
      if (!sharesRoot(nodes[i], nodes[j], graph).independent) {
        independentOfAll = false
        break
      }
    }
    if (independentOfAll) count++
  }
  return count
}

// ── Four-valued Belnap corroboration status (lattice, not ladder) ───

function deriveCorroborationStatus(facts: {
  presentSignatureFailures: number
  hasWitnessConflict: boolean
  signerCount: number
  witnessCount: number
  independentSigners: number
}): ConstraintStatus {
  if (facts.presentSignatureFailures > 0 || facts.hasWitnessConflict) return 'fail'
  if (facts.signerCount <= 1 && facts.witnessCount === 0) return 'not_applicable'
  if (facts.independentSigners >= 2) return 'pass'
  return 'unknown'
}

// ── The interim builder ─────────────────────────────────────────────

/**
 * Build the Evidence Descriptor from pre-checked mechanical facts. Pure:
 * identical input yields an identical descriptor. Reads no issuer field;
 * every input is a cryptographic result the caller already computed or a
 * fact from the key/DID graph.
 *
 * Field-for-field equivalent to W2-A1 buildEvidenceDescriptor. Swapped for
 * A1's builder at merge with no change to the offline verifier call site.
 */
export function buildDescriptor(input: BuildDescriptorInput): EvidenceDescriptor {
  const signerClaims: SignerClaim[] = input.signatures.map((s) => ({
    signerId: s.signerId,
    role: s.role,
    claim: s.claim,
    signatureValid: s.valid,
  }))

  const signerSet = [...new Set(input.signatures.map((s) => s.signerId))].sort()

  let validSignatureCount = 0
  let absentSignerCount = 0
  let presentSignatureFailures = 0
  for (const s of input.signatures) {
    if (s.valid === null) absentSignerCount++
    else if (s.valid === true) validSignatureCount++
    else presentSignatureFailures++
  }
  const allSignaturesValid = presentSignatureFailures === 0 && absentSignerCount === 0

  const conflicts = input.witnessConflicts ?? []
  const witnessConflictIds = [...new Set(conflicts.map((c) => c.conflictId))].sort()
  const hasWitnessConflict = witnessConflictIds.length > 0

  const witnessObservations: WitnessObservationFact[] = (input.witnessObservations ?? [])
    .slice()
    .sort((a, b) => (a.witnessId < b.witnessId ? -1 : a.witnessId > b.witnessId ? 1 : 0))

  const nodeById = new Map<string, SignerNode>()
  for (const s of input.signatures) {
    if (!nodeById.has(s.signerId)) {
      nodeById.set(s.signerId, { id: s.signerId, chainsTo: s.chainsTo, role: s.role })
    }
  }
  const graph: SignerGraph = {
    nodes: [...nodeById.values()],
    anchorEdges: input.anchorEdges,
  }
  const independenceRelations = allPairwiseIndependence(graph)
  const indepCount = independentSignerCount(graph)
  const fullyIndependent =
    signerSet.length >= 2 && independenceRelations.every((r) => r.independent)

  const corroborationStatus = deriveCorroborationStatus({
    presentSignatureFailures,
    hasWitnessConflict,
    signerCount: signerSet.length,
    witnessCount: witnessObservations.length,
    independentSigners: indepCount,
  })

  const scope_of_claim: ScopeOfClaim = {
    asserts:
      'Reports the mechanical evidence on one receipt: which signers signed which claim and whether each signature verified, each witness observation basis, presence of any witness conflict, and signer independence derived from the key and DID graph.',
    does_not_assert: [
      'That any external effect described by the receipt actually occurred.',
      'That the underlying outcome is true; signature validity is not outcome truth.',
      'Any issuer-set assurance level; no such field is read.',
      'That independent signers cannot still be coordinated off-graph.',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'best_effort',
    self_attested: indepCount < 2,
  }

  return {
    version: 'aps:evidence-descriptor:v1',
    receiptId: input.receiptId,
    signerClaims,
    signerSet,
    witnessObservations,
    hasWitnessConflict,
    witnessConflictIds,
    allSignaturesValid,
    validSignatureCount,
    absentSignerCount,
    independenceRelations,
    independentSignerCount: indepCount,
    fullyIndependent,
    corroborationStatus,
    scope_of_claim,
  }
}
