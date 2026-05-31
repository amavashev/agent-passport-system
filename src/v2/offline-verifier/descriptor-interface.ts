// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// W2-A1 Evidence Descriptor interface - consumed, not owned
// ══════════════════════════════════════════════════════════════════
// The Evidence Descriptor is owned by the W2-A1 module
// (src/v2/assurance/descriptor.ts). At the time this offline verifier
// was authored, W2-A1 lived on a sibling branch not yet merged into this
// one. To wire against its interface without duplicating its logic, this
// file declares ONLY the structural type contract the offline verifier
// produces and consumes:
//
//   - BuildDescriptorInput  : what the verifier hands the A1 builder.
//   - EvidenceDescriptor    : what the A1 builder returns.
//   - DescriptorBuilder     : the builder function shape.
//
// These mirror the exported shapes of src/v2/assurance/descriptor.ts
// field for field. At merge, delete the interim builder in
// ./descriptor.ts and point it at A1's buildEvidenceDescriptor; nothing
// in the offline verifier's call site changes, because it is typed
// against this contract, not against any concrete builder.
//
// THE ABSOLUTE RULE this contract preserves: assurance is a
// verifier-derived OUTPUT, never an issuer-set INPUT. No field below is
// read from a receipt body as a grade. Every field is a mechanical fact
// the verifier recomputes from the receipt, the signatures it already
// checked, the witness attestations, and the key/DID graph. The lattice
// point is the four-valued Belnap ConstraintStatus, never a scalar ladder.
// ══════════════════════════════════════════════════════════════════

import type {
  ConstraintStatus,
  WitnessObservationBasis,
  WitnessConflict,
} from '../../types/gateway.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'

/** A pairwise signer-independence relation, derived from the key/DID
 *  graph via the sharesRoot relation. Mirrors A1 IndependenceRelation. */
export interface IndependenceRelation {
  signerA: string
  signerB: string
  /** True iff the two signers chain to NO common root. */
  independent: boolean
  /** Roots both signers chain to, sorted. Empty iff independent. */
  sharedRoots: string[]
}

/** One signer as a node in the key/DID graph. Mirrors A1 SignerNode. */
export interface SignerNode {
  id: string
  chainsTo?: string[]
  role?: string
}

/** The signer graph the verifier assembles before computing
 *  independence. Mirrors A1 SignerGraph. */
export interface SignerGraph {
  nodes: SignerNode[]
  anchorEdges?: Array<[string, string]>
}

/** One mechanical fact: signer `signerId` produced a signature over
 *  `claim` and the verifier checked it. Mirrors A1 SignerClaim. */
export interface SignerClaim {
  signerId: string
  role?: string
  claim: string
  /** Cryptographic result. `null` = signer expected but no signature present. */
  signatureValid: boolean | null
}

/** One witness's mechanical observation facts. Mirrors A1
 *  WitnessObservationFact. observationBasis reuses the existing
 *  five-valued WitnessObservationBasis enum verbatim. */
export interface WitnessObservationFact {
  witnessId: string
  observationBasis: WitnessObservationBasis
  /** predictionError.divergence (0..1) if the witness reported one. */
  divergence?: number
}

/** A pre-checked signature fact handed to the descriptor builder. The
 *  builder does NOT re-run crypto; it consumes verification results the
 *  caller already produced. `valid: null` = signer expected, no
 *  signature present. Mirrors A1 CheckedSignature. */
export interface CheckedSignature {
  signerId: string
  role?: string
  claim: string
  valid: boolean | null
  /** Anchors this signer chains to (issuer DID, gateway root, JWKS
   *  origin, trust-anchor fingerprint). Feeds the independence graph. */
  chainsTo?: string[]
}

/** Input to the W2-A1 descriptor builder. Mirrors A1 BuildDescriptorInput. */
export interface BuildDescriptorInput {
  receiptId: string
  signatures: CheckedSignature[]
  witnessObservations?: WitnessObservationFact[]
  witnessConflicts?: WitnessConflict[]
  /** Anchor equivalences for the independence graph (verifier-supplied). */
  anchorEdges?: Array<[string, string]>
}

/** The verifier OUTPUT over one receipt's evidence. Mirrors A1
 *  EvidenceDescriptor field for field. */
export interface EvidenceDescriptor {
  version: 'aps:evidence-descriptor:v1'
  receiptId: string
  signerClaims: SignerClaim[]
  signerSet: string[]
  witnessObservations: WitnessObservationFact[]
  hasWitnessConflict: boolean
  witnessConflictIds: string[]
  allSignaturesValid: boolean
  validSignatureCount: number
  absentSignerCount: number
  independenceRelations: IndependenceRelation[]
  independentSignerCount: number
  fullyIndependent: boolean
  /** Four-valued Belnap corroboration status. NOT a scalar ladder. */
  corroborationStatus: ConstraintStatus
  scope_of_claim: ScopeOfClaim
}

/** The builder function shape. The offline verifier is typed against
 *  this, so the concrete builder (interim here, A1's at merge) is a
 *  drop-in. */
export type DescriptorBuilder = (input: BuildDescriptorInput) => EvidenceDescriptor
