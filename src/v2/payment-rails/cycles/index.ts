// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cycles — APS V2 ↔ Cycles reserve/commit/release budget-authority rail
// ══════════════════════════════════════════════════════════════════
// Public functions:
//   mapCyclesDenialToFoundation(evidence)         → FoundationDenialMapping | null
//
//   [TODO — staged on this branch, not yet implemented]
//   signCyclesPermitReceipt(input, privateKeyHex) → CyclesPermitReceipt
//   verifyCyclesPermitReceipt(receipt, options)   → CyclesVerifyResult
//   signCyclesReleaseReceipt(input, privateKeyHex) → CyclesReleaseReceipt
//   verifyCyclesReleaseReceipt(receipt, options)  → CyclesVerifyResult
//   signCyclesDenial(input, privateKeyHex)        → CyclesDenial
//   verifyCyclesDenial(denial, options)           → CyclesVerifyResult
//
// Denial mapping (well-specified; this commit lands the const tables):
//   - ErrorCode → APS Tier-1: 15 v0.1.25 base values
//     (canonical L429-L446 of cycles-protocol-v0.yaml)
//   - DecisionReasonCode → APS Tier-1: 6 v0.1.25 base values
//     (canonical L487-L545)
//   Unknown DecisionReasonCode values gracefully degrade to rail_error
//   per canonical L503-L505; raw code preserved Tier-2 byte-for-byte.
//   v0.1.26 extension codes (ACTION_QUOTA_EXCEEDED / ACTION_KIND_DENIED
//   / ACTION_KIND_NOT_ALLOWED) and the DenyDetail structure are OUT
//   OF SCOPE for v0.1 — see mapping doc's "v0.2 promotion criterion"
//   section at runcycles/cycles-protocol/drafts/
//   cycles-aps-denial-mapping-v0.1.md (merged commit 9b0fb5e).
//
// Spec refs:
//   - runcycles/cycles-protocol drafts/cycles-evidence-v0.1.yaml
//     (merged commit 61186a2) — signed envelope this adapter consumes
//   - runcycles/cycles-protocol drafts/cycles-aps-denial-mapping-v0.1.md
//     (merged commit 9b0fb5e) — the contract this adapter implements
//   - aeoess/agent-governance-vocabulary crosswalk/cycles.yaml (#92,
//     merged commit 3ccc17f) — Cycles signal-type crosswalk
//   - aeoess/agent-governance-vocabulary crosswalk/budget_reservation.yaml
//     (#91, merged commit 161b1d4) — verb-layer crosswalk
//   - aeoess/agent-passport-system#27 (merged commit 4abd9df) — SDK PR
//     adding the three rail.budget_reservation.*.v1 claim_type literals
//     this adapter emits.
// ══════════════════════════════════════════════════════════════════

import type { DenialReason as FoundationDenialReason } from '../types.js'
import {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
} from './types.js'
export {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
} from './types.js'
import type {
  CyclesDenialDetail,
  CyclesEvidenceView,
} from './types.js'

// ── Denial mapping: Cycles ErrorCode → APS Tier-1 ─────────────────
// 15 v0.1.25 base values. Canonical refs in each row's compression
// note in the merged spec. v0.1.26 extension codes are OUT OF SCOPE
// for v0.1 — see file header.

const ERROR_CODE_TO_TIER1: Record<string, FoundationDenialReason> = {
  INVALID_REQUEST:          'rail_error',
  UNAUTHORIZED:             'rail_error',
  FORBIDDEN:                'no_commerce_scope',
  NOT_FOUND:                'rail_error',
  BUDGET_EXCEEDED:          'spend_limit_exceeded',
  BUDGET_FROZEN:            'wallet_revoked',
  BUDGET_CLOSED:            'wallet_revoked',
  RESERVATION_EXPIRED:      'time_window_violation',
  RESERVATION_FINALIZED:    'rail_error',
  IDEMPOTENCY_MISMATCH:     'rail_error',
  UNIT_MISMATCH:            'rail_error',
  OVERDRAFT_LIMIT_EXCEEDED: 'spend_limit_exceeded',
  DEBT_OUTSTANDING:         'wallet_revoked',
  MAX_EXTENSIONS_EXCEEDED:  'time_window_violation',
  INTERNAL_ERROR:           'rail_error',
}

// ── Denial mapping: Cycles DecisionReasonCode → APS Tier-1 ────────
// 6 known v0.1.25 base values. The enum is OPEN per canonical L487 —
// unknown values gracefully degrade to rail_error per L503-L505.

const DECISION_REASON_TO_TIER1: Record<string, FoundationDenialReason> = {
  BUDGET_EXCEEDED:          'spend_limit_exceeded',
  BUDGET_FROZEN:            'wallet_revoked',
  BUDGET_CLOSED:            'wallet_revoked',
  BUDGET_NOT_FOUND:         'rail_error',
  OVERDRAFT_LIMIT_EXCEEDED: 'spend_limit_exceeded',
  DEBT_OUTSTANDING:         'wallet_revoked',
}

// ── mapCyclesDenialToFoundation ───────────────────────────────────

/**
 * The contract from the merged denial-mapping spec (runcycles/
 * cycles-protocol#93, commit 9b0fb5e).
 *
 * Maps a Cycles denial signal (extracted from a CyclesEvidence view)
 * to an APS Tier-1 denial reason, preserving the full Cycles-side
 * detail Tier-2 in `cycles.denial_detail`.
 *
 * Returns `null` if the evidence view does not represent a denial
 * (artifact_type=decide-ALLOW, reserve-ALLOW, commit, release).
 * Callers MUST NOT invoke this on permit-class evidence.
 *
 * Denial paths:
 *   (A) HTTP 4xx/5xx — artifact_type=error. ErrorCode source.
 *   (B) /v1/decide DENY — artifact_type=decide. DecisionReasonCode source.
 *   (C) dry_run=true reserve DENY — artifact_type=reserve.
 *       DecisionReasonCode source. (Non-dry reserve DENY is a wire-
 *       shape impossibility per cycles-protocol-v0.yaml:978 and is
 *       rejected at the CyclesEvidence schema layer.)
 */
export function mapCyclesDenialToFoundation(
  evidence: CyclesEvidenceView,
): { denial_reason: FoundationDenialReason; cycles: { denial_detail: CyclesDenialDetail } } | null {
  const p = evidence.payload

  if ('error' in p) {
    const e = p.error
    const code = e.response.error
    return {
      denial_reason: ERROR_CODE_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code,
          http_status: e.http_status,
          message: e.response.message,
          request_id: e.response.request_id,
          trace_id: e.response.trace_id ?? evidence.trace_id,
        },
      },
    }
  }

  if ('decide' in p && p.decide.response.decision === 'DENY') {
    const code = p.decide.response.reason_code ?? 'UNKNOWN'
    return {
      denial_reason: DECISION_REASON_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'DecisionReasonCode',
          code,
          trace_id: evidence.trace_id,
        },
      },
    }
  }

  if ('reserve' in p && p.reserve.response.decision === 'DENY') {
    const code = p.reserve.response.reason_code ?? 'UNKNOWN'
    return {
      denial_reason: DECISION_REASON_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'DecisionReasonCode',
          code,
          trace_id: evidence.trace_id,
        },
      },
    }
  }

  return null
}

// ── Signed receipt + denial emission ──────────────────────────────
// TODO: implement signCyclesPermitReceipt, signCyclesReleaseReceipt,
// signCyclesDenial. Each mirrors the mpp pattern (sign over JCS-canon
// receipt body with signature cleared, Ed25519, hex output) but emits
// the rail.budget_reservation.*.v1 claim_type literals merged in
// aeoess/agent-passport-system#27.
//
// Two-receipt emission model per issue #25 Q2(ii): permit at reserve,
// release at release, denial on the dry-run-DENY / live-4xx / decide-
// DENY paths.

// ── Signed receipt + denial verification ──────────────────────────
// TODO: implement verifyCyclesPermitReceipt, verifyCyclesReleaseReceipt,
// verifyCyclesDenial. Each verifies:
//   1. claim_type is the expected rail.budget_reservation.*.v1 literal
//   2. receipt_id is sha256 of JCS-canon body with signature cleared
//   3. Ed25519 signature over the canon body
//   4. CyclesEvidenceRef.cycles_evidence_id_sha256 matches the fetched
//      CyclesEvidence envelope (verify join integrity per CyclesEvidence
//      v0.1 spec) — this is the load-bearing offline-audit guarantee.
