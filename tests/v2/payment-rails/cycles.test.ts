// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  mapCyclesDenialToFoundation,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  signCyclesDenial,
  signCyclesPermitReceipt,
  signCyclesReleaseReceipt,
  verifyCyclesDenial,
  verifyCyclesPermitReceipt,
  verifyCyclesReleaseReceipt,
} from '../../../src/v2/payment-rails/cycles/index.js'
import type {
  CyclesEvidenceRef,
  CyclesEvidenceView,
} from '../../../src/v2/payment-rails/cycles/types.js'

// ── Test helpers ──────────────────────────────────────────────────

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), 'cycles-fixtures')

function loadFixture(filename: string): CyclesEvidenceView {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, filename), 'utf-8'))
}

function evidenceRef(): CyclesEvidenceRef {
  return {
    cycles_evidence_url: 'https://cycles.example.com/v1/evidence/abc',
    cycles_evidence_id_sha256: 'a'.repeat(64),
    action_ref: 'aps:action:cycles-test-001',
    delegation_ref: 'aps:delegation:cycles-test-001',
  }
}

// ── mapCyclesDenialToFoundation: 3 golden fixtures ────────────────

test('mapCyclesDenialToFoundation: 03-reserve-dry-run-deny → spend_limit_exceeded / DecisionReasonCode / BUDGET_EXCEEDED', () => {
  const env = loadFixture('03-reserve-dry-run-deny.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r, 'mapping should return non-null')
  assert.equal(r.denial_reason, 'spend_limit_exceeded')
  assert.equal(r.cycles.denial_detail.source, 'DecisionReasonCode')
  assert.equal(r.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
})

test('mapCyclesDenialToFoundation: 11-reserve-live-budget-exceeded → spend_limit_exceeded / ErrorCode / BUDGET_EXCEEDED', () => {
  const env = loadFixture('11-reserve-live-budget-exceeded.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'spend_limit_exceeded')
  assert.equal(r.cycles.denial_detail.source, 'ErrorCode')
  assert.equal(r.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
  assert.equal(r.cycles.denial_detail.http_status, 409)
})

test('mapCyclesDenialToFoundation: 12-decide-live-forbidden → no_commerce_scope / ErrorCode / FORBIDDEN', () => {
  const env = loadFixture('12-decide-live-forbidden.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'no_commerce_scope')
  assert.equal(r.cycles.denial_detail.source, 'ErrorCode')
  assert.equal(r.cycles.denial_detail.code, 'FORBIDDEN')
  assert.equal(r.cycles.denial_detail.http_status, 403)
})

test('mapCyclesDenialToFoundation: unknown ErrorCode → rail_error fallback', () => {
  const env: CyclesEvidenceView = {
    artifact_type: 'error',
    payload: {
      error: {
        endpoint: 'POST /v1/reservations',
        http_status: 500,
        response: {
          error: 'FUTURE_UNKNOWN_CODE',
          message: 'something new',
          request_id: 'req_x',
        },
      },
    },
  }
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'rail_error')
  assert.equal(r.cycles.denial_detail.code, 'FUTURE_UNKNOWN_CODE')
})

// ── Permit receipt sign/verify round-trip ─────────────────────────

test('signCyclesPermitReceipt + verifyCyclesPermitReceipt: happy-path round-trip', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_01HZZ8N4F8FBQX5K6TGYR0M0A3',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      expires_at_ms: 1810000030100,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(receipt.claim_type, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE)
  assert.equal(receipt.rail_name, 'cycles')
  assert.equal(receipt.decision, 'ALLOW')
  assert.match(receipt.receipt_id, /^cycles_permit_/)
  assert.equal(receipt.signature.length, 128)
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('verifyCyclesPermitReceipt: tampered reservation_id → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_original',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = { ...receipt, reservation_id: 'rsv_tampered' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

test('verifyCyclesPermitReceipt: missing cycles_evidence → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Strip the join shape and re-verify (this also corrupts signature
  // but we check the missing-field path runs before signature verify).
  const broken = {
    ...receipt,
    cycles_evidence: { ...receipt.cycles_evidence, cycles_evidence_id_sha256: '' },
  }
  const result = verifyCyclesPermitReceipt(broken)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

test('verifyCyclesPermitReceipt: wrong claim_type → INVALID_CLAIM_TYPE', () => {
  const { privateKey } = generateKeyPair()
  const release = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      released: { unit: 'TOKENS', amount: 8000 },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Feed a release receipt to the permit verifier.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = verifyCyclesPermitReceipt(release as any)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'INVALID_CLAIM_TYPE')
})

// ── Release receipt sign/verify round-trip ────────────────────────

test('signCyclesReleaseReceipt + verifyCyclesReleaseReceipt: happy-path round-trip with reason', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_release_001',
      released: { unit: 'USD_MICROCENTS', amount: 500000 },
      reason: 'handler_timeout',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(receipt.claim_type, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE)
  assert.equal(receipt.reason, 'handler_timeout')
  assert.match(receipt.receipt_id, /^cycles_release_/)
  assert.deepEqual(verifyCyclesReleaseReceipt(receipt), { valid: true })
})

test('verifyCyclesReleaseReceipt: tampered released amount → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_release_001',
      released: { unit: 'USD_MICROCENTS', amount: 500000 },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...receipt,
    released: { ...receipt.released, amount: 999999999 },
  }
  const result = verifyCyclesReleaseReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── Denial sign/verify round-trip ─────────────────────────────────

test('signCyclesDenial + verifyCyclesDenial: ErrorCode-sourced denial round-trip', () => {
  const { privateKey } = generateKeyPair()
  const env = loadFixture('11-reserve-live-budget-exceeded.json')
  const mapped = mapCyclesDenialToFoundation(env)
  assert.ok(mapped, 'mapping must succeed')
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapped.denial_reason,
      cycles: mapped.cycles,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(denial.claim_type, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE)
  assert.equal(denial.denial_reason, 'spend_limit_exceeded')
  assert.equal(denial.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
  assert.equal(denial.cycles.denial_detail.source, 'ErrorCode')
  assert.match(denial.receipt_id, /^cycles_denial_/)
  assert.deepEqual(verifyCyclesDenial(denial), { valid: true })
})

test('signCyclesDenial + verifyCyclesDenial: DecisionReasonCode-sourced denial round-trip (dry-run)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadFixture('03-reserve-dry-run-deny.json')
  const mapped = mapCyclesDenialToFoundation(env)
  assert.ok(mapped)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapped.denial_reason,
      cycles: mapped.cycles,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(denial.denial_reason, 'spend_limit_exceeded')
  assert.equal(denial.cycles.denial_detail.source, 'DecisionReasonCode')
  assert.deepEqual(verifyCyclesDenial(denial), { valid: true })
})

test('verifyCyclesDenial: tampered cycles.denial_detail.code → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: 'spend_limit_exceeded',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code: 'BUDGET_EXCEEDED',
          http_status: 409,
        },
      },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...denial,
    cycles: {
      denial_detail: {
        ...denial.cycles.denial_detail,
        code: 'TAMPERED',
      },
    },
  }
  const result = verifyCyclesDenial(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── Signer-mismatch + expected_signer option ──────────────────────

test('verifyCyclesPermitReceipt: expected_signer mismatch → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, {
    expected_signer: 'f'.repeat(64),
  })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── TTL / EXPIRED ─────────────────────────────────────────────────

test('verifyCyclesPermitReceipt: past-TTL → EXPIRED', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const future = new Date(Date.parse(receipt.issued_at) + 48 * 60 * 60 * 1000)
  const result = verifyCyclesPermitReceipt(receipt, { now: future, ttl_seconds: 24 * 60 * 60 })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EXPIRED')
})

// ── rail_name invariant ───────────────────────────────────────────

test('verifyCyclesPermitReceipt: tampered rail_name → SIGNATURE_INVALID (signature catches it)', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Cast to assign a non-literal rail_name for testing the structural check.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tampered: any = { ...receipt, rail_name: 'cycles_v2' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'INVALID_RAIL_NAME')
})

// ── Accountability-shape invariants ───────────────────────────────

test('verifyCyclesPermitReceipt: timestamp != issued_at → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = { ...receipt, timestamp: '2020-01-01T00:00:00.000Z' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

test('verifyCyclesPermitReceipt: empty scope_of_claim.asserts → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...receipt,
    scope_of_claim: { ...receipt.scope_of_claim!, asserts: '' },
  }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

// ── DID URI signers ───────────────────────────────────────────────

test('verifyCyclesPermitReceipt (sync): DID URI signer → DID_RESOLVER_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      issuer_agent_id: 'did:cycles:example',
      issuer_key_ref: 'key-1',
    },
    privateKey,
  )
  assert.equal(receipt.signer, 'did:cycles:example#key-1')
  const result = verifyCyclesPermitReceipt(receipt)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'DID_RESOLVER_MISSING')
})
