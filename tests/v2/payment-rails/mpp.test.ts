// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license.
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  apsToMppHttpError,
  delegationToMppAllowed,
  MPP_VERSION,
  preAuthorizeMppPayment,
  signMppDenial,
  signMppReceipt,
  verifyMppDenial,
  verifyMppReceipt,
} from '../../../src/v2/payment-rails/mpp/index.js'
import type {
  MppDenialReason,
  MppMethod,
  MppPaymentChallenge,
} from '../../../src/v2/payment-rails/mpp/types.js'
import type { V2Delegation } from '../../../src/v2/types.js'

// ── Test helpers ──────────────────────────────────────────────────

function paymentDelegation(overrides: Partial<{
  spend_limit_cents: number
  allowed_payment_methods: string
  allowed_currencies: string
  valid_until: string
  action_categories: string[]
}> = {}): V2Delegation {
  const validUntil =
    overrides.valid_until ?? new Date(Date.now() + 60 * 60 * 1000).toISOString()
  const validFrom = new Date(Date.now() - 60 * 1000).toISOString()
  return {
    id: 'del_mpp_test_001',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'agent-001',
    delegatee: 'agent-002',
    scope: {
      action_categories: overrides.action_categories ?? ['payment'],
      resource_limits: {
        spend_limit_cents: overrides.spend_limit_cents ?? 5000,
      },
      constraints: {
        allowed_payment_methods: overrides.allowed_payment_methods ?? 'tempo,card',
        allowed_currencies: overrides.allowed_currencies ?? 'usd,btc',
      },
    },
    policy_context: {
      policy_version: '2.0.0',
      values_floor_version: '1.0.0',
      trust_epoch: 1,
      issuer_id: 'agent-001',
      created_at: validFrom,
      valid_from: validFrom,
      valid_until: validUntil,
    },
    signature: 'stub_signature_for_test',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable',
  }
}

function tempoMethod(overrides: Partial<{
  recipient_address: string
  currency: string
  network: 'mainnet' | 'testnet'
  max_amount: string
}> = {}): MppMethod {
  return {
    method_type: 'tempo',
    recipient_address: overrides.recipient_address ?? '0xabc1230000000000000000000000000000000001',
    currency: overrides.currency ?? 'usd',
    network: overrides.network ?? 'mainnet',
    max_amount: overrides.max_amount,
  }
}

function cardMethod(overrides: Partial<{
  amount_minor_units: number
  currency: string
  brands: string[]
}> = {}): MppMethod {
  return {
    method_type: 'card',
    acceptance_url: 'https://acceptance.mpp.dev/v1/auth',
    supported_brands: overrides.brands ?? ['visa', 'mastercard'],
    amount_minor_units: overrides.amount_minor_units ?? 1500,
    currency: overrides.currency ?? 'usd',
  }
}

function lightningMethod(amount_msat = 1_000_000): MppMethod {
  return {
    method_type: 'lightning',
    bolt11_invoice: 'lnbc10u1p3xyz...',
    amount_msat,
  }
}

function happyChallenge(overrides: Partial<MppPaymentChallenge> = {}): MppPaymentChallenge {
  return {
    challenge_id: 'mpc_test_001',
    methods: [tempoMethod(), cardMethod()],
    required_amount: '1500',
    currency: 'usd',
    resource: 'https://api.example.com/v1/widgets/42',
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    nonce: 'nonce_xyz',
    ...overrides,
  }
}

// ── Crosswalk ─────────────────────────────────────────────────────

test('delegationToMppAllowed — extracts cap from resource_limits.spend_limit_cents', () => {
  const d = paymentDelegation({ spend_limit_cents: 2500 })
  const allowed = delegationToMppAllowed(d)
  assert.equal(allowed.max_amount_per_charge, 2500)
})

test('delegationToMppAllowed — extracts cap from resource_limits[commerce.spend_limit] AP2 alias', () => {
  const d = paymentDelegation()
  delete (d.scope as { resource_limits?: Record<string, number> }).resource_limits
  d.scope.resource_limits = { 'commerce.spend_limit': 8888 }
  const allowed = delegationToMppAllowed(d)
  assert.equal(allowed.max_amount_per_charge, 8888)
})

test('delegationToMppAllowed — falls back to constraints.spend_limit_cents string', () => {
  const d = paymentDelegation()
  delete (d.scope as { resource_limits?: Record<string, number> }).resource_limits
  ;(d.scope.constraints as Record<string, string>).spend_limit_cents = '7500'
  const allowed = delegationToMppAllowed(d)
  assert.equal(allowed.max_amount_per_charge, 7500)
})

test('delegationToMppAllowed — null cap when no field present', () => {
  const d = paymentDelegation()
  delete (d.scope as { resource_limits?: Record<string, number> }).resource_limits
  delete (d.scope.constraints as Record<string, string>).spend_limit_cents
  const allowed = delegationToMppAllowed(d)
  assert.equal(allowed.max_amount_per_charge, null)
})

test('delegationToMppAllowed — parses CSV methods + currencies, lower-cases currency', () => {
  const d = paymentDelegation({
    allowed_payment_methods: 'tempo, card ,lightning',
    allowed_currencies: 'USD,BTC',
  })
  const allowed = delegationToMppAllowed(d)
  assert.deepEqual(allowed.allowed_methods, ['tempo', 'card', 'lightning'])
  assert.deepEqual(allowed.allowed_currencies, ['usd', 'btc'])
})

test('delegationToMppAllowed — picks valid_until from policy_context', () => {
  const future = new Date(Date.now() + 30 * 60 * 1000).toISOString()
  const d = paymentDelegation({ valid_until: future })
  const allowed = delegationToMppAllowed(d)
  assert.equal(allowed.valid_until, future)
})

// ── Pre-authorization gate ────────────────────────────────────────

test('preAuthorizeMppPayment — happy path allows', () => {
  const r = preAuthorizeMppPayment(happyChallenge(), paymentDelegation())
  assert.equal(r.allow, true)
})

test('preAuthorizeMppPayment — denies missing payment scope', () => {
  const d = paymentDelegation({ action_categories: ['analysis'] })
  const r = preAuthorizeMppPayment(happyChallenge(), d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'no_payment_scope')
})

test('preAuthorizeMppPayment — denies expired delegation', () => {
  const d = paymentDelegation({ valid_until: new Date(Date.now() - 1000).toISOString() })
  const r = preAuthorizeMppPayment(happyChallenge(), d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'delegation_expired')
})

test('preAuthorizeMppPayment — denies expired challenge', () => {
  const ch = happyChallenge({ expires_at: new Date(Date.now() - 1000).toISOString() })
  const r = preAuthorizeMppPayment(ch, paymentDelegation())
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'challenge_expired')
})

test('preAuthorizeMppPayment — denies method not in allow-list', () => {
  const d = paymentDelegation({ allowed_payment_methods: 'card' })
  const ch = happyChallenge({ methods: [tempoMethod()] })
  const r = preAuthorizeMppPayment(ch, d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'method_not_allowed')
})

test('preAuthorizeMppPayment — denies currency not in allow-list', () => {
  const d = paymentDelegation({ allowed_currencies: 'eur' })
  const ch = happyChallenge({ methods: [cardMethod({ currency: 'usd' })] })
  const r = preAuthorizeMppPayment(ch, d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'currency_not_allowed')
})

test('preAuthorizeMppPayment — denies card amount over per-charge cap', () => {
  const d = paymentDelegation({ spend_limit_cents: 1000 })
  const ch = happyChallenge({ methods: [cardMethod({ amount_minor_units: 99999 })] })
  const r = preAuthorizeMppPayment(ch, d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'spend_limit_exceeded')
})

test('preAuthorizeMppPayment — passes if at least one method matches', () => {
  // Only 'card' is allowed; challenge offers tempo + card. Should allow.
  const d = paymentDelegation({ allowed_payment_methods: 'card' })
  const ch = happyChallenge({ methods: [tempoMethod(), cardMethod()] })
  const r = preAuthorizeMppPayment(ch, d)
  assert.equal(r.allow, true)
})

test('preAuthorizeMppPayment — empty methods list rejected', () => {
  const ch = happyChallenge({ methods: [] })
  const r = preAuthorizeMppPayment(ch, paymentDelegation())
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'invalid_authorization')
})

// ── APS → MPP HTTP error mapping ──────────────────────────────────

test('apsToMppHttpError — every denial reason maps deterministically', () => {
  const reasons: MppDenialReason[] = [
    'spend_limit_exceeded',
    'method_not_allowed',
    'currency_not_allowed',
    'delegation_expired',
    'no_payment_scope',
    'challenge_expired',
    'invalid_authorization',
    'session_replay',
    'wallet_revoked',
    'mpp_version_mismatch',
  ]
  const seen = new Set<string>()
  for (const r of reasons) {
    const m = apsToMppHttpError(r)
    assert.ok([402, 403, 410, 503].includes(m.http_status), `${r} must map to a known status`)
    assert.ok(m.www_authenticate_error, `${r} must produce error= token`)
    seen.add(`${m.http_status}|${m.www_authenticate_error}`)
  }
  assert.ok(seen.size >= 4, `expected >=4 distinct envelopes, got ${seen.size}`)
})

test('apsToMppHttpError — version mismatch is 503', () => {
  const m = apsToMppHttpError('mpp_version_mismatch')
  assert.equal(m.http_status, 503)
})

test('apsToMppHttpError — wallet_revoked is 410', () => {
  const m = apsToMppHttpError('wallet_revoked')
  assert.equal(m.http_status, 410)
})

// ── Receipt sign / verify ─────────────────────────────────────────

test('signMppReceipt + verifyMppReceipt — round-trip per method (tempo)', () => {
  const kp = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_001',
      method_type: 'tempo',
      amount_paid: '1.50',
      currency: '0x20c0c5b3a2f1aa8ee9b3d1c7e0a1b2c3d4e5f6a7',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/1',
      delegation_ref: 'del_mpp_test_001',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  assert.equal(r.mpp_version, MPP_VERSION)
  assert.equal(r.receipt_kind, 'mpp.payment_settled')
  assert.equal(r.method_type, 'tempo')
  assert.equal(r.signer, kp.publicKey)
  assert.ok(r.signature.length > 0)
  const v = verifyMppReceipt(r)
  assert.equal(v.valid, true)
})

test('signMppReceipt + verifyMppReceipt — round-trip per method (card)', () => {
  const kp = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_002',
      method_type: 'card',
      amount_paid: '1500',
      currency: 'usd',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/2',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  const v = verifyMppReceipt(r)
  assert.equal(v.valid, true)
})

test('signMppReceipt + verifyMppReceipt — round-trip per method (lightning)', () => {
  const kp = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_003',
      method_type: 'lightning',
      amount_paid: '1000000',
      currency: 'btc',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/3',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  const v = verifyMppReceipt(r)
  assert.equal(v.valid, true)
})

test('verifyMppReceipt — rejects tampered signature', () => {
  const kp = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_004',
      method_type: 'card',
      amount_paid: '500',
      currency: 'usd',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/4',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  ;(r as { amount_paid: string }).amount_paid = '99999'
  const v = verifyMppReceipt(r)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'SIGNATURE_INVALID')
})

test('verifyMppReceipt — rejects expired receipt (default 24h ttl)', () => {
  const kp = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_005',
      method_type: 'card',
      amount_paid: '500',
      currency: 'usd',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/5',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  r.issued_at = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString()
  const v = verifyMppReceipt(r)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'EXPIRED')
})

test('verifyMppReceipt — rejects mpp_version mismatch', () => {
  const kp = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_006',
      method_type: 'card',
      amount_paid: '500',
      currency: 'usd',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/6',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  ;(r as { mpp_version: string }).mpp_version = 'draft-httpauth-payment-99'
  const v = verifyMppReceipt(r)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'INVALID_VERSION')
})

test('verifyMppReceipt — rejects expected_signer mismatch', () => {
  const kp1 = generateKeyPair()
  const kp2 = generateKeyPair()
  const r = signMppReceipt(
    {
      challenge_id: 'mpc_007',
      method_type: 'card',
      amount_paid: '500',
      currency: 'usd',
      paid_at: new Date().toISOString(),
      resource: 'https://api.example.com/v1/widgets/7',
      agent_id: 'agent-001',
    },
    kp1.privateKey,
  )
  const v = verifyMppReceipt(r, { expected_signer: kp2.publicKey })
  assert.equal(v.valid, false)
})

// ── Denial sign / verify ──────────────────────────────────────────

test('signMppDenial + verifyMppDenial — round-trip and stable mapping', () => {
  const kp = generateKeyPair()
  const denial = signMppDenial(
    {
      challenge_id: 'mpc_d1',
      method_type: 'card',
      reason: 'spend_limit_exceeded',
      delegation_ref: 'd1',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  assert.equal(denial.http_status, 402)
  assert.equal(denial.www_authenticate_error, 'insufficient_funds')

  const v = verifyMppDenial(denial)
  assert.equal(v.valid, true)
})

test('verifyMppDenial — rejects tampered http_status (mapping invariant)', () => {
  const kp = generateKeyPair()
  const denial = signMppDenial(
    {
      reason: 'method_not_allowed',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  ;(denial as { http_status: number }).http_status = 503
  const v = verifyMppDenial(denial)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'SIGNATURE_INVALID')
})

test('verifyMppDenial — every denial reason produces a verifiable denial', () => {
  const reasons: MppDenialReason[] = [
    'spend_limit_exceeded',
    'method_not_allowed',
    'currency_not_allowed',
    'delegation_expired',
    'no_payment_scope',
    'challenge_expired',
    'invalid_authorization',
    'session_replay',
    'wallet_revoked',
    'mpp_version_mismatch',
  ]
  const kp = generateKeyPair()
  for (const r of reasons) {
    const d = signMppDenial(
      {
        challenge_id: `mpc_${r}`,
        reason: r,
        agent_id: 'agent-001',
      },
      kp.privateKey,
    )
    const v = verifyMppDenial(d)
    assert.equal(v.valid, true, `denial for ${r} should verify; got ${JSON.stringify(v)}`)
  }
})
