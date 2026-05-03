// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Payment-rails governance hooks — preAuthorize, emit, verify, fixtures.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createDefaultGovernanceHooks,
  createNanoRail,
  emitDenial,
  emitReceipt,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentReceipt,
  xnoToRaw,
} from '../../../src/v2/payment-rails/index.js'
import type {
  DelegationView,
  PaymentDenial,
  PaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import { publicKeyFromPrivate } from '../../../src/crypto/keys.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, '..', '..', '..', 'src', 'v2', 'payment-rails', 'fixtures')

const ISSUER_PRIV = '88'.repeat(32)
const ISSUER_PUB = publicKeyFromPrivate(ISSUER_PRIV)
const FIXED_TS = '2026-05-03T20:00:00.000Z'

const ADDR = 'nano_3test1f1xt7r3y6a7z9k1c0nv8d4yhfk93rcd6b1pmce8wkqf6kpunkfxnwd'

function _delegation(overrides: Partial<DelegationView> = {}): DelegationView {
  return {
    receipt_id: 'd'.repeat(64),
    scope: ['commerce.purchase'],
    spend_limit_base_units: xnoToRaw('1'), // 1 XNO
    wallet_id: 'wallet-test-001',
    currency: 'XNO',
    ...overrides,
  }
}

function _rail() {
  return createNanoRail({
    receivingAddress: ADDR,
    fetchHistory: async () => [],
    fetchBlockInfo: async () => ({ confirmed: 'true', amount: '0' }),
  })
}

// ── preAuthorize gate matrix ──────────────────────────────────────

describe('preAuthorize', () => {
  it('returns ok=true when scope matches and amount under limit', () => {
    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, true)
  })

  it('rejects with no_commerce_scope when required_scope is absent', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ scope: ['commerce.refund'] }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'no_commerce_scope')
    assert.match(result.reason_detail ?? '', /commerce\.purchase/)
  })

  it('rejects with spend_limit_exceeded when amount > delegation budget', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ spend_limit_base_units: xnoToRaw('0.0001') }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('1'), // way over the 0.0001 limit
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'spend_limit_exceeded')
  })

  it('rejects with wallet_revoked after rail.revokeWallet on the bound wallet', async () => {
    const rail = _rail()
    await rail.revokeWallet('wallet-test-001')
    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'wallet_revoked')
  })

  it('rejects with time_window_violation when before not_before', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ not_before: '2099-01-01T00:00:00.000Z' }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        now: new Date('2026-05-03T20:00:00.000Z'),
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'time_window_violation')
    assert.match(result.reason_detail ?? '', /not_before/)
  })

  it('rejects with time_window_violation when after not_after', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ not_after: '2020-01-01T00:00:00.000Z' }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        now: new Date('2026-05-03T20:00:00.000Z'),
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'time_window_violation')
    assert.match(result.reason_detail ?? '', /not_after/)
  })

  it('rejects with spend_limit_exceeded when currencies do not match', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ currency: 'USDC' }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'spend_limit_exceeded')
    assert.match(result.reason_detail ?? '', /currency mismatch/)
  })

  it('default GovernanceHooks bundle exposes the same preAuthorize behavior', () => {
    const hooks = createDefaultGovernanceHooks()
    const result = hooks.preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, true)
  })
})

// ── emitReceipt + verifyPaymentReceipt ────────────────────────────

describe('emitReceipt + verifyPaymentReceipt', () => {
  it('emits a signed receipt that round-trips through verify', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        invoice_id: 'inv-test-001',
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    assert.equal(r.claim_type, 'aps:payment_receipt:v1')
    assert.equal(r.signer_did, ISSUER_PUB)
    assert.equal(r.receipt_id.length, 64)
    assert.equal(r.signature.length, 128)
    const v = verifyPaymentReceipt(r)
    assert.equal(v.valid, true)
  })

  it('verify returns RECEIPT_ID_MISMATCH when amount is tampered', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const tampered: PaymentReceipt = { ...r, amount_base_units: xnoToRaw('1') }
    const v = verifyPaymentReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('verify returns SIGNATURE_INVALID when signature byte is flipped', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const last = r.signature.slice(-1)
    const flipped = r.signature.slice(0, -1) + (last === '0' ? '1' : '0')
    const tampered: PaymentReceipt = { ...r, signature: flipped }
    const v = verifyPaymentReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('verify returns INVALID_CLAIM_TYPE for wrong claim_type', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const tampered: PaymentReceipt = { ...r, claim_type: 'aps:other:v1' }
    const v = verifyPaymentReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_CLAIM_TYPE')
  })

  it('two emits with identical inputs produce the same receipt_id and signature', () => {
    const inputs = {
      delegation_ref: 'd'.repeat(64),
      action_ref: 'a'.repeat(64),
      rail_name: 'nano',
      amount_base_units: xnoToRaw('0.001'),
      currency: 'XNO',
      tx_proof: 'b'.repeat(64),
      invoice_id: 'inv-test-001',
      issued_at: FIXED_TS,
    }
    const a = emitReceipt(inputs, ISSUER_PRIV)
    const b = emitReceipt(inputs, ISSUER_PRIV)
    assert.equal(a.receipt_id, b.receipt_id)
    assert.equal(a.signature, b.signature)
  })
})

// ── emitDenial + verifyPaymentDenial ──────────────────────────────

describe('emitDenial + verifyPaymentDenial', () => {
  it('emits a signed denial that round-trips through verify', () => {
    const d = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        denial_reason: 'no_commerce_scope',
        reason_detail: "scope 'commerce.purchase' not in delegation",
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    assert.equal(d.claim_type, 'aps:payment_denial:v1')
    assert.equal(d.denial_reason, 'no_commerce_scope')
    const v = verifyPaymentDenial(d)
    assert.equal(v.valid, true)
  })

  it('verify returns INVALID_DENIAL_REASON for unknown reason', () => {
    const d = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        denial_reason: 'rail_error',
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const tampered: PaymentDenial = {
      ...d,
      denial_reason: 'made_up_reason' as PaymentDenial['denial_reason'],
    }
    const v = verifyPaymentDenial(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_DENIAL_REASON')
  })

  it('emit throws on unknown denial_reason at construction time', () => {
    assert.throws(
      () =>
        emitDenial(
          {
            delegation_ref: 'd'.repeat(64),
            action_ref: 'a'.repeat(64),
            rail_name: 'nano',
            amount_base_units: xnoToRaw('0.001'),
            currency: 'XNO',
            denial_reason: 'made_up' as PaymentDenial['denial_reason'],
            issued_at: FIXED_TS,
          },
          ISSUER_PRIV,
        ),
      /denial_reason must be one of/,
    )
  })
})

// ── Fixture byte-parity ───────────────────────────────────────────

describe('fixtures — byte-parity round trip', () => {
  it('checked-in receipt fixture verifies clean', () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'receipt-nano-happy.fixture.json'), 'utf8'),
    ) as PaymentReceipt
    const v = verifyPaymentReceipt(fixture)
    assert.equal(v.valid, true, `fixture verify failed: ${v.reason}`)
  })

  it('checked-in denial fixture verifies clean', () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'denial-no-scope.fixture.json'), 'utf8'),
    ) as PaymentDenial
    const v = verifyPaymentDenial(fixture)
    assert.equal(v.valid, true, `fixture verify failed: ${v.reason}`)
  })
})
