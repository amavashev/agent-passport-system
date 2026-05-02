// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Claim → Evidence types — skeleton conformance.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  ClaimType,
  RecordType,
  EvidenceProfiles,
  requiredEvidenceFor,
} from '../../src/index.js'

describe('claim-evidence-types', () => {
  it('every ClaimType has an EvidenceProfile entry', () => {
    for (const claim of Object.values(ClaimType)) {
      const profile = EvidenceProfiles[claim]
      assert.ok(profile, `missing EvidenceProfile for ${claim}`)
      assert.ok(Array.isArray(profile.required), `required must be an array for ${claim}`)
      assert.ok(
        profile.forbiddenSubstitutions && typeof profile.forbiddenSubstitutions === 'object',
        `forbiddenSubstitutions must be an object for ${claim}`,
      )
    }
  })

  it('requiredEvidenceFor(BINDING_COMMITMENT) includes forbiddenSubstitutions for ActionReceipt', () => {
    const profile = requiredEvidenceFor(ClaimType.BINDING_COMMITMENT)
    const reason = profile.forbiddenSubstitutions[RecordType.ActionReceipt]
    assert.equal(typeof reason, 'string')
    assert.ok(
      reason && reason.length > 0,
      'forbiddenSubstitutions[ActionReceipt] must carry a non-empty rationale',
    )
    assert.match(reason!, /binding commitment/i)
  })

  it('requiredEvidenceFor(AUTHORITY_TO_EXECUTE) returns expected required record types', () => {
    const profile = requiredEvidenceFor(ClaimType.AUTHORITY_TO_EXECUTE)
    assert.deepEqual(profile.required, [RecordType.AuthorityBoundaryReceipt])
  })
})
