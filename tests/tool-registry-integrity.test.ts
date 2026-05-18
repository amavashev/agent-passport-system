// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Tool Registry & Discovery Integrity — tests
// Covers: Part 0 hash fix, signed manifests, publisher identity verification,
// namespace governance, metadata-change re-approval, conformance vectors.
// Maps to CoSAI control `controlToolRegistryandDiscoveryIntegrity`.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createToolRegistryEntry,
  verifyToolIntegrity,
} from '../src/core/tool-integrity.js'

// ══════════════════════════════════════════════════════════════════
// Part 0 — Buffer/string hashing fix
// ══════════════════════════════════════════════════════════════════
describe('Part 0 — implementation hashing (Buffer + string)', () => {
  it('hashes a utf-8 string and its equivalent Buffer to the same hash', () => {
    const kp = generateKeyPair()
    const strEntry = createToolRegistryEntry({
      toolName: 'web_search', implementation: 'tool-source-v1',
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const bufEntry = createToolRegistryEntry({
      toolName: 'web_search', implementation: Buffer.from('tool-source-v1', 'utf8'),
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    // Canonical behaviour: string -> utf-8 bytes, Buffer -> raw bytes.
    // An equivalent utf-8 Buffer therefore produces the SAME implementationHash.
    assert.equal(strEntry.implementationHash, bufEntry.implementationHash)
  })

  it('verifyToolIntegrity cross-checks a string entry against an equivalent Buffer', () => {
    const kp = generateKeyPair()
    const entry = createToolRegistryEntry({
      toolName: 'web_search', implementation: 'tool-source-v1',
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const r = verifyToolIntegrity({
      registryEntry: entry,
      currentImplementation: Buffer.from('tool-source-v1', 'utf8'),
      attestorPublicKey: kp.publicKey,
    })
    assert.equal(r.implementationVerified, true)
    assert.equal(r.attestorSignatureValid, true)
    assert.equal(r.valid, true)
  })

  it('hashes raw (non-utf8) Buffer bytes as-is', () => {
    const kp = generateKeyPair()
    const raw = Buffer.from([0xff, 0x00, 0xfe, 0x01, 0x80])
    const entry = createToolRegistryEntry({
      toolName: 'binary_tool', implementation: raw,
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const expected = 'sha256:' + createHash('sha256').update(raw).digest('hex')
    assert.equal(entry.implementationHash, expected)
  })

  it('detects a swapped implementation (tool-swap attack)', () => {
    const kp = generateKeyPair()
    const entry = createToolRegistryEntry({
      toolName: 'web_search', implementation: 'tool-source-v1',
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const r = verifyToolIntegrity({
      registryEntry: entry,
      currentImplementation: Buffer.from('malicious-source', 'utf8'),
      attestorPublicKey: kp.publicKey,
    })
    assert.equal(r.implementationVerified, false)
    assert.equal(r.valid, false)
  })
})
