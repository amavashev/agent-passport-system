// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// did:cycles: DID-to-JWKS mapping and Ed25519 JWK selection (M3)
// ══════════════════════════════════════════════════════════════════
// did:cycles is an AEOESS-defined, did:web-style, HTTPS-anchored
// method. There is no external registry to conform to; this file IS
// its specification. It mirrors didWebToUrl() in core/did-interop.ts
// exactly, except the method name is `cycles` and the resolved
// document is a JWKS (RFC 7517) rather than a DID Document.
//
//   did:cycles:example.com          -> https://example.com/.well-known/jwks.json
//   did:cycles:example.com:agents:7 -> https://example.com/agents/7/jwks.json
//   did:cycles:example.com%3A8443   -> https://example.com:8443/.well-known/jwks.json
//
// A DID-URL fragment is the kid:
//   did:cycles:example.com#agent-7-2026
// selects the JWK whose kid === "agent-7-2026" from the resolved set.
// ══════════════════════════════════════════════════════════════════

import { decodeBase64Url, bytesToHex } from './base64url.js'
import type { Ed25519JWK, JWKS } from './types.js'

export interface ParsedDIDCycles {
  /** https JWKS endpoint the DID maps to. */
  jwksUrl: string
  /** kid taken from the DID-URL fragment, if present. */
  kid?: string
}

/**
 * Parse a did:cycles identifier (optionally with a #fragment) into its
 * JWKS URL and kid. Mirrors didWebToUrl: colon-separated segments,
 * each percent-decoded, segment[0] is the authority, the rest is the
 * path; a bare authority uses /.well-known/jwks.json.
 *
 * Throws on a structurally invalid did:cycles string. The fragment is
 * split off BEFORE segment parsing so a `#` never lands inside a path
 * segment.
 */
export function parseDIDCycles(did: string): ParsedDIDCycles {
  if (typeof did !== 'string') {
    throw new Error('did:cycles must be a string')
  }
  // Split the DID-URL fragment (the kid) off first.
  const hashIndex = did.indexOf('#')
  let kid: string | undefined
  let core = did
  if (hashIndex >= 0) {
    kid = did.slice(hashIndex + 1)
    core = did.slice(0, hashIndex)
    if (kid.length === 0) {
      throw new Error('did:cycles fragment (kid) must not be empty when "#" is present')
    }
  }

  const parts = core.split(':')
  if (parts.length < 3 || parts[0] !== 'did' || parts[1] !== 'cycles') {
    throw new Error(`Invalid did:cycles format: ${core}`)
  }
  // Everything after "did:cycles:" is authority-and-path, colon-separated.
  const segments = parts.slice(2).map(s => decodeURIComponent(s))
  const authority = segments[0]
  if (!authority) {
    throw new Error('did:cycles must include an authority')
  }
  let jwksUrl: string
  if (segments.length === 1) {
    jwksUrl = `https://${authority}/.well-known/jwks.json`
  } else {
    const path = segments.slice(1).join('/')
    jwksUrl = `https://${authority}/${path}/jwks.json`
  }
  return { jwksUrl, kid }
}

/** True if the value looks like a did:cycles identifier. */
export function isDIDCycles(value: string): boolean {
  return typeof value === 'string' && value.startsWith('did:cycles:')
}

export type JWKSelection =
  | { ok: true; jwk: Ed25519JWK; publicKeyHex: string; kid?: string }
  | { ok: false; status: 'not_found' | 'ambiguous' | 'malformed'; reason: string }

/**
 * Validate that a parsed object is a well-formed JWKS with a non-empty
 * `keys` array. Returns the JWKS on success or null on any structural
 * problem. Does NOT validate individual JWK key material; that happens
 * during candidate filtering / selection.
 */
export function asJWKS(body: unknown): JWKS | null {
  if (!body || typeof body !== 'object') return null
  const keys = (body as Record<string, unknown>).keys
  if (!Array.isArray(keys) || keys.length === 0) return null
  return { keys: keys as Ed25519JWK[] }
}

/**
 * Is this JWK an admissible Ed25519 SIGNING candidate?
 *   kty === "OKP" && crv === "Ed25519"
 *   (use absent || use === "sig")
 *   (alg absent || alg === "EdDSA")
 *   (key_ops absent || includes "verify")
 * X-curves, enc keys, and non-EdDSA algs are excluded here.
 */
function isEd25519SigningCandidate(jwk: unknown): jwk is Ed25519JWK {
  if (!jwk || typeof jwk !== 'object') return false
  const k = jwk as Record<string, unknown>
  if (k.kty !== 'OKP') return false
  if (k.crv !== 'Ed25519') return false
  if (typeof k.x !== 'string' || k.x.length === 0) return false
  if (k.use !== undefined && k.use !== 'sig') return false
  if (k.alg !== undefined && k.alg !== 'EdDSA') return false
  if (k.key_ops !== undefined) {
    if (!Array.isArray(k.key_ops) || !k.key_ops.includes('verify')) return false
  }
  return true
}

/**
 * Decode a candidate's `x` to a 32-byte Ed25519 public key, returned
 * as 64-char lowercase hex. Returns null if `x` does not base64url-
 * decode to exactly 32 bytes (malformed key material).
 */
function candidateToHex(jwk: Ed25519JWK): string | null {
  const bytes = decodeBase64Url(jwk.x)
  if (!bytes || bytes.length !== 32) return null
  return bytesToHex(bytes)
}

/**
 * Select exactly one Ed25519 verification key from a JWKS by kid.
 *
 *  1. Filter to Ed25519 signing candidates.
 *  2. If a kid is requested: the candidate whose kid strictly equals it
 *     must be unique. Zero matches -> not_found. Duplicate kids ->
 *     ambiguous. kid comparison is exact, case-sensitive.
 *  3. If no kid is requested: exactly one candidate -> use it; more than
 *     one -> ambiguous; zero -> not_found.
 *  4. Decode `x` -> 32 bytes -> hex. A candidate that survives filtering
 *     but whose `x` is not 32 bytes is malformed.
 *
 * Never silently falls back to a different kid than requested.
 */
export function selectKey(jwks: JWKS, requestedKid?: string): JWKSelection {
  const candidates = jwks.keys.filter(isEd25519SigningCandidate)
  if (candidates.length === 0) {
    return { ok: false, status: 'not_found', reason: 'no Ed25519 signing key in JWKS' }
  }

  if (requestedKid !== undefined) {
    const matches = candidates.filter(c => c.kid === requestedKid)
    if (matches.length === 0) {
      return { ok: false, status: 'not_found', reason: `no key with kid='${requestedKid}'` }
    }
    if (matches.length > 1) {
      return { ok: false, status: 'ambiguous', reason: `duplicate kid='${requestedKid}' in JWKS` }
    }
    const jwk = matches[0]
    const hex = candidateToHex(jwk)
    if (!hex) {
      return { ok: false, status: 'malformed', reason: `kid='${requestedKid}' x is not a 32-byte key` }
    }
    return { ok: true, jwk, publicKeyHex: hex, kid: jwk.kid }
  }

  // No kid requested: require an unambiguous single candidate.
  if (candidates.length > 1) {
    return { ok: false, status: 'ambiguous', reason: 'multiple signing keys and no kid requested' }
  }
  const jwk = candidates[0]
  const hex = candidateToHex(jwk)
  if (!hex) {
    return { ok: false, status: 'malformed', reason: 'sole candidate x is not a 32-byte key' }
  }
  return { ok: true, jwk, publicKeyHex: hex, kid: jwk.kid }
}
