# RFC 9421 + RFC 9530 request-binding profile

A transport profile that wraps a request-bound HTTP Message Signature
([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.txt)) as the **inner** proof
and links it to an APS delegation receipt by content hash. Body integrity is
bound with a Content-Digest field
([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.txt), sha-256).

The HTTP signature shows "this exact request was the one authorized". The APS
layer shows authority. These are two separate claims and are kept separate.

## What this covers

- Covered components: `@method`, `@authority`, `@path` (request-context derived
  components, RFC 9421 §2.2), plus optional `content-digest` for bodies.
- `keyid` is the DID verification method.
- Signature params: `created` (freshness), `nonce` (replay defense, verifier
  must track), and a profile `tag` (cross-protocol-reuse defense). `alg` is
  omitted by default to avoid alg-confusion; the verifier derives the algorithm
  from the key.
- Byte-exact signature-base serialization per RFC 9421 §2.3 and §2.5: each line
  is `"<lowercased-name>": <value>` terminated by a single LF (0x0A, not CRLF),
  with a final `@signature-params` line carrying no trailing newline.

## Conformance vectors

The reference Ed25519 path is validated against the deterministic published
vectors:

- **RFC 9530 Appendix B.1**: sha-256 Content-Digest of `{"hello": "world"}\n`
  (19 bytes) byte-matches `sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:`.
- **RFC 9421 Appendix B.2.6**: signing the published signature base with the
  `test-key-ed25519` private key reproduces the published signature value
  byte-for-byte (Ed25519 is deterministic).

Negative paths are tested explicitly: wrong method, swapped path, swapped
authority, body substitution (content-digest mismatch), stale or future-dated
`created` outside the skew window, replayed nonce, tag mismatch, missing
required component, empty covered set, unknown verification method, and a
tampered signature.

## Proof box

A valid request-binding proof under this profile **proves**:

> The signer, holding the private key for the named DID verification method,
> authorized this exact HTTP request (method, authority, path, and, when
> `content-digest` is covered, the body bytes) at the signing time `created`.

It **does not prove**:

- That the request reached its destination, was acted on, or produced any
  effect. It binds intent at signing time, not delivery.
- Authority, by itself. Authority is established by the APS delegation receipt linked
  via `receiptHash`. The HTTP signature shows the request was the one
  authorized; the APS layer shows the signer was authorized to make it.
- A binding between `action_ref` and the HTTP request. `action_ref` does NOT
  bind the HTTP request and is not used by this profile. The link between this
  request and a delegation receipt is the content hash carried in `receiptHash`
  plus the inner HTTP Message Signature.
- The body, when `content-digest` is covered, unless the verifier recomputes the
  digest over received bytes and byte-compares. Content-digest alone, unsigned
  or unrecomputed, shows nothing about the body.

## Scope

This module provides protocol primitives and a reference verifier. The
`NonceStore` is an interface with an in-memory reference implementation; a
production, shared, or persistent replay cache is a deployment concern and is
out of scope here. This profile does not modify the APS receipt-signing path,
the `action_ref` preimage, or canonical serialization.

## Usage

```ts
import {
  signRequest,
  verifyRequest,
  InMemoryNonceStore,
  APS_REQUEST_BINDING_TAG,
} from 'agent-passport-system/src/v2/transport/rfc9421/index.js'

const profile = signRequest({
  request: { method: 'POST', url: 'https://example.com/foo?param=Value', body },
  signer: { privateKeyHex, verificationMethod: 'did:key:z6Mk...#z6Mk...' },
  params: { created: Math.floor(Date.now() / 1000), nonce: cryptoNonce },
  covered: ['@method', '@authority', '@path', 'content-digest'],
  receiptHash, // hex sha-256 of the linked delegation receipt
})

const store = new InMemoryNonceStore()
const result = verifyRequest({
  profile,
  request: { method: 'POST', url: 'https://example.com/foo?param=Value', body },
  keys: [{ publicKeyHex, verificationMethod: 'did:key:z6Mk...#z6Mk...' }],
  policy: { expectedTag: APS_REQUEST_BINDING_TAG, maxSkewSeconds: 300 },
  nonceStore: store,
})
// result.valid === true
```
