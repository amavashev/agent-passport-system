// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// aps-fs-witness — filesystem walker, hasher, and envelope signer
// ══════════════════════════════════════════════════════════════════

import {
  createPrivateKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto'
import {
  createHash,
} from 'node:crypto'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, posix, resolve } from 'node:path'

import {
  canonicalizeEnvelope,
  canonicalizePath,
  computeContextRoot,
  sortInstructionFiles,
} from '../vendor/canonicalize.js'
import { canonicalizeJCS } from '../vendor/canonical-jcs.js'
import type {
  FilesystemMode,
  InstructionFile,
  InstructionRole,
} from '../vendor/types.js'
import type {
  WitnessedContextRoot,
  WitnessIndependenceLevel,
  WitnessKeyMaterial,
} from './types.js'

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

const DEFAULT_KEY_DIR = join(homedir(), '.aps-fs-witness')
const DEFAULT_KEY_PATH = join(DEFAULT_KEY_DIR, 'witness-key.json')

/** Limitations the v0 witness signs into every envelope. Downstream
 *  verifiers MUST surface these to humans rather than treat a witnessed
 *  envelope as a stronger guarantee than it is. */
export const DEFAULT_CLAIM_LIMITATIONS: readonly string[] = [
  'does-not-prove: agent used only these instructions',
  'does-not-prove: no other instructions influenced the action',
  'does-not-prove: model attention respected file content',
  'does-not-prove: agent did not read instruction-class content from outside the declared discovery patterns',
  'does-not-prove: file content at agent-execution time matches file content at witness-observation time',
  'does-not-prove: discovery patterns are exhaustive over the working_root',
]

export interface LoadOrCreateKeyOptions {
  /** Path to the witness key file. Defaults to
   *  `~/.aps-fs-witness/witness-key.json`. */
  keyPath?: string
}

/**
 * Load the witness key material from disk, or generate and persist a new
 * Ed25519 keypair on first run. The key file is written with mode 0600.
 *
 * Independence rule: this key MUST be generated locally inside the witness
 * process. It MUST NOT be derived from, shared with, or copied from any
 * agent process — that would defeat the point of having a witness.
 */
export function loadOrCreateWitnessKey(
  options: LoadOrCreateKeyOptions = {},
): WitnessKeyMaterial {
  const keyPath = options.keyPath ?? DEFAULT_KEY_PATH
  if (existsSync(keyPath)) {
    const raw = readFileSync(keyPath, 'utf8')
    const parsed = JSON.parse(raw) as WitnessKeyMaterial
    if (
      typeof parsed.privateKeyHex !== 'string' ||
      !/^[0-9a-f]{64}$/.test(parsed.privateKeyHex) ||
      typeof parsed.publicKeyHex !== 'string' ||
      !/^[0-9a-f]{64}$/.test(parsed.publicKeyHex)
    ) {
      throw new Error(`witness key at ${keyPath} is malformed; refuse to use`)
    }
    return parsed
  }

  // First-run keygen — locally, inside this process. No external entropy
  // source beyond Node's crypto.generateKeyPairSync.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const seedDer = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer
  // PKCS8 Ed25519 envelope is the 16-byte prefix above + 32-byte seed.
  const seed = seedDer.subarray(PKCS8_ED25519_PREFIX.length)
  if (seed.length !== 32) {
    throw new Error(`unexpected Ed25519 seed length: ${seed.length}`)
  }
  const pubRaw = publicKey.export({ format: 'der', type: 'spki' }) as Buffer
  // SPKI Ed25519 SubjectPublicKeyInfo is 12 bytes of prefix + 32-byte key.
  const pub = pubRaw.subarray(pubRaw.length - 32)

  const material: WitnessKeyMaterial = {
    privateKeyHex: Buffer.from(seed).toString('hex'),
    publicKeyHex: Buffer.from(pub).toString('hex'),
    createdAt: new Date().toISOString(),
  }

  const dir = keyPath.slice(0, keyPath.lastIndexOf('/')) || '/'
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(keyPath, JSON.stringify(material, null, 2), { mode: 0o600 })
  return material
}

export interface WalkOptions {
  workingRoot: string
  discoveryPatterns: string[]
  filesystemMode: FilesystemMode
}

/**
 * Walk the working root and return InstructionFile entries for every
 * regular file matched by any of the discovery patterns.
 *
 * Patterns are POSIX globs relative to `workingRoot`. Supported features:
 *   - literal segments
 *   - `*`  matches any run of non-`/` characters
 *   - `**` matches any number of path segments
 *   - leading `./` is stripped
 *   - dotfiles are matched (no special handling)
 *
 * The walk is breadth-first under `workingRoot`; symlinks are recorded as
 * `is_symlink: true` entries with the link's own digest (we do not follow).
 */
export function walkAndHash(options: WalkOptions): InstructionFile[] {
  const { workingRoot, discoveryPatterns, filesystemMode } = options
  if (!isAbsolute(workingRoot)) {
    throw new Error(`working_root must be absolute POSIX: ${workingRoot}`)
  }
  if (discoveryPatterns.length === 0) {
    throw new Error('discovery_patterns must be non-empty')
  }

  const matchers = discoveryPatterns.map(p => {
    const stripped = stripLeadingDotSlash(p)
    const normalized = filesystemMode === 'case-insensitive' ? stripped.toLowerCase() : stripped
    return globToRegex(normalized)
  })

  const matched = new Map<string, InstructionFile>()

  const allFiles = walkAllFiles(workingRoot)
  for (const abs of allFiles) {
    const rel = abs.slice(workingRoot.length + 1)
    const cmpRel = filesystemMode === 'case-insensitive' ? rel.toLowerCase() : rel
    const isMatch = matchers.some(re => re.test(cmpRel))
    if (!isMatch) continue

    const stat = lstatSync(abs)
    const isSymlink = stat.isSymbolicLink()
    const isFile = stat.isFile()
    if (!isSymlink && !isFile) continue

    const buf = readFileSync(abs)
    const digest = createHash('sha256').update(buf).digest('hex')
    const role = classifyRole(rel)

    const canonical = canonicalizePath(rel, {
      workingRoot,
      filesystemMode,
    })

    matched.set(canonical, {
      path: canonical,
      digest,
      bytes: buf.length,
      role,
      ...(isSymlink ? { is_symlink: true } : {}),
    })
  }

  return sortInstructionFiles(Array.from(matched.values()))
}

function walkAllFiles(root: string): string[] {
  const out: string[] = []
  const stack: string[] = [root]
  while (stack.length > 0) {
    const dir = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const entry of entries) {
      // Skip a small set of well-known non-source directories so the witness
      // does not spend forever in node_modules. The witness still hashes any
      // top-level file inside these if a pattern names them explicitly,
      // because literal-pattern matches are checked separately below.
      if (entry === 'node_modules' || entry === '.git') continue
      const full = join(dir, entry)
      let stat
      try {
        stat = lstatSync(full)
      } catch {
        continue
      }
      if (stat.isDirectory()) stack.push(full)
      else out.push(full)
    }
  }
  return out
}

function stripLeadingDotSlash(p: string): string {
  if (p.startsWith('./')) return p.slice(2)
  return p
}

/** Translate a POSIX glob to a JS RegExp anchored at start and end.
 *  Supports `*` (single-segment) and `**` (multi-segment). */
export function globToRegex(glob: string): RegExp {
  let re = ''
  let i = 0
  while (i < glob.length) {
    const c = glob[i]
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**` — match any number of path segments. Consume optional `/`.
        re += '.*'
        i += 2
        if (glob[i] === '/') i += 1
      } else {
        re += '[^/]*'
        i += 1
      }
    } else if (c === '?') {
      re += '[^/]'
      i += 1
    } else if (c === '.' || c === '+' || c === '(' || c === ')' || c === '|' || c === '^' || c === '$' || c === '{' || c === '}' || c === '[' || c === ']' || c === '\\') {
      re += `\\${c}`
      i += 1
    } else {
      re += c
      i += 1
    }
  }
  return new RegExp(`^${re}$`)
}

function classifyRole(relPath: string): InstructionRole {
  const lower = relPath.toLowerCase()
  const base = posix.basename(lower)
  if (base === 'claude.md' || base === 'agents.md') return 'agent_md'
  if (base === 'memory.md') return 'memory'
  if (base === '.cursorrules' || base.endsWith('rules.md') || base === 'rules') return 'rules'
  if (base.startsWith('system_prompt') || base.startsWith('system-prompt')) return 'system_prompt'
  if (base === 'user.md') return 'user_md'
  return 'other'
}

export interface ProduceWitnessedContextRootInput {
  workingRoot: string
  discoveryPatterns: string[]
  filesystemMode: FilesystemMode
  independenceLevel: WitnessIndependenceLevel
  key: WitnessKeyMaterial
  /** Override observation time for tests; defaults to now(). */
  observedAt?: string
  /** Override claim limitations; defaults to DEFAULT_CLAIM_LIMITATIONS. */
  claimLimitations?: readonly string[]
}

/**
 * End-to-end witness pipeline: walk, hash, canonicalize, sign.
 * Returns a fully-formed WitnessedContextRoot envelope.
 */
export function produceWitnessedContextRoot(
  input: ProduceWitnessedContextRootInput,
): WitnessedContextRoot {
  const files = walkAndHash({
    workingRoot: input.workingRoot,
    discoveryPatterns: input.discoveryPatterns,
    filesystemMode: input.filesystemMode,
  })

  const contextRoot = computeContextRoot(files)
  const observedAt = input.observedAt ?? new Date().toISOString()
  const claimLimitations = [
    ...(input.claimLimitations ?? DEFAULT_CLAIM_LIMITATIONS),
  ]
  const witnessDid = `did:key:zWitness${input.key.publicKeyHex.slice(0, 32)}`
  const signingKeyId = `ed25519:${input.key.publicKeyHex.slice(0, 16)}`

  // Build unsigned envelope and JCS-canonicalize for signing. The signature
  // covers everything except `witness_signature` itself.
  const unsigned = {
    witness_did: witnessDid,
    witness_role: 'filesystem-witness' as const,
    independence_level: input.independenceLevel,
    observed_at: observedAt,
    working_root: input.workingRoot,
    filesystem_mode: input.filesystemMode,
    discovery_patterns: input.discoveryPatterns,
    instruction_files: files,
    context_root: contextRoot,
    claim_limitations: claimLimitations,
    witness_signing_key_id: signingKeyId,
  }

  const canonicalBytes = canonicalizeJCS(unsigned)
  const signature = signEd25519(canonicalBytes, input.key.privateKeyHex)

  return { ...unsigned, witness_signature: signature }
}

export function signEd25519(message: string | Uint8Array, privateKeyHex: string): string {
  const seed = Buffer.from(privateKeyHex, 'hex')
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const msg = typeof message === 'string' ? Buffer.from(message, 'utf8') : Buffer.from(message)
  const sig = cryptoSign(null, msg, keyObj)
  return Buffer.from(sig).toString('hex')
}

/** Re-export so consumers can compute envelope bytes without importing the
 *  vendor path directly. */
export { canonicalizeJCS, canonicalizeEnvelope, computeContextRoot }
export { DEFAULT_KEY_PATH }
export { resolve as resolvePath }
