// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Drift-Denial Demo — APS structural mitigation for the Cursor public CVE
// pattern (GHSA-4cxx-hrm3-49rm, GHSA-vqv7-vq92-x87f, CVE-2025-54135 /
// CurXecute, NomShub).
//
// Run:  npx tsx demo.ts
// ══════════════════════════════════════════════════════════════════

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeEnvelope,
  canonicalizePath,
  computeContextRoot,
  createInstructionProvenanceReceipt,
  sha256Hex,
  sortInstructionFiles,
  verifyActionTimeContextRoot,
} from '../../src/v2/instruction-provenance/index.js'
import type {
  CreateIPRInput,
  InstructionFile,
  InstructionProvenanceReceipt,
} from '../../src/v2/instruction-provenance/index.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const DEMO_DIR = __dirname
const FIXTURE_PATH = resolve(DEMO_DIR, '..', '..', 'fixtures', 'instruction-provenance', 'canonicalize-fixture-v1.json')

// ─── deterministic identity / delegation -------------------------------------
// Fixed values keep `expected-output.txt` byte-stable across machines.

const DELEGATION_CHAIN_ROOT = sha256Hex('drift-denial-demo-delegation')
const ALLOWED_ACTION_CLASSES = ['github.merge_pr', 'send_payment']
const AGENT_DID = 'did:key:zDriftDenialDemoAgent'
const WORKING_ROOT = '/demo/drift-denial-workspace'
const ISSUED_AT = '2026-04-26T00:00:00.000Z'
const BOUND_TO = { type: 'session' as const, ref: 'sess_drift_denial_demo_001' }
const SESSION_KEY_SEED = sha256Hex('drift-denial-demo-private-key')

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function deriveKeypairFromSeed(seedHex: string): { privateKeyHex: string; publicKeyHex: string } {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, 'hex')])
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  const pubDer = createPublicKey(priv).export({ format: 'der', type: 'spki' }) as Buffer
  return { privateKeyHex: seedHex, publicKeyHex: pubDer.subarray(pubDer.length - 32).toString('hex') }
}

const { privateKeyHex, publicKeyHex } = deriveKeypairFromSeed(SESSION_KEY_SEED)

// ─── instruction-file ingestion ---------------------------------------------

interface IngestedFile {
  /** canonical relative POSIX path used inside the IPR */
  path: string
  /** absolute on-disk path used to read content */
  diskPath: string
  role: InstructionFile['role']
}

const INGESTED: IngestedFile[] = [
  { path: 'CLAUDE.md', diskPath: join(DEMO_DIR, 'CLAUDE.md'), role: 'agent_md' },
  { path: '.cursor/rules/security.md', diskPath: join(DEMO_DIR, '.cursor', 'rules', 'security.md'), role: 'rules' },
]

const SECURITY_MD = INGESTED.find(f => f.path === '.cursor/rules/security.md')!
const ATTACK_PATH = join(DEMO_DIR, '.cursor', 'rules', 'security.md.attack')

function hashFileFromDisk(absPath: string): { digest: string; bytes: number } {
  const buf = readFileSync(absPath)
  return { digest: sha256Hex(buf), bytes: buf.byteLength }
}

function instructionFilesAt(): InstructionFile[] {
  // Re-read every file from disk and emit canonical InstructionFile entries.
  const files: InstructionFile[] = INGESTED.map(f => {
    const { digest, bytes } = hashFileFromDisk(f.diskPath)
    const canonical = canonicalizePath(f.path, {
      workingRoot: WORKING_ROOT,
      filesystemMode: 'case-sensitive',
    })
    return { path: canonical, digest, bytes, role: f.role }
  })
  return sortInstructionFiles(files)
}

// ─── output helpers ---------------------------------------------------------

function line(s: string = ''): void {
  process.stdout.write(s + '\n')
}

// ─── WITHOUT APS path -------------------------------------------------------
// No IPR. The agent ingests files mid-session; injected instructions land in
// the model context and the action proceeds.

function runWithoutAps(): void {
  line('WITHOUT APS:')
  line(`  Delegation: ${DELEGATION_CHAIN_ROOT}`)
  line('  Instruction file injected at T+5s')
  line('  Action: send_payment')
  line('  RESULT: action proceeds under attacker-controlled instructions')
  line('  VULNERABLE: action would have executed under injected instruction context')
}

// ─── WITH APS path ----------------------------------------------------------
// 1. Issue IPR with recompute_at_action: true at T0.
// 2. Mid-session, swap security.md for the .attack version on disk.
// 3. Re-walk discovery_patterns at action time, recompute context_root.
// 4. verifyActionTimeContextRoot detects drift, deny the action.

interface DriftOutcome {
  envelope: InstructionProvenanceReceipt
  contextRootAtActionTime: string
  drift: boolean
  reason: string
}

function runWithApsAndDrift(): DriftOutcome {
  // ── Issue IPR --------------------------------------------------------------
  const initialFiles = instructionFilesAt()
  const input: CreateIPRInput = {
    delegation_chain_root: DELEGATION_CHAIN_ROOT,
    agent_did: AGENT_DID,
    discovery_patterns: ['./CLAUDE.md', './.cursor/rules/*.md'],
    working_root: WORKING_ROOT,
    filesystem_mode: 'case-sensitive',
    instruction_files: initialFiles,
    recompute_at_action: true,
    issued_at: ISSUED_AT,
    bound_to: BOUND_TO,
    privateKeyHex,
    publicKeyHex,
  }
  const envelope = createInstructionProvenanceReceipt(input)

  // ── Inject the .attack version (real swap with try/finally restore) ------
  const originalSecurityMd = readFileSync(SECURITY_MD.diskPath)
  const attackContent = readFileSync(ATTACK_PATH)
  let outcome: DriftOutcome
  try {
    writeFileSync(SECURITY_MD.diskPath, attackContent)
    const reWalked = instructionFilesAt()
    const contextRootAtActionTime = computeContextRoot(reWalked)
    const result = verifyActionTimeContextRoot({
      envelope,
      context_root_at_action_time: contextRootAtActionTime,
    })
    outcome = {
      envelope,
      contextRootAtActionTime,
      drift: !result.valid,
      reason: result.errors[0] ?? 'no_action_time_drift required, observed mismatch',
    }
  } finally {
    writeFileSync(SECURITY_MD.diskPath, originalSecurityMd)
  }

  // ── Print rhythm -----------------------------------------------------------
  line('WITH APS:')
  line(`  Delegation: ${DELEGATION_CHAIN_ROOT}`)
  line(`  IPR issued: context_root ${envelope.context_root}`)
  line('  Instruction file injected at T+5s')
  line('  Action: send_payment')
  line(`  context_root_at_action_time: ${outcome.contextRootAtActionTime}`)
  line('  DECISION: DENY')
  line('  Reason: instruction_context.no_action_time_drift required, observed mismatch')
  line('  This is the structural mitigation for: GHSA-4cxx-hrm3-49rm class')

  return outcome
}

// ─── Byte-parity check vs IPR fixture vectors -------------------------------
// Re-runs the canonicalizer on every fixture vector that publishes
// canonical_bytes_hex. Fails loud if anything drifts away from the spec
// reference bytes / hash.

interface FixtureVector {
  name: string
  envelope?: InstructionProvenanceReceipt
  canonical_bytes_hex?: string
  canonical_sha256?: string
  context_root?: string
  receipt_id?: string
  expected_verification: boolean
}
interface FixtureFile { vectors: FixtureVector[] }

function runByteParityCheck(): { passed: number; total: number; failures: string[] } {
  const fixture: FixtureFile = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'))
  const positives = fixture.vectors.filter(v => v.canonical_bytes_hex && v.envelope)
  const failures: string[] = []
  let passed = 0
  for (const v of positives) {
    const env = v.envelope!
    const canonical = canonicalizeEnvelope(env)
    const canonicalHex = Buffer.from(canonical, 'utf8').toString('hex')
    const canonicalHash = sha256Hex(canonical)
    const recomputedRoot = computeContextRoot(env.instruction_files)
    if (canonicalHex !== v.canonical_bytes_hex) {
      failures.push(`${v.name}: canonical bytes mismatch`)
      continue
    }
    if (canonicalHash !== v.canonical_sha256) {
      failures.push(`${v.name}: canonical sha256 mismatch`)
      continue
    }
    if (v.receipt_id && canonicalHash !== v.receipt_id) {
      failures.push(`${v.name}: receipt_id mismatch`)
      continue
    }
    if (v.context_root && recomputedRoot !== v.context_root) {
      failures.push(`${v.name}: context_root mismatch`)
      continue
    }
    passed += 1
  }
  return { passed, total: positives.length, failures }
}

// ─── main -------------------------------------------------------------------

function main(): void {
  line('═══════════════════════════════════════════════════════════════')
  line(' Drift-Denial Demo — Cursor public CVE class structural mitigation')
  line(' (GHSA-4cxx-hrm3-49rm, GHSA-vqv7-vq92-x87f, CVE-2025-54135, NomShub)')
  line('═══════════════════════════════════════════════════════════════')
  line()
  runWithoutAps()
  line()
  const outcome = runWithApsAndDrift()
  line()
  const parity = runByteParityCheck()
  line('Byte-parity vs fixtures/instruction-provenance/canonicalize-fixture-v1.json:')
  line(`  ${parity.passed}/${parity.total} vectors PASS`)
  if (parity.failures.length > 0) {
    for (const f of parity.failures) line(`  FAIL: ${f}`)
    process.exit(1)
  }
  if (!outcome.drift) {
    line('FAIL: drift not detected; demo invariant broken')
    process.exit(1)
  }
}

main()
