#!/usr/bin/env node
// ══════════════════════════════════════════════════════════════
// Agent Social Contract — CLI
// ══════════════════════════════════════════════════════════════
//
// passport join     — Create an agent in the social contract
// passport verify   — Verify an agent's passport + attestation
// passport delegate — Grant authority to another agent
// passport work     — Record a unit of work
// passport prove    — Generate contribution proofs
// passport audit    — Check compliance against the Floor
// passport inspect  — View passport/receipt/proof details
// passport status   — Show current agent status
//
// Data is stored in .passport/ directory:
//   .passport/agent.json     — passport + keys + attestation
//   .passport/delegations/   — active delegations
//   .passport/receipts/      — signed action receipts
//   .passport/proofs/        — generated proofs

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

import {
  joinSocialContract, verifySocialContract,
  delegate, recordWork, proveContributions, auditCompliance,
  generateKeyPair, loadFloor, clearStores, verifyMerkleProof,
  verifyPassport, verifyAttestation, verifyReceipt,
  verifyAttributionReport
} from '../index.js'

import type {
  SignedPassport, FloorAttestation,
  ActionReceipt, Delegation, KeyPair, ValuesFloor
} from '../types/passport.js'

import type { SocialContractAgent } from '../contract.js'

// ── Paths ──
const DIR = '.passport'
const AGENT_FILE = join(DIR, 'agent.json')
const DEL_DIR = join(DIR, 'delegations')
const RECEIPT_DIR = join(DIR, 'receipts')
const PROOF_DIR = join(DIR, 'proofs')

// ── Storage helpers ──

function ensureDirs(): void {
  for (const d of [DIR, DEL_DIR, RECEIPT_DIR, PROOF_DIR]) {
    if (!existsSync(d)) mkdirSync(d, { recursive: true })
  }
}

function saveJSON(path: string, data: unknown): void {
  writeFileSync(path, JSON.stringify(data, null, 2))
}

function loadJSON<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T
}

function agentExists(): boolean {
  return existsSync(AGENT_FILE)
}

interface StoredAgent {
  passport: SignedPassport
  keyPair: KeyPair
  attestation: FloorAttestation | null
  agentId: string
  publicKey: string
}

function loadAgent(): StoredAgent {
  if (!agentExists()) {
    console.error('❌ No agent found. Run: passport join')
    process.exit(1)
  }
  return loadJSON<StoredAgent>(AGENT_FILE)
}

function loadDelegations(): Delegation[] {
  if (!existsSync(DEL_DIR)) return []
  return readdirSync(DEL_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => loadJSON<Delegation>(join(DEL_DIR, f)))
}

function loadReceipts(): ActionReceipt[] {
  if (!existsSync(RECEIPT_DIR)) return []
  return readdirSync(RECEIPT_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => loadJSON<ActionReceipt>(join(RECEIPT_DIR, f)))
}

// ── CLI Router ──

const args = process.argv.slice(2)
const command = args[0]

switch (command) {
  case 'join': cmdJoin(); break
  case 'verify': cmdVerify(); break
  case 'delegate': cmdDelegate(); break
  case 'work': cmdWork(); break
  case 'prove': cmdProve(); break
  case 'audit': cmdAudit(); break
  case 'inspect': cmdInspect(); break
  case 'status': cmdStatus(); break
  default: cmdHelp(); break
}

// ══════════════════════════════════════
// JOIN — Create agent in the social contract
// ══════════════════════════════════════

function cmdJoin(): void {
  if (agentExists()) {
    console.error('❌ Agent already exists. Delete .passport/ to start over.')
    process.exit(1)
  }

  const name = getFlag('--name') || 'agent'
  const mission = getFlag('--mission') || 'General purpose autonomous agent'
  const owner = getFlag('--owner') || 'anonymous'
  const caps = getFlag('--capabilities')?.split(',') || ['code_execution', 'web_search']
  const platform = getFlag('--platform') || 'node'
  const models = getFlag('--models')?.split(',') || ['unknown']
  const floorPath = getFlag('--floor')
  const beneficiaryId = getFlag('--beneficiary')
  const extensions = getFlag('--extensions')?.split(',') || []

  let floor: string | undefined
  if (floorPath) {
    if (!existsSync(floorPath)) {
      console.error(`❌ Floor file not found: ${floorPath}`)
      process.exit(1)
    }
    floor = readFileSync(floorPath, 'utf8')
  }

  const agent = joinSocialContract({
    name,
    mission,
    owner,
    capabilities: caps,
    platform,
    models,
    floor,
    floorExtensions: extensions,
    beneficiary: beneficiaryId ? { id: beneficiaryId, relationship: 'creator' } : undefined
  })

  ensureDirs()
  saveJSON(AGENT_FILE, {
    passport: agent.passport,
    keyPair: agent.keyPair,
    attestation: agent.attestation,
    agentId: agent.agentId,
    publicKey: agent.publicKey
  })

  console.log('🤝 Joined the Agent Social Contract')
  console.log('')
  console.log(`  Agent:    ${agent.agentId}`)
  console.log(`  Owner:    ${owner}`)
  console.log(`  Mission:  ${mission}`)
  console.log(`  Caps:     ${caps.join(', ')}`)
  console.log(`  Key:      ${agent.publicKey.slice(0, 16)}...`)
  if (agent.attestation) {
    console.log(`  Floor:    v${agent.attestation.floorVersion} ✓ attested`)
  }
  if (beneficiaryId) {
    console.log(`  Beneficiary: ${beneficiaryId}`)
  }
  console.log('')
  console.log(`  Stored in ${DIR}/`)
  console.log(`  ⚠️  Keep ${AGENT_FILE} safe — contains private key`)
}

// ══════════════════════════════════════
// VERIFY — Check another agent's passport
// ══════════════════════════════════════

function cmdVerify(): void {
  const file = args[1]
  if (!file) {
    console.error('Usage: passport verify <passport.json>')
    console.error('       passport verify <agent.json>')
    process.exit(1)
  }

  if (!existsSync(file)) {
    console.error(`❌ File not found: ${file}`)
    process.exit(1)
  }

  const data = loadJSON<any>(file)

  // Support both full agent files and passport-only files
  const passport: SignedPassport = data.passport || data
  const attestation: FloorAttestation | null = data.attestation || null

  const trust = verifySocialContract(passport, attestation)

  console.log('')
  if (trust.overall) {
    console.log('✅ TRUSTED')
  } else {
    console.log('❌ NOT TRUSTED')
  }

  console.log('')
  console.log(`  Identity: ${trust.identity.valid ? '✓ valid' : '✗ INVALID'}`)
  if (trust.identity.errors.length) {
    for (const e of trust.identity.errors) console.log(`    ✗ ${e}`)
  }

  if (trust.values) {
    console.log(`  Values:   ${trust.values.valid ? '✓ attested' : '✗ INVALID'}`)
    if (trust.values.errors.length) {
      for (const e of trust.values.errors) console.log(`    ✗ ${e}`)
    }
  } else {
    console.log(`  Values:   — not attested`)
  }

  if (passport.passport) {
    const p = passport.passport
    console.log('')
    console.log(`  Agent:    ${p.agentName} (${p.agentId})`)
    console.log(`  Owner:    ${p.ownerAlias}`)
    console.log(`  Mission:  ${p.mission}`)
    console.log(`  Caps:     ${p.capabilities.join(', ')}`)
    console.log(`  Expires:  ${p.expiresAt}`)
  }
  console.log('')
}

// ══════════════════════════════════════
// DELEGATE — Grant authority
// ══════════════════════════════════════

function cmdDelegate(): void {
  const agent = loadAgent()
  const toKey = getFlag('--to')
  const scope = getFlag('--scope')?.split(',')
  const limit = Number(getFlag('--limit') || '0') || undefined
  const hours = Number(getFlag('--hours') || '24')
  const depth = Number(getFlag('--depth') || '1')

  if (!toKey || !scope) {
    console.error('Usage: passport delegate --to <publicKey> --scope <scope1,scope2> [--limit 500] [--hours 24] [--depth 1]')
    process.exit(1)
  }

  const del = delegate({
    from: agent as any,
    toPublicKey: toKey,
    scope,
    spendLimit: limit,
    maxDepth: depth,
    expiresInHours: hours
  })

  ensureDirs()
  saveJSON(join(DEL_DIR, `${del.delegationId}.json`), del)

  console.log('📋 Delegation created')
  console.log('')
  console.log(`  ID:       ${del.delegationId}`)
  console.log(`  From:     ${agent.publicKey.slice(0, 16)}...`)
  console.log(`  To:       ${toKey.slice(0, 16)}...`)
  console.log(`  Scope:    ${scope.join(', ')}`)
  if (limit) console.log(`  Limit:    $${limit}`)
  console.log(`  Depth:    max ${depth}`)
  console.log(`  Expires:  ${del.expiresAt}`)
  console.log('')
}

// ══════════════════════════════════════
// WORK — Record an action
// ══════════════════════════════════════

function cmdWork(): void {
  const agent = loadAgent()
  const type = getFlag('--type') || 'task'
  const target = getFlag('--target') || 'unknown'
  const scope = getFlag('--scope')
  const spend = Number(getFlag('--spend') || '0')
  const result = (getFlag('--result') || 'success') as 'success' | 'failure' | 'partial'
  const summary = getFlag('--summary') || ''
  const delId = getFlag('--delegation')
  const chain = getFlag('--chain')?.split(',')

  if (!scope) {
    console.error('Usage: passport work --scope <scope> [--type task] [--target x] [--spend 10] [--result success] [--summary "did stuff"]')
    console.error('       --delegation <id>  — delegation to act under')
    console.error('       --chain <key1,key2,...>  — delegation chain (principal to executor)')
    process.exit(1)
  }

  // Find delegation
  const delegations = loadDelegations()
  let del: Delegation | undefined

  if (delId) {
    del = delegations.find(d => d.delegationId === delId)
  } else {
    // Auto-find: first delegation that includes this scope
    del = delegations.find(d => d.scope.includes(scope))
  }

  if (!del) {
    console.error('❌ No valid delegation found for scope: ' + scope)
    console.error('   Create one with: passport delegate --to <key> --scope ' + scope)
    process.exit(1)
  }

  // Build chain: default to [delegator, agent]
  const delegationChain = chain || [del.delegatedBy, agent.publicKey]

  const receipt = recordWork(
    agent as any,
    del,
    delegationChain,
    { type, target, scope, spend, result, summary }
  )

  ensureDirs()
  saveJSON(join(RECEIPT_DIR, `${receipt.receiptId}.json`), receipt)

  console.log('📝 Work recorded')
  console.log('')
  console.log(`  Receipt:  ${receipt.receiptId}`)
  console.log(`  Type:     ${type}`)
  console.log(`  Target:   ${target}`)
  console.log(`  Scope:    ${scope}`)
  if (spend) console.log(`  Spend:    $${spend}`)
  console.log(`  Result:   ${result}`)
  if (summary) console.log(`  Summary:  ${summary}`)
  console.log(`  Under:    ${del.delegationId}`)
  console.log('')
}

// ══════════════════════════════════════
// PROVE — Generate contribution proofs
// ══════════════════════════════════════

function cmdProve(): void {
  const agent = loadAgent()
  const beneficiary = getFlag('--beneficiary') || agent.publicKey
  const receipts = loadReceipts()
  const delegations = loadDelegations()

  if (receipts.length === 0) {
    console.error('❌ No receipts found. Record work first: passport work --scope ...')
    process.exit(1)
  }

  const proof = proveContributions(
    agent as any,
    receipts,
    delegations,
    beneficiary
  )

  ensureDirs()
  // Serialize proofs map
  const serializedProofs: Record<string, any> = {}
  for (const [id, p] of proof.proofs) {
    serializedProofs[id] = p
  }

  const output = {
    attribution: proof.attribution,
    merkleRoot: proof.merkleRoot,
    proofs: serializedProofs,
    traces: proof.traces,
    generatedAt: new Date().toISOString()
  }

  const outFile = join(PROOF_DIR, `proof-${Date.now().toString(36)}.json`)
  saveJSON(outFile, output)

  console.log('🌳 Contribution proof generated')
  console.log('')
  console.log(`  Agent:       ${agent.agentId}`)
  console.log(`  Beneficiary: ${beneficiary}`)
  console.log(`  Receipts:    ${proof.attribution.receiptCount}`)
  console.log(`  Weight:      ${proof.attribution.totalWeight}`)
  console.log(`  Merkle root: ${proof.merkleRoot.slice(0, 24)}...`)
  console.log(`  Proofs:      ${proof.proofs.size} (one per receipt)`)

  // Verify each proof
  let allValid = true
  for (const [id, merkleProof] of proof.proofs) {
    if (!verifyMerkleProof(merkleProof)) {
      console.log(`  ❌ ${id}: proof INVALID`)
      allValid = false
    }
  }
  if (allValid) console.log(`  Verified:    ✓ all proofs valid`)

  // Show traces
  const verified = proof.traces.filter(t => t.verified).length
  console.log(`  Traces:      ${verified}/${proof.traces.length} fully verified`)

  console.log('')
  console.log(`  Saved: ${outFile}`)
  console.log('')
}

// ══════════════════════════════════════
// AUDIT — Check compliance against Floor
// ══════════════════════════════════════

function cmdAudit(): void {
  const floorPath = getFlag('--floor') || args[1]
  if (!floorPath) {
    console.error('Usage: passport audit --floor <floor.yaml>')
    process.exit(1)
  }

  if (!existsSync(floorPath)) {
    console.error(`❌ Floor file not found: ${floorPath}`)
    process.exit(1)
  }

  const agent = loadAgent()
  const receipts = loadReceipts()
  const delegations = loadDelegations()
  const floor = loadFloor(readFileSync(floorPath, 'utf8'))
  const verifier = generateKeyPair()

  // Build delegation context
  const delContext = new Map<string, { scope: string[]; revoked: boolean }>()
  for (const d of delegations) {
    delContext.set(d.delegationId, { scope: d.scope, revoked: false })
  }

  const report = auditCompliance(agent.agentId, receipts, floor, delContext, verifier)

  console.log('🔍 Compliance Audit')
  console.log('')
  console.log(`  Agent:       ${agent.agentId}`)
  console.log(`  Floor:       v${report.floorVersion}`)
  console.log(`  Receipts:    ${report.receiptsAnalyzed}`)
  console.log(`  Compliance:  ${(report.overallCompliance * 100).toFixed(1)}%`)
  console.log('')

  for (const check of report.checks) {
    const icon = check.status === 'enforced' ? '🔒' :
                 check.status === 'attested' ? '📝' :
                 check.status === 'violation' ? '❌' : '❓'
    console.log(`  ${icon} ${check.principleName}: ${check.status}`)
    console.log(`     ${check.detail}`)
  }
  console.log('')
}

// ══════════════════════════════════════
// INSPECT — View any protocol artifact
// ══════════════════════════════════════

function cmdInspect(): void {
  const file = args[1]
  if (!file) {
    console.error('Usage: passport inspect <file.json>')
    process.exit(1)
  }

  if (!existsSync(file)) {
    console.error(`❌ File not found: ${file}`)
    process.exit(1)
  }

  const data = loadJSON<any>(file)
  console.log('')

  // Detect what kind of artifact this is (order matters — check specific fields first)
  if (data.passport && data.keyPair) {
    console.log('📋 Agent (full)')
    console.log(`  ID:      ${data.agentId}`)
    console.log(`  Name:    ${data.passport.passport.agentName}`)
    console.log(`  Key:     ${data.publicKey.slice(0, 16)}...`)
    console.log(`  Floor:   ${data.attestation ? 'v' + data.attestation.floorVersion : 'none'}`)
  } else if (data.passport && data.signature && data.signedAt) {
    console.log('📋 Signed Passport')
    const p = data.passport
    console.log(`  Agent:   ${p.agentName} (${p.agentId})`)
    console.log(`  Owner:   ${p.ownerAlias}`)
    console.log(`  Caps:    ${p.capabilities.join(', ')}`)
    console.log(`  Expires: ${p.expiresAt}`)
  } else if (data.receiptId) {
    console.log('📋 Action Receipt')
    console.log(`  ID:      ${data.receiptId}`)
    console.log(`  Agent:   ${data.agentId}`)
    console.log(`  Action:  ${data.action?.type} → ${data.action?.target}`)
    console.log(`  Scope:   ${data.action?.scopeUsed}`)
    console.log(`  Result:  ${data.result?.status}`)
    console.log(`  Chain:   ${data.delegationChain?.length} hops`)
  } else if (data.attribution) {
    console.log('📋 Contribution Proof')
    console.log(`  Agent:   ${data.attribution.agentId}`)
    console.log(`  Weight:  ${data.attribution.totalWeight}`)
    console.log(`  Root:    ${data.merkleRoot?.slice(0, 24)}...`)
    console.log(`  Proofs:  ${Object.keys(data.proofs || {}).length}`)
    console.log(`  Traces:  ${data.traces?.length || 0}`)
  } else if (data.reportId && data.checks) {
    console.log('📋 Compliance Report')
    console.log(`  Agent:   ${data.agentId}`)
    console.log(`  Floor:   v${data.floorVersion}`)
    console.log(`  Score:   ${(data.overallCompliance * 100).toFixed(1)}%`)
    console.log(`  Checks:  ${data.checks.length}`)
  } else if (data.delegationId) {
    console.log('📋 Delegation')
    console.log(`  ID:      ${data.delegationId}`)
    console.log(`  From:    ${data.delegatedBy?.slice(0, 16)}...`)
    console.log(`  To:      ${data.delegatedTo?.slice(0, 16)}...`)
    console.log(`  Scope:   ${data.scope?.join(', ')}`)
    console.log(`  Expires: ${data.expiresAt}`)
  } else {
    console.log('📋 Unknown artifact')
    console.log(JSON.stringify(data, null, 2).slice(0, 500))
  }
  console.log('')
}

// ══════════════════════════════════════
// STATUS — Current agent status
// ══════════════════════════════════════

function cmdStatus(): void {
  if (!agentExists()) {
    console.log('')
    console.log('  No agent found.')
    console.log('  Run: passport join --name <name> --owner <owner>')
    console.log('')
    return
  }

  const agent = loadAgent()
  const delegations = loadDelegations()
  const receipts = loadReceipts()
  const proofFiles = existsSync(PROOF_DIR)
    ? readdirSync(PROOF_DIR).filter(f => f.endsWith('.json'))
    : []

  console.log('')
  console.log('🤝 Agent Social Contract — Status')
  console.log('━'.repeat(40))
  console.log('')
  console.log(`  Agent:        ${agent.agentId}`)
  console.log(`  Key:          ${agent.publicKey.slice(0, 16)}...`)

  // Verify identity
  const idCheck = verifyPassport(agent.passport)
  console.log(`  Identity:     ${idCheck.valid ? '✓ valid' : '✗ INVALID'}`)

  // Check attestation
  if (agent.attestation) {
    const attCheck = verifyAttestation(agent.attestation)
    console.log(`  Floor:        v${agent.attestation.floorVersion} ${attCheck.valid ? '✓' : '✗ ' + attCheck.errors[0]}`)
  } else {
    console.log(`  Floor:        — not attested`)
  }

  console.log('')
  console.log(`  Delegations:  ${delegations.length}`)
  const active = delegations.filter(d => new Date(d.expiresAt) > new Date())
  const expired = delegations.length - active.length
  if (expired > 0) console.log(`    (${expired} expired)`)

  console.log(`  Receipts:     ${receipts.length}`)
  if (receipts.length > 0) {
    const scopes = new Set(receipts.map(r => r.action.scopeUsed))
    console.log(`    Scopes:     ${[...scopes].join(', ')}`)
    const success = receipts.filter(r => r.result.status === 'success').length
    console.log(`    Success:    ${success}/${receipts.length}`)
  }

  console.log(`  Proofs:       ${proofFiles.length}`)
  console.log('')
}

// ══════════════════════════════════════
// HELP
// ══════════════════════════════════════

function cmdHelp(): void {
  console.log(`
🤝 Agent Social Contract — CLI

  GETTING STARTED:
    passport join --name aeoess --owner tymofii --floor values/floor.yaml
    passport status

  COMMANDS:
    join       Create an agent in the social contract
               --name <name>  --owner <owner>  --mission <text>
               --capabilities code_execution,web_search
               --platform node  --models claude-sonnet
               --floor <floor.yaml>  --beneficiary <id>

    verify     Verify another agent's passport
               passport verify <agent.json or passport.json>

    delegate   Grant authority to another agent
               --to <publicKey>  --scope <scope1,scope2>
               --limit <amount>  --hours <24>  --depth <1>

    work       Record a unit of work
               --scope <scope>  --type <task>  --target <x>
               --spend <10>  --result success  --summary "text"
               --delegation <id>  --chain <key1,key2>

    prove      Generate contribution proofs (Merkle tree)
               --beneficiary <id>

    audit      Check compliance against the Floor
               --floor <floor.yaml>

    inspect    View any protocol artifact
               passport inspect <file.json>

    status     Show current agent status

  DATA:
    All data stored in .passport/ directory.
    Keep .passport/agent.json safe — it contains your private key.

  PROTOCOL:
    https://github.com/aeoess/agent-passport-system
`)
}

// ── Flag parser ──

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag)
  if (idx === -1 || idx + 1 >= args.length) return undefined
  return args[idx + 1]
}
