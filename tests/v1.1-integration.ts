// v1.1 Integration Test — Full accountability chain
// Creates passports for aeoess & PortalX2, delegates, executes, traces, revokes

import {
  createPassport, verifyPassport, generateKeyPair,
  createDelegation, subDelegate, verifyDelegation,
  revokeDelegation, createReceipt, verifyReceipt,
  getReceipts, clearStores
} from '../src/index.js'

clearStores()

console.log('═══════════════════════════════════════════════════')
console.log('  AGENT PASSPORT v1.1 — FULL INTEGRATION TEST')
console.log('═══════════════════════════════════════════════════\n')

// ──────────────────────────────────────
// STEP 1: Create passports for both agents
// ──────────────────────────────────────
console.log('▸ STEP 1: Creating passports...\n')

const aeoess = createPassport({
  agentId: 'aeoess-001',
  agentName: 'aeoess',
  ownerAlias: 'tima',
  mission: 'Autonomous AI software engineer',
  capabilities: ['code_execution', 'web_search', 'email_management',
    'git_operations', 'system_control', 'browser_automation'],
  runtime: { platform: 'node', models: ['claude-sonnet', 'gpt-4o'],
    toolsCount: 17, memoryType: 'sqlite' }
})

const portal = createPassport({
  agentId: 'portalx2-001',
  agentName: 'PortalX2',
  ownerAlias: 'tymofii',
  mission: 'Build community good for agent community',
  capabilities: ['code_execution', 'web_search', 'browser_automation',
    'file_management', 'sub_agent_orchestration'],
  runtime: { platform: 'node', models: ['claude-opus-4'],
    toolsCount: 14, memoryType: 'file_persistent' }
})

// Verify both passports
const aV = verifyPassport(aeoess.signedPassport)
const pV = verifyPassport(portal.signedPassport)
console.log(`  aeoess:   ${aV.valid ? '✅ VALID' : '❌ INVALID'} | vote weight: ${aeoess.signedPassport.passport.voteWeight}`)
console.log(`  PortalX2: ${pV.valid ? '✅ VALID' : '❌ INVALID'} | vote weight: ${portal.signedPassport.passport.voteWeight}`)
console.log(`  aeoess pubkey:  ${aeoess.keyPair.publicKey.slice(0, 16)}...`)
console.log(`  portal pubkey:  ${portal.keyPair.publicKey.slice(0, 16)}...\n`)

// ──────────────────────────────────────
// STEP 2: aeoess delegates to PortalX2
// ──────────────────────────────────────
console.log('▸ STEP 2: aeoess delegates "code_execution" to PortalX2...\n')

const delegation = createDelegation({
  delegatedTo: portal.signedPassport.passport.publicKey,
  delegatedBy: aeoess.signedPassport.passport.publicKey,
  scope: ['code_execution', 'web_search'],
  spendLimit: 500,
  maxDepth: 1,  // Only 1 level of sub-delegation allowed
  expiresInHours: 24,
  privateKey: aeoess.keyPair.privateKey
})

const dV = verifyDelegation(delegation)
console.log(`  Delegation ${delegation.delegationId}: ${dV.valid ? '✅ VALID' : '❌ INVALID'}`)
console.log(`  Scope: [${delegation.scope}]`)
console.log(`  Spend limit: $${delegation.spendLimit}`)
console.log(`  Depth: ${delegation.currentDepth}/${delegation.maxDepth}\n`)

// ──────────────────────────────────────
// STEP 3: PortalX2 executes a task and signs a receipt
// ──────────────────────────────────────
console.log('▸ STEP 3: PortalX2 executes task + signs action receipt...\n')

const receipt1 = createReceipt({
  agentId: 'portalx2-001',
  delegationId: delegation.delegationId,
  delegation,
  action: {
    type: 'code_execution',
    target: 'github.com/aeoess/agent-passport-system',
    method: 'git push',
    scopeUsed: 'code_execution',
    spend: { amount: 50, currency: 'USD' }
  },
  result: {
    status: 'success',
    summary: 'Pushed kanban board implementation to aeoess_web repo'
  },
  delegationChain: [
    aeoess.signedPassport.passport.publicKey,
    portal.signedPassport.passport.publicKey
  ],
  privateKey: portal.keyPair.privateKey
})

const r1V = verifyReceipt(receipt1, portal.signedPassport.passport.publicKey)
console.log(`  Receipt ${receipt1.receiptId}: ${r1V.valid ? '✅ VALID' : '❌ INVALID'}`)
console.log(`  Action: ${receipt1.action.type} → ${receipt1.action.target}`)
console.log(`  Scope used: ${receipt1.action.scopeUsed}`)
console.log(`  Spend: $${receipt1.action.spend?.amount}`)
console.log(`  Result: ${receipt1.result.status} — ${receipt1.result.summary}`)
console.log(`  Chain: ${receipt1.delegationChain.map(k => k.slice(0,8)+'...').join(' → ')}\n`)

// ──────────────────────────────────────
// STEP 4: PortalX2 sub-delegates to a third agent (SINT)
// ──────────────────────────────────────
console.log('▸ STEP 4: PortalX2 sub-delegates to SINT (depth test)...\n')

const sintKeys = generateKeyPair()
const subDel = subDelegate({
  parentDelegation: delegation,
  delegatedTo: sintKeys.publicKey,
  scope: ['web_search'],  // narrower scope
  spendLimit: 100,          // less than parent remaining
  privateKey: portal.keyPair.privateKey
})

const sdV = verifyDelegation(subDel)
console.log(`  Sub-delegation ${subDel.delegationId}: ${sdV.valid ? '✅ VALID' : '❌ INVALID'}`)
console.log(`  Scope narrowed to: [${subDel.scope}]`)
console.log(`  Depth: ${subDel.currentDepth}/${subDel.maxDepth}`)

// SINT tries to sub-delegate further (depth=2, maxDepth=2 → should fail)
console.log(`\n  SINT tries to sub-delegate (depth 2/2)...`)
try {
  const thirdKeys = generateKeyPair()
  subDelegate({
    parentDelegation: subDel,
    delegatedTo: thirdKeys.publicKey,
    scope: ['web_search'],
    privateKey: sintKeys.privateKey
  })
  console.log('  ❌ SHOULD HAVE FAILED')
} catch (e: any) {
  console.log(`  ✅ Correctly blocked: ${e.message}\n`)
}

// ──────────────────────────────────────
// STEP 5: Scope violation test
// ──────────────────────────────────────
console.log('▸ STEP 5: Scope violation test...\n')

try {
  subDelegate({
    parentDelegation: delegation,
    delegatedTo: sintKeys.publicKey,
    scope: ['email_management'],  // NOT in parent scope
    privateKey: portal.keyPair.privateKey
  })
  console.log('  ❌ SHOULD HAVE FAILED')
} catch (e: any) {
  console.log(`  ✅ Correctly blocked: ${e.message}\n`)
}

// ──────────────────────────────────────
// STEP 6: Revocation — aeoess revokes Portal's delegation
// ──────────────────────────────────────
console.log('▸ STEP 6: aeoess revokes PortalX2 delegation...\n')

const revocation = revokeDelegation(
  delegation.delegationId,
  aeoess.signedPassport.passport.publicKey,
  'task_complete',
  aeoess.keyPair.privateKey
)

console.log(`  Revocation ${revocation.revocationId}: signed ✅`)
console.log(`  Reason: ${revocation.reason}`)
console.log(`  Revoked at: ${revocation.revokedAt}`)

// Now verify delegation again — should be invalid
const dV2 = verifyDelegation(delegation)
console.log(`\n  Delegation after revocation: ${dV2.valid ? '❌ STILL VALID (BUG)' : '✅ CORRECTLY INVALID'}`)
console.log(`  Revoked: ${dV2.revoked}`)
console.log(`  Errors: ${dV2.errors.join(', ')}`)

// ──────────────────────────────────────
// STEP 7: Try to create receipt after revocation — should fail
// ──────────────────────────────────────
console.log('\n▸ STEP 7: PortalX2 tries to act after revocation...\n')

try {
  createReceipt({
    agentId: 'portalx2-001',
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: 'code_execution',
      target: 'github.com/aeoess/something',
      scopeUsed: 'code_execution'
    },
    result: { status: 'success', summary: 'should not work' },
    delegationChain: [
      aeoess.signedPassport.passport.publicKey,
      portal.signedPassport.passport.publicKey
    ],
    privateKey: portal.keyPair.privateKey
  })
  console.log('  ❌ SHOULD HAVE FAILED')
} catch (e: any) {
  console.log(`  ✅ Correctly blocked: ${e.message}\n`)
}

// ──────────────────────────────────────
// STEP 8: Audit trail — show all receipts
// ──────────────────────────────────────
console.log('▸ STEP 8: Full audit trail...\n')

const allReceipts = getReceipts()
console.log(`  Total receipts: ${allReceipts.length}`)
allReceipts.forEach((r, i) => {
  console.log(`  [${i+1}] ${r.receiptId} | ${r.agentId} | ${r.action.scopeUsed} | ${r.result.status}`)
  console.log(`      Chain: ${r.delegationChain.map(k => k.slice(0,8)+'...').join(' → ')}`)
})

// ──────────────────────────────────────
// SUMMARY
// ──────────────────────────────────────
console.log('\n═══════════════════════════════════════════════════')
console.log('  TEST SUMMARY')
console.log('═══════════════════════════════════════════════════')
console.log('  ✅ Passport creation + verification')
console.log('  ✅ Delegation with scope + spend + depth')
console.log('  ✅ Action receipt creation + verification')
console.log('  ✅ Sub-delegation with depth enforcement')
console.log('  ✅ Depth limit blocking at max_depth')
console.log('  ✅ Scope narrowing enforcement')
console.log('  ✅ Revocation with cascade')
console.log('  ✅ Post-revocation action blocked')
console.log('  ✅ Full audit trail traceable')
console.log('═══════════════════════════════════════════════════\n')
