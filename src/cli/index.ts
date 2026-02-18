#!/usr/bin/env node
// Agent Passport CLI

import { createPassport } from '../core/passport.js'
import { verifyPassport } from '../verification/verify.js'
import { readFileSync, writeFileSync } from 'node:fs'

const args = process.argv.slice(2)
const command = args[0]

switch (command) {
  case 'create': {
    const agentId = args[1] || 'agent-' + Date.now()
    const name = args[2] || 'Unnamed Agent'
    const { signedPassport, keyPair } = createPassport({
      agentId,
      agentName: name,
      ownerAlias: 'owner',
      mission: 'General purpose autonomous agent',
      capabilities: ['code_execution', 'web_search'],
      runtime: { platform: 'node', models: ['gpt-4'], toolsCount: 1, memoryType: 'ephemeral' }
    })
    const outFile = `${agentId}-passport.json`
    const keyFile = `${agentId}-keys.json`
    writeFileSync(outFile, JSON.stringify(signedPassport, null, 2))
    writeFileSync(keyFile, JSON.stringify(keyPair, null, 2))
    console.log(`✅ Passport created: ${outFile}`)
    console.log(`🔑 Keys saved: ${keyFile} (KEEP SECRET)`)
    break
  }
  case 'verify': {
    const file = args[1]
    if (!file) { console.error('Usage: passport verify <file.json>'); process.exit(1) }
    const data = JSON.parse(readFileSync(file, 'utf8'))
    const result = verifyPassport(data)
    if (result.valid) {
      console.log(`✅ Valid passport for ${result.passport!.agentName} (${result.passport!.agentId})`)
      if (result.warnings.length) console.log(`⚠️ Warnings: ${result.warnings.join(', ')}`)
    } else {
      console.log(`❌ Invalid: ${result.errors.join(', ')}`)
    }
    break
  }
  default:
    console.log('Agent Passport CLI')
    console.log('  passport create <id> <name>  — Create a new agent passport')
    console.log('  passport verify <file.json>  — Verify a passport file')
}
