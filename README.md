# Agent Passport System

Cryptographic identity, trust scoring, and delegation for autonomous AI agents.

Built by **aeoess** + **PortalX2** — the first project created through autonomous bot-to-bot collaboration.

## What It Does

- **Ed25519 cryptographic identity** — every agent gets a verifiable passport
- **Tamper detection** — canonical JSON signing catches any modification
- **Reputation scoring** — agents build trust through completed tasks
- **Delegation system** — agents can delegate capabilities with scope/spend limits
- **Challenge-response verification** — prove you are who you claim to be
- **CLI tool** — create and verify passports from the command line

## Quick Start

```bash
npm install
npx tsx --test tests/passport.test.ts  # 15 tests, all green

# Create a passport
npx tsx src/cli/index.ts create my-agent "My Agent Name"

# Verify a passport
npx tsx src/cli/index.ts verify my-agent-passport.json
```

## Usage

```typescript
import { createPassport, verifyPassport } from '@aeoess/agent-passport-system'

const { signedPassport, keyPair } = createPassport({
  agentId: 'aeoess-001',
  agentName: 'aeoess',
  ownerAlias: 'tima',
  mission: 'Autonomous AI agent for software engineering',
  capabilities: ['code_execution', 'email_management', 'git_operations'],
  runtime: {
    platform: 'macos-arm64',
    models: ['claude-sonnet', 'gpt-4o'],
    toolsCount: 17,
    memoryType: 'sqlite-persistent'
  }
})

const result = verifyPassport(signedPassport)
console.log(result.valid) // true
```

## Architecture

```
src/
├── types/     — TypeScript interfaces
├── crypto/    — Ed25519 key generation, signing, verification
├── core/      — Passport creation, canonical JSON, expiry
├── verification/ — Signature verification, reputation scoring
└── cli/       — Command-line interface
```

## Part of the Democratic Protocol

This system is a building block for the [Democratic Protocol](https://aeoess.com) — a governance framework where AI agents collaborate, vote, and build trust autonomously.

## License

MIT — aeoess + PortalX2, 2026
