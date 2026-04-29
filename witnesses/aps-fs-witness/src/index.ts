#!/usr/bin/env node
// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// aps-fs-witness — CLI entry (one-shot only in v0; no watch mode)
// ══════════════════════════════════════════════════════════════════

import { isAbsolute, resolve } from 'node:path'

import {
  DEFAULT_KEY_PATH,
  loadOrCreateWitnessKey,
  produceWitnessedContextRoot,
} from './witness.js'
import type { FilesystemMode, WitnessIndependenceLevel } from './types.js'

interface CliArgs {
  workingRoot: string
  discoveryPatterns: string[]
  filesystemMode: FilesystemMode
  independenceLevel: WitnessIndependenceLevel
  once: boolean
  keyPath: string
}

function parseArgs(argv: string[]): CliArgs {
  let workingRoot: string | undefined
  let discoveryPatterns: string[] | undefined
  let filesystemMode: FilesystemMode = 'case-sensitive'
  let independenceLevel: WitnessIndependenceLevel = 'separate-process'
  let once = false
  let keyPath = DEFAULT_KEY_PATH

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    switch (a) {
      case '--working-root':
        workingRoot = argv[++i]
        break
      case '--discovery-patterns':
        discoveryPatterns = (argv[++i] ?? '').split(',').map(s => s.trim()).filter(Boolean)
        break
      case '--filesystem-mode':
        filesystemMode = argv[++i] as FilesystemMode
        break
      case '--independence-level':
        independenceLevel = argv[++i] as WitnessIndependenceLevel
        break
      case '--key-path':
        keyPath = argv[++i]
        break
      case '--once':
        once = true
        break
      case '--help':
      case '-h':
        printUsageAndExit(0)
      default:
        console.error(`unknown argument: ${a}`)
        printUsageAndExit(2)
    }
  }

  if (!workingRoot) {
    console.error('--working-root is required')
    printUsageAndExit(2)
  }
  if (!discoveryPatterns || discoveryPatterns.length === 0) {
    console.error('--discovery-patterns is required (comma-separated list)')
    printUsageAndExit(2)
  }
  if (!once) {
    // v0 only supports one-shot. Surface this clearly so a future watch
    // mode is added explicitly rather than implied by absence of --once.
    console.error('aps-fs-witness v0 requires --once (no watch mode in this version)')
    printUsageAndExit(2)
  }
  const absRoot = isAbsolute(workingRoot!) ? workingRoot! : resolve(workingRoot!)
  if (filesystemMode !== 'case-sensitive' && filesystemMode !== 'case-insensitive') {
    console.error(`invalid --filesystem-mode: ${filesystemMode}`)
    printUsageAndExit(2)
  }
  return {
    workingRoot: absRoot,
    discoveryPatterns: discoveryPatterns!,
    filesystemMode,
    independenceLevel,
    once,
    keyPath,
  }
}

function printUsageAndExit(code: number): never {
  const usage = [
    'aps-fs-witness — independent filesystem witness for APS IPR.',
    '',
    'Usage:',
    '  aps-fs-witness --once \\',
    '    --working-root <abs path> \\',
    '    --discovery-patterns "<glob1>,<glob2>,..." \\',
    '    [--filesystem-mode case-sensitive|case-insensitive] \\',
    '    [--independence-level separate-process|separate-host|separate-operator] \\',
    '    [--key-path <path>]',
    '',
    'Outputs a signed WitnessedContextRoot JSON envelope to stdout.',
    `Witness key default path: ${DEFAULT_KEY_PATH}`,
  ].join('\n')
  console.error(usage)
  process.exit(code)
}

function main(): void {
  const args = parseArgs(process.argv.slice(2))
  const key = loadOrCreateWitnessKey({ keyPath: args.keyPath })
  const envelope = produceWitnessedContextRoot({
    workingRoot: args.workingRoot,
    discoveryPatterns: args.discoveryPatterns,
    filesystemMode: args.filesystemMode,
    independenceLevel: args.independenceLevel,
    key,
  })
  process.stdout.write(JSON.stringify(envelope, null, 2) + '\n')
}

main()
