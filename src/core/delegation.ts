// Delegation System — create, verify, revoke, and enforce depth limits
// v1.1: Action Receipts + Revocation + Depth Limits

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type {
  Delegation, ActionReceipt, RevocationRecord, DelegationStatus
} from '../types/passport.js'

// In-memory revocation registry (in production, this would be persistent)
const revocationRegistry = new Map<string, RevocationRecord>()

// In-memory receipt store
const receiptStore: ActionReceipt[] = []

// ══════════════════════════════════════
// DELEGATION CREATION
// ══════════════════════════════════════

export interface CreateDelegationOptions {
  delegatedTo: string       // public key of delegate
  delegatedBy: string       // public key of delegator
  scope: string[]
  spendLimit?: number
  maxDepth?: number
  currentDepth?: number
  expiresInHours?: number
  privateKey: string        // delegator's private key for signing
}

export function createDelegation(opts: CreateDelegationOptions): Delegation {
  const now = new Date()
  const expiry = new Date(now)
  expiry.setHours(expiry.getHours() + (opts.expiresInHours || 24))

  const delegation: Omit<Delegation, 'signature'> = {
    delegationId: 'del_' + uuidv4().slice(0, 12),
    delegatedTo: opts.delegatedTo,
    delegatedBy: opts.delegatedBy,
    scope: opts.scope,
    expiresAt: expiry.toISOString(),
    spendLimit: opts.spendLimit,
    spentAmount: 0,
    maxDepth: opts.maxDepth ?? 1,
    currentDepth: opts.currentDepth ?? 0,
    createdAt: now.toISOString()
  }

  const canonical = canonicalize(delegation)
  const signature = sign(canonical, opts.privateKey)

  return { ...delegation, signature }
}

// ══════════════════════════════════════
// SUB-DELEGATION (with depth enforcement)
// ══════════════════════════════════════

export interface SubDelegateOptions {
  parentDelegation: Delegation
  delegatedTo: string     // public key of new delegate
  scope: string[]         // must be subset of parent scope
  spendLimit?: number     // must be <= parent remaining
  privateKey: string      // current delegate's private key
}

export function subDelegate(opts: SubDelegateOptions): Delegation {
  const parent = opts.parentDelegation

  // Enforce depth limit — new delegation would be at parent.currentDepth + 1
  const newDepth = parent.currentDepth + 1
  if (newDepth > parent.maxDepth) {
    throw new Error(
      `Depth limit exceeded: would be depth ${newDepth}, max allowed is ${parent.maxDepth}`
    )
  }

  // Enforce scope narrowing
  const invalidScopes = opts.scope.filter(s => !parent.scope.includes(s))
  if (invalidScopes.length > 0) {
    throw new Error(
      `Scope violation: [${invalidScopes}] not in parent scope [${parent.scope}]`
    )
  }

  // Enforce spend limit
  const parentRemaining = (parent.spendLimit || Infinity) - (parent.spentAmount || 0)
  if (opts.spendLimit && opts.spendLimit > parentRemaining) {
    throw new Error(
      `Spend limit ${opts.spendLimit} exceeds parent remaining ${parentRemaining}`
    )
  }

  return createDelegation({
    delegatedTo: opts.delegatedTo,
    delegatedBy: parent.delegatedTo, // the current delegate becomes delegator
    scope: opts.scope,
    spendLimit: opts.spendLimit || parentRemaining,
    maxDepth: parent.maxDepth,
    currentDepth: parent.currentDepth + 1,
    expiresInHours: 24,
    privateKey: opts.privateKey
  })
}

// ══════════════════════════════════════
// DELEGATION VERIFICATION
// ══════════════════════════════════════

export function verifyDelegation(delegation: Delegation): DelegationStatus {
  const errors: string[] = []

  // Check signature
  const { signature, ...unsigned } = delegation
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, delegation.delegatedBy)
  if (!sigValid) errors.push('Invalid delegation signature')

  // Check expiry
  const expired = new Date(delegation.expiresAt) < new Date()
  if (expired) errors.push('Delegation expired')

  // Check revocation
  const revocation = revocationRegistry.get(delegation.delegationId)
  const revoked = !!revocation

  if (revoked) errors.push(`Revoked at ${revocation!.revokedAt}: ${revocation!.reason}`)

  // Check depth
  const depthExceeded = delegation.currentDepth > delegation.maxDepth
  if (depthExceeded) errors.push('Depth limit exceeded')

  return {
    valid: errors.length === 0,
    revoked,
    expired,
    depthExceeded,
    revokedAt: revocation?.revokedAt,
    errors
  }
}

// ══════════════════════════════════════
// REVOCATION
// ══════════════════════════════════════

export function revokeDelegation(
  delegationId: string,
  revokedBy: string,
  reason: string,
  privateKey: string
): RevocationRecord {
  const record: Omit<RevocationRecord, 'signature'> = {
    revocationId: 'rev_' + uuidv4().slice(0, 12),
    delegationId,
    revokedBy,
    revokedAt: new Date().toISOString(),
    reason
  }

  const canonical = canonicalize(record)
  const signature = sign(canonical, privateKey)
  const revocation = { ...record, signature }

  // Store in registry
  revocationRegistry.set(delegationId, revocation)
  return revocation
}

export function verifyRevocation(revocation: RevocationRecord): boolean {
  const { signature, ...unsigned } = revocation
  const canonical = canonicalize(unsigned)
  return verify(canonical, signature, revocation.revokedBy)
}

// ══════════════════════════════════════
// ACTION RECEIPTS
// ══════════════════════════════════════

export interface CreateReceiptOptions {
  agentId: string
  delegationId: string
  delegation: Delegation       // for chain verification
  action: ActionReceipt['action']
  result: ActionReceipt['result']
  delegationChain: string[]    // public keys from principal to executor
  privateKey: string           // executing agent's private key
}

export function createReceipt(opts: CreateReceiptOptions): ActionReceipt {
  // Verify delegation is still valid
  const status = verifyDelegation(opts.delegation)
  if (!status.valid) {
    throw new Error(`Cannot create receipt: delegation invalid — ${status.errors.join(', ')}`)
  }

  // Verify scope
  if (!opts.delegation.scope.includes(opts.action.scopeUsed)) {
    throw new Error(
      `Scope '${opts.action.scopeUsed}' not in delegation [${opts.delegation.scope}]`
    )
  }

  // Verify spend
  if (opts.action.spend) {
    const remaining = (opts.delegation.spendLimit || Infinity) -
      (opts.delegation.spentAmount || 0)
    if (opts.action.spend.amount > remaining) {
      throw new Error(
        `Spend ${opts.action.spend.amount} exceeds remaining ${remaining}`
      )
    }
  }

  const receipt: Omit<ActionReceipt, 'signature'> = {
    receiptId: 'rcpt_' + uuidv4().slice(0, 12),
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId: opts.agentId,
    delegationId: opts.delegationId,
    action: opts.action,
    result: opts.result,
    delegationChain: opts.delegationChain
  }

  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.privateKey)
  const signedReceipt = { ...receipt, signature }

  // Store receipt
  receiptStore.push(signedReceipt)

  return signedReceipt
}

export function verifyReceipt(
  receipt: ActionReceipt,
  agentPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = receipt
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, agentPublicKey)
  if (!sigValid) errors.push('Invalid receipt signature')

  if (receipt.version !== '1.1') errors.push('Unsupported receipt version')

  return { valid: errors.length === 0, errors }
}

// Getters
export function getReceipts(agentId?: string): ActionReceipt[] {
  if (agentId) return receiptStore.filter(r => r.agentId === agentId)
  return [...receiptStore]
}

export function getRevocation(delegationId: string): RevocationRecord | undefined {
  return revocationRegistry.get(delegationId)
}

export function clearStores(): void {
  revocationRegistry.clear()
  receiptStore.length = 0
}
