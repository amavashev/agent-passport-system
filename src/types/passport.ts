// Agent Passport System — Type Definitions

export interface KeyPair {
  privateKey: string  // hex-encoded Ed25519 private key
  publicKey: string   // hex-encoded Ed25519 public key
}

export interface AgentPassport {
  version: string
  agentId: string
  agentName: string
  ownerAlias: string
  publicKey: string
  mission: string
  capabilities: string[]
  runtime: RuntimeInfo
  createdAt: string
  expiresAt: string
  voteWeight: number
  reputation: ReputationScore
  delegations: Delegation[]
  metadata: Record<string, unknown>
}

export interface RuntimeInfo {
  platform: string
  models: string[]
  toolsCount: number
  memoryType: string
}

export interface ReputationScore {
  overall: number
  collaborationsCompleted: number
  proposalsSubmitted: number
  proposalsApproved: number
  tokensContributed: number
  tasksCompleted: number
  lastUpdated: string
}

export interface Delegation {
  delegationId: string
  delegatedTo: string
  delegatedBy: string
  scope: string[]
  expiresAt: string
  spendLimit?: number
  spentAmount?: number
  maxDepth: number
  currentDepth: number
  createdAt: string
  signature: string  // signed by delegator
}

export interface ActionReceipt {
  receiptId: string
  version: string
  timestamp: string
  agentId: string
  delegationId: string
  action: {
    type: string
    target: string
    method?: string
    scopeUsed: string
    spend?: { amount: number; currency: string }
  }
  result: {
    status: 'success' | 'failure' | 'partial'
    summary: string
  }
  delegationChain: string[]  // public key fingerprints from principal to executor
  signature: string  // signed by executing agent
}

export interface RevocationRecord {
  revocationId: string
  delegationId: string
  revokedBy: string   // public key of original delegator
  revokedAt: string
  reason: string
  signature: string   // signed by original delegator
}

export interface DelegationStatus {
  valid: boolean
  revoked: boolean
  expired: boolean
  depthExceeded: boolean
  revokedAt?: string
  errors: string[]
}

export interface SignedPassport {
  passport: AgentPassport
  signature: string
  signedAt: string
}

export interface VerificationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
  passport?: AgentPassport
}

export interface Challenge {
  challengeId: string
  nonce: string
  timestamp: string
  expiresAt: string
}

export interface ChallengeResponse {
  challengeId: string
  signature: string
  publicKey: string
}

export interface ReputationEvent {
  type: 'collaboration_completed' | 'proposal_submitted' | 'proposal_approved' |
        'tokens_contributed' | 'task_completed' | 'task_failed' | 'incident'
  quality?: number  // 0-1
  amount?: number
}

export interface CreatePassportOptions {
  agentId: string
  agentName: string
  ownerAlias: string
  mission: string
  capabilities: string[]
  runtime: RuntimeInfo
  expiresInDays?: number
  delegations?: Delegation[]
  metadata?: Record<string, unknown>
}
