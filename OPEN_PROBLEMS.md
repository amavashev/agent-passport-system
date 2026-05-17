# Open Problems

APS is an open protocol for agent identity, scoped authority, enforcement, receipts, and attribution.

The agent economy should not be built as a world of strangers guessing whether they can trust each other. It should be built so strangers, agents, and organizations can work together safely because authority, scope, and outcomes are verifiable. That principle applies to this project too.

You do not need prior status or private access to contribute. Start with a problem. Bring an artifact. Make it reproducible. State what it proves and what it does not prove. Keep contributor-controlled services out of conformance.

Unknown is not hostile. Unverified is not canonical. A contribution can be valuable without becoming canonical. More contributors now work with agents and automation; this project judges the artifact, not the account.

This page lists problems where outside contributors, agent teams, researchers, and builders can move APS forward.

## Starter problems

Receipt verification example in a language or runtime not yet covered.
Negative-path fixtures: expired delegation, revoked authority, over-budget execution, wrong principal, invalid receipt signature, stale policy, replayed receipt, mismatched action hash.
A diagram that explains monotonic authority narrowing.
A local, offline receipt viewer.
A minimal adapter example for an agent runtime.

## Intermediate problems

Third-substrate Ed25519 and canonical-JSON byte-parity vectors.
Delegation-chain narrowing tests.
Receipt-misuse examples: a valid receipt used to claim something it does not prove.
Receipt verification inside an MCP flow.
Cross-runtime validation of the same receipt.

## Hard problems, open research

These are genuinely unsolved. Honest partial progress is welcome.
Collusion-resistant attribution.
Witness and oracle diversity, where three APIs from one vendor count as one witness.
A state-reversion taxonomy for irreversible actions.
Evidence handling for non-deterministic evaluation.
Values-floor evasion.
Attribution under multi-agent delegation.

## How to take a problem

Pick one or propose one. Bring a self-contained, reproducible artifact. Say what it proves and what it does not. If it proves something useful, we credit it and review it for promotion. Open entry does not mean automatic promotion, and non-promotion is not rejection.
