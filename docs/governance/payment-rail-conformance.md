# Payment Rail Conformance

Any third-party `PaymentRail` adapter (Lightning, USDC, Stripe,
EVM-stablecoin, custom rail) can claim conformance to the APS
governance contract by passing the standard scenario suite under
`src/v2/payment-rails/conformance/`.

The harness is to payment rails what `tests/interop/*-vectors.test.ts`
is to delegation primitives: a closed, byte-pinned suite that adapter
authors run to prove their implementation honours the same contract
as the reference (Nano) impl shipped in this repo.

## What conformance asserts

The contract has four parts. Each scenario exercises one of them:

1. **Pre-authorization gating** — `GovernanceHooks.preAuthorize` MUST
   accept exactly when a delegation has the required scope, the
   amount is within budget, the wallet is live, and the call falls
   inside `[not_before, not_after]`. Any other case MUST deny with a
   denial reason from the closed taxonomy
   (`no_commerce_scope | spend_limit_exceeded | wallet_revoked |
   time_window_violation | rail_error`).

2. **Receipt emission** — `GovernanceHooks.emitReceipt` MUST produce
   a `PaymentReceipt` with claim type `aps:payment_receipt:v1`, a
   stable `receipt_id` (sha256 hex of the canonical JCS body), and a
   valid Ed25519 signature over the canonical bytes.

3. **Denial emission** — `GovernanceHooks.emitDenial` MUST produce a
   signed `PaymentDenial` whose `denial_reason` is in the closed
   taxonomy.

4. **Revocation** — `PaymentRail.revokeWallet(walletId)` MUST stop
   subsequent operations bound to that wallet. Idempotent on repeat.

## Standard scenarios

| ID      | What it asserts                                                                            |
| ------- | ------------------------------------------------------------------------------------------ |
| SCN-001 | preAuthorize accepts when scope matches and amount is within budget                        |
| SCN-002 | preAuthorize denies with `no_commerce_scope` when required scope absent                    |
| SCN-003 | preAuthorize denies with `spend_limit_exceeded` when amount exceeds budget                 |
| SCN-004 | preAuthorize denies with `wallet_revoked` when bound wallet is revoked                     |
| SCN-005 | preAuthorize denies with `time_window_violation` after `not_after` expiry                  |
| SCN-006 | emitReceipt produces a receipt with valid Ed25519 signature                                |
| SCN-007 | emitReceipt output round-trips through JSON canonicalization and verifies clean            |
| SCN-008 | emitDenial produces a denial with valid Ed25519 signature                                  |
| SCN-009 | revokeWallet halts subsequent preAuthorize calls bound to that wallet (idempotent)         |
| SCN-010 | emitted receipt's `delegation_ref` equals the input delegation receipt_id                  |

## Using the harness

Programmatically:

```ts
import {
  createDefaultGovernanceHooks,
  runConformance,
} from '@aeoess/agent-passport-system'
import { myRail } from './my-rail.js'

const hooks = createDefaultGovernanceHooks()
const report = await runConformance(myRail, hooks)

if (!report.all_pass) {
  for (const s of report.scenarios.filter((s) => !s.pass)) {
    console.error(`${s.id} failed: ${s.reason}`)
  }
  process.exit(1)
}
```

`runConformance` never throws on scenario failure — failures land
inside the returned report so you can render the result however you
like (JSON, console, CI annotation).

## Using the verifier CLI

For one-shot runs, use the bundled CLI:

```bash
node  scripts/verify-payment-rail-conformance.mjs <rail-module-path>
npx tsx scripts/verify-payment-rail-conformance.mjs <rail-module-path>   # for TS adapters
```

Flags:

- `--json`  emit the full `ConformanceReport` as JSON on stdout
- `--quiet` skip per-scenario lines, print only the summary

Exit code: `0` on all-pass, `1` on any-fail or any module load error.

The rail module MUST export the rail (and optionally the hooks) in
one of these shapes:

1. `default = { rail, hooks? }`
2. `default = () => Promise<{ rail, hooks? }> | { rail, hooks? }`
3. named exports `rail` + optional `hooks`
4. named export `setup()` returning `{ rail, hooks? }`
5. named export `createRail()` factory (hooks default to
   `createDefaultGovernanceHooks()`)

## Interpreting the report

```ts
interface ConformanceReport {
  rail_name: string
  rail_currency: string
  started_at: string
  finished_at: string
  total: number
  passed: number
  failed: number
  all_pass: boolean
  scenarios: ScenarioReport[]
}

interface ScenarioReport {
  id: string
  description: string
  pass: boolean
  reason?: string  // populated only on failure
  duration_ms: number
}
```

A failed scenario carries a `reason` string that names what diverged
from the contract. Common shapes:

- `expected denial_reason=X, got Y` — the rail returned the wrong
  taxonomy member.
- `expected denial, got ok` — gating let through a request that
  should have been blocked.
- `signature length=…` / `receipt_id length=…` — emit produced the
  wrong canonical shape.
- `verifyPaymentReceipt failed: SIGNATURE_INVALID` — bytes don't
  round-trip; usually a canonicalization bug.

## Claiming conformance

To claim conformance in your adapter's README:

1. **Pin a fixture set version.** The canonical inputs and expected
   outputs live under
   `src/v2/payment-rails/conformance/fixtures/META.json`. Read its
   `schema_version` and pin to that version.
2. **Run the verifier.** Build (or run via `tsx`) and execute:
   ```bash
   npx tsx scripts/verify-payment-rail-conformance.mjs <your-rail-module>
   ```
3. **Capture the report.** Save the verifier's `--json` output as
   `conformance-report.json` and post it (or a summary) in your
   adapter's README. Include the SDK version, the fixture
   `schema_version` you pinned, and the `started_at` timestamp.
4. **Re-verify on bumps.** When this SDK bumps its fixture
   `schema_version` (breaking shape change), re-run the verifier and
   update the pinned version in your README.

## Reference command

The Nano adapter shipped in this repo is the conformance reference.
You can confirm it passes with:

```bash
npx tsx scripts/verify-payment-rail-conformance.mjs \
  scripts/_payment-rail-nano-reference.ts
```

Expected output ends with `ALL PASS  10/10 scenarios passed (0 failed)`
and exit code `0`.
