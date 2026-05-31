# aps-sdk-runtime-wasm

WASM build path for the APS Runtime Passport verifier, exposing the
batched `check_many` API for browser and edge runtimes.

This crate exists because the napi binding in `../src/lib.rs` is a
`cdylib` linked against the Node N-API ABI and cannot target
`wasm32-unknown-unknown`. The WASM path here compiles the same
`aps-verifier-core` hot path into a portable module so the batched API
has a runtime that does not depend on Node.

## What it is

- A thin wasm-bindgen surface over `aps_verifier_core::aps_check`.
- `compile_authority(passport_json, tools_json)` parses and compiles a
  passport into a reusable handle (no signature verification in this
  scaffold, matching the napi `load_passport_unverified` path).
- `check_many(handle, actions_json, now_unix_ns)` evaluates a batch of
  actions in one call and returns a JSON array of decisions, one per
  action, in input order.

Every decision comes from `aps_check`; this crate never re-implements
verifier semantics. A WASM `check_many` result is therefore identical to
a native `check_many` result for the same inputs.

## Isolation

This is its own cargo workspace root (see the empty `[workspace]` table
in `Cargo.toml`), so its `wasm-bindgen` dependency is contained to this
sub-package and is not pulled into the repo's root workspace. Building it
touches neither the napi crate nor any other workspace member.

## Build

```sh
./scripts/build-wasm.sh
```

Stage 1 compiles to `wasm32-unknown-unknown` and is verified on this
host: it writes `target/wasm32-unknown-unknown/release/aps_sdk_runtime_wasm.wasm`.

Stage 2 (JS/TS bindings via `wasm-bindgen-cli`) runs only when
`wasm-bindgen` is on `PATH`; otherwise it is skipped and reported. The
JS-loadable bundle is environment-gated on a runner that has
`wasm-bindgen-cli` installed at the matching crate version. It is not
faked.

## Tests

```sh
cargo test --release
```

The unit tests run on the host target (not wasm32) and exercise the same
JSON-parse plus batch-evaluation logic the wasm entry points use,
including a u64-precision check on resource-path hashes above 2^53.

## Proof box

Proves: each action in a `check_many` call is evaluated under the same
policy as a single `check`, via the identical `aps_check` code path
against the same compiled authority and verifier context, in input
order. The batched decision stream is byte-equal to the sequential one.

Does not prove: anything about wall-clock latency on any platform. No
public latency claim is approved from any WASM measurement; any result
artifact is internal pending CLAIMS.md review.

## Time on WASM

`wasm32-unknown-unknown` has no system clock, so `check_many` takes
`now_unix_ns` as a parameter. Time policy stays with the host
embedding the module.
