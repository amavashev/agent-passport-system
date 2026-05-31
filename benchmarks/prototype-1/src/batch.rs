//! L5 batch-amortization workload.
//!
//! Measures the per-action cost of evaluating a fixed batch of Allow
//! actions two ways:
//!
//! - `sequential`: call `aps_check` once per action (the shape a host
//!   gets from N single `check` calls).
//! - `batched`: evaluate the whole slice in one loop holding a single
//!   `VerifierContext` (the shape the napi `check_many` wraps).
//!
//! This is a verifier-core measurement only. It does NOT cross the
//! N-API boundary, so it does not measure the FFI marshalling cost that
//! `check_many` actually amortizes in a JS host. The Rust numbers here
//! bound the per-element verifier work; the FFI amortization is exercised
//! and asserted on the TS side (see `tests/check-many-parity.test.ts`)
//! and would be measured end-to-end only once a `.node` artifact is built
//! on a target runner. No published latency claim is approved from this
//! harness; result JSON is internal pending CLAIMS.md review.

use aps_verifier_core::{
    aps_check, hash_path_component, ActionDescriptor, CompiledAuthority, Decision, ManualClock,
    NullSink, RuntimePassport, Tier, ToolEntry, ToolRegistry, VerifierContext,
};

const TOOL_HEX: &str = "abcd000000000000000000000000000000000000000000000000000000000000";
const SEQ_START: u64 = 1000;
const CLOCK_NS: u64 = 1_779_230_341_000_000_000;

/// Batch sizes swept by the L5 measurement.
pub const BATCH_SIZES: &[usize] = &[1, 8, 64, 512, 4096];

pub struct BatchFixture {
    pub authority: CompiledAuthority,
    pub actions: Vec<ActionDescriptor>,
    clock: ManualClock,
    instance_id_hash: [u8; 32],
    revocation_epoch: u32,
    sink: NullSink,
}

impl BatchFixture {
    /// Build a fixture with `n` pre-finalized Allow actions carrying
    /// consecutive sequence ids starting at `SEQ_START`.
    pub fn build(n: usize) -> Result<Self, String> {
        let tool_hash = hash_from_hex(TOOL_HEX);
        let registry = ToolRegistry::from_entries(vec![ToolEntry {
            descriptor_hash: tool_hash,
            local_id: 0,
        }])
        .map_err(|e| format!("registry: {e}"))?;
        let root_hex = hex_encode(&registry.current_root());
        let json = passport_json(&root_hex, &hex_encode(&tool_hash));
        let passport = RuntimePassport::from_json(&json).map_err(|e| format!("passport: {e}"))?;
        let authority = CompiledAuthority::from_passport(&passport, registry)
            .map_err(|e| format!("compile: {e}"))?;

        let mut template = blank_action();
        template.passport_id_hash = blake3_32("rp_01HX0EXAMPLE000000000000000");
        template.tool_descriptor_hash = tool_hash;
        template.local_tool_id = 0;
        template.operation_id = 0;
        template.risk_class = 2;
        template.resource_path_depth = 1;
        template.resource_path_hashes[0] = hash_path_component("customer");
        template.cost_units = 1;
        template.nonce = [0x55; 16];

        let mut actions = Vec::with_capacity(n);
        for i in 0..n {
            let mut a = template.clone();
            a.sequence_id = SEQ_START + i as u64;
            a.finalize();
            actions.push(a);
        }

        Ok(BatchFixture {
            authority,
            actions,
            clock: ManualClock::new(CLOCK_NS),
            instance_id_hash: blake3_32("vi_01HX0VI00000000000000000000"),
            revocation_epoch: 1842,
            sink: NullSink,
        })
    }

    pub fn context(&self) -> VerifierContext<'_> {
        VerifierContext::with_sink(
            &self.clock,
            self.instance_id_hash,
            Tier::T2,
            self.revocation_epoch,
            &self.sink,
        )
    }

    pub fn reset_sequence(&self) {
        self.authority
            .sequence_next
            .store(SEQ_START, std::sync::atomic::Ordering::Release);
    }
}

/// Evaluate the whole action slice sequentially (one context, one
/// `aps_check` per action). Resets the sequence floor first so the slice
/// is fully replayable.
pub fn run_sequential(fixture: &BatchFixture) -> Vec<Decision> {
    fixture.reset_sequence();
    let ctx = fixture.context();
    fixture
        .actions
        .iter()
        .map(|a| aps_check(&fixture.authority, a, &ctx))
        .collect()
}

/// Evaluate the whole action slice in one batched loop, the exact body
/// the napi `check_many` wraps. Resets the sequence floor first.
pub fn run_batched(fixture: &BatchFixture) -> Vec<Decision> {
    fixture.reset_sequence();
    let ctx = fixture.context();
    let mut out = Vec::with_capacity(fixture.actions.len());
    for a in &fixture.actions {
        out.push(aps_check(&fixture.authority, a, &ctx));
    }
    out
}

// -----------------------------------------------------------------------
// helpers (kept local; mirror workload.rs)
// -----------------------------------------------------------------------

fn blank_action() -> ActionDescriptor {
    ActionDescriptor {
        version: 1,
        reserved: [0; 3],
        passport_id_hash: [0; 32],
        tool_descriptor_hash: [0; 32],
        local_tool_id: 0,
        operation_id: 0,
        resource_type: 0,
        risk_class: 0,
        resource_path_depth: 0,
        reserved2: [0; 2],
        cost_units: 0,
        sequence_id: 0,
        nonce: [0; 16],
        resource_path_hashes: [0; 8],
        action_hash: [0; 32],
    }
}

fn hash_from_hex(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn blake3_32(s: &str) -> [u8; 32] {
    *blake3::hash(s.as_bytes()).as_bytes()
}

fn passport_json(root_hex: &str, tool_hex: &str) -> String {
    format!(
        r#"{{
  "type": "aps.runtime_passport",
  "version": "0.1",
  "passport_id": "rp_01HX0EXAMPLE000000000000000",
  "agent_id": "ag_01HX0AGENT000000000000000000",
  "principal_id": "pr_01HX0PRINCIPAL00000000000000",
  "beneficiary_id": "bn_01HX0BEN00000000000000000000",
  "issuer": "https://gateway.example.test",
  "issued_at": "2026-05-19T22:38:56.000Z",
  "expires_at": "2026-05-19T22:39:56.000Z",
  "max_clock_skew_ms": 1000,
  "policy_epoch": 42,
  "revocation_epoch": 1842,
  "tool_registry_root": "blake3:{root_hex}",
  "delegation_chain_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "effective_authority_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
  "risk_class": "R2",
  "minimum_tier_required": "T2",
  "tier_attested": "T2",
  "verifier_instance_id": "vi_01HX0VI00000000000000000000",
  "verifier_build_hash": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
  "session_id": "sn_01HX0SESS00000000000000000000",
  "sequence_start": 1000,
  "sequence_end": 100000001,
  "budget_lease": {{
    "lease_id": "bl_01HX0LEASE0000000000000000000",
    "max_actions": 4294967295,
    "max_cost_units": 18446744073709551615,
    "sublease_parent": null
  }},
  "authority_blob_encoding": "application/aps-authority+json",
  "authority_blob": {{
    "allowed_tools": ["blake3:{tool_hex}"],
    "allowed_operations": ["read"],
    "resource_scopes": ["customer/*"],
    "approval_rules": []
  }},
  "receipt_stream_id": "rs_01HX0RS00000000000000000000",
  "signature": "ed25519:{sig}"
}}"#,
        sig = "0".repeat(128)
    )
}
