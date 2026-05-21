//! HKDF-SHA256 receipt-stream-key derivation tests.
//!
//! Five test groups per the HKDF-DERIVATION-DESIGN memo:
//! 1. RFC 5869 KAT vectors (A.1, A.2, A.3) for HKDF-SHA256.
//! 2. Per-input variation (one test per derivation input).
//! 3. Determinism (same inputs always produce same output).
//! 4. End-to-end recovery (real passport + log + mutate inputs).
//! 5. Negative (random valid signatures produce non-zero keys).

mod common;

use std::path::PathBuf;

use ed25519_dalek::Signer;
use hkdf::Hkdf;
use sha2::Sha256;
use tempfile::TempDir;

use aps_verifier_core::{
    derive_receipt_stream_key, recover_log, CompiledAuthority, LogWriter, RecoveryError,
    RecoveryStatus, RuntimePassport, ToolEntry, ToolRegistry,
};

use common::{hash_from_hex, hex_encode, hex_encode_64, PassportBuilder};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn happy_registry() -> ToolRegistry {
    ToolRegistry::from_entries(vec![ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap()
}

/// Build a real signed passport using the test gateway keypair. The
/// resulting JSON parses back to a `RuntimePassport` with a valid
/// 64-byte signature that `decode_signature` accepts, which is what
/// `from_passport` needs to derive the receipt stream key.
fn happy_signed_passport(
    sequence_start: u64,
    sequence_end: u64,
    delegation_chain_hash: [u8; 32],
    receipt_stream_id: &str,
    revocation_epoch: u32,
) -> (RuntimePassport, String) {
    let (signing_key, _) = common::test_gateway_keypair();
    let root = happy_registry().current_root();
    let builder = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        .with_sequence_window(sequence_start, sequence_end)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .with_delegation_chain_hash(delegation_chain_hash)
        .with_receipt_stream_id(receipt_stream_id)
        .with_revocation_epoch(revocation_epoch);
    let json = builder.build_signed_json(&signing_key);
    let passport = RuntimePassport::from_json(&json).unwrap();
    (passport, json)
}

/// Re-implement the derivation chain a caller would do given a
/// parsed passport. Used by the end-to-end recovery test to compute
/// the MAC key that will validate the log we wrote.
fn derive_key_for(passport: &RuntimePassport) -> [u8; 32] {
    let sig = strip_prefix_hex(&passport.signature);
    let sig_bytes = hex_to_64(sig);
    let dch = strip_prefix_hex(&passport.delegation_chain_hash);
    let dch_bytes = hex_to_32(dch);
    let vi_hash = *blake3::hash(passport.verifier_instance_id.as_bytes()).as_bytes();
    derive_receipt_stream_key(
        &sig_bytes,
        &vi_hash,
        &dch_bytes,
        &passport.receipt_stream_id,
        passport.revocation_epoch,
    )
}

fn strip_prefix_hex(s: &str) -> &str {
    match s.split_once(':') {
        Some((_, rest)) => rest,
        None => s,
    }
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_to_64(s: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// -----------------------------------------------------------------------
// 1. RFC 5869 KAT vectors (HKDF-SHA256 primitive integration)
// -----------------------------------------------------------------------

/// RFC 5869 Appendix A.1: Test Case 1 (HKDF-SHA256, basic).
#[test]
fn rfc5869_a1_hkdf_sha256_basic() {
    let ikm = [0x0b_u8; 22];
    let salt = hex_to_vec("000102030405060708090a0b0c");
    let info = hex_to_vec("f0f1f2f3f4f5f6f7f8f9");
    let expected_prk =
        hex_to_vec("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let expected_okm = hex_to_vec(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
    );

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut prk = [0u8; 32];
    let hk_extract_only = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    prk.copy_from_slice(hk_extract_only.0.as_slice());
    assert_eq!(prk.as_slice(), expected_prk.as_slice(), "A.1 PRK");

    let mut okm = vec![0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, expected_okm, "A.1 OKM");
}

/// RFC 5869 Appendix A.2: Test Case 2 (HKDF-SHA256, longer inputs/outputs).
#[test]
fn rfc5869_a2_hkdf_sha256_longer() {
    let ikm = hex_to_vec(
        "000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f\
         303132333435363738393a3b3c3d3e3f\
         404142434445464748494a4b4c4d4e4f",
    );
    let salt = hex_to_vec(
        "606162636465666768696a6b6c6d6e6f\
         707172737475767778797a7b7c7d7e7f\
         808182838485868788898a8b8c8d8e8f\
         909192939495969798999a9b9c9d9e9f\
         a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    );
    let info = hex_to_vec(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
         c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
         d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
         e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
         f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );
    let expected_prk =
        hex_to_vec("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    let expected_okm = hex_to_vec(
        "b11e398dc80327a1c8e7f78c596a4934\
         4f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09\
         da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f\
         1d87",
    );

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let extract = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(extract.0.as_slice(), expected_prk.as_slice(), "A.2 PRK");

    let mut okm = vec![0u8; 82];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, expected_okm, "A.2 OKM");
}

/// RFC 5869 Appendix A.3: Test Case 3 (HKDF-SHA256, zero-length salt and info).
#[test]
fn rfc5869_a3_hkdf_sha256_empty_salt_info() {
    let ikm = [0x0b_u8; 22];
    let salt: &[u8] = &[];
    let info: &[u8] = &[];
    let expected_prk =
        hex_to_vec("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    let expected_okm = hex_to_vec(
        "8da4e775a563c18f715f802a063c5a31\
         b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8",
    );

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let extract = Hkdf::<Sha256>::extract(Some(salt), &ikm);
    assert_eq!(extract.0.as_slice(), expected_prk.as_slice(), "A.3 PRK");

    let mut okm = vec![0u8; 42];
    hk.expand(info, &mut okm).unwrap();
    assert_eq!(okm, expected_okm, "A.3 OKM");
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
    }
    out
}

// -----------------------------------------------------------------------
// 2. Per-input variation (one test per derivation input)
// -----------------------------------------------------------------------

fn baseline_inputs() -> ([u8; 64], [u8; 32], [u8; 32], String, u32) {
    let mut sig = [0u8; 64];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut vi = [0u8; 32];
    for (i, b) in vi.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x40);
    }
    let mut dch = [0u8; 32];
    for (i, b) in dch.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x80);
    }
    (sig, vi, dch, "rs_baseline".into(), 7)
}

#[test]
fn varies_with_signature() {
    let (mut sig, vi, dch, sid, ep) = baseline_inputs();
    let a = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    sig[0] ^= 1;
    let b = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    assert_ne!(a, b, "different signature bytes must produce different keys");
}

#[test]
fn varies_with_verifier_instance_id_hash() {
    let (sig, mut vi, dch, sid, ep) = baseline_inputs();
    let a = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    vi[0] ^= 1;
    let b = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    assert_ne!(a, b, "different verifier_instance_id_hash must produce different keys");
}

#[test]
fn varies_with_delegation_chain_hash() {
    let (sig, vi, mut dch, sid, ep) = baseline_inputs();
    let a = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    dch[0] ^= 1;
    let b = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    assert_ne!(a, b, "different delegation_chain_hash must produce different keys");
}

#[test]
fn varies_with_receipt_stream_id() {
    let (sig, vi, dch, _sid, ep) = baseline_inputs();
    let a = derive_receipt_stream_key(&sig, &vi, &dch, "rs_a", ep);
    let b = derive_receipt_stream_key(&sig, &vi, &dch, "rs_b", ep);
    assert_ne!(a, b, "different receipt_stream_id must produce different keys");
}

#[test]
fn varies_with_revocation_epoch() {
    let (sig, vi, dch, sid, _ep) = baseline_inputs();
    let a = derive_receipt_stream_key(&sig, &vi, &dch, &sid, 1);
    let b = derive_receipt_stream_key(&sig, &vi, &dch, &sid, 2);
    assert_ne!(a, b, "different revocation_epoch must produce different keys");
}

// -----------------------------------------------------------------------
// 3. Determinism
// -----------------------------------------------------------------------

#[test]
fn deterministic_across_calls() {
    let (sig, vi, dch, sid, ep) = baseline_inputs();
    let a = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    let b = derive_receipt_stream_key(&sig, &vi, &dch, &sid, ep);
    assert_eq!(a, b, "same inputs must produce byte-identical output");
}

// -----------------------------------------------------------------------
// 4. End-to-end recovery (derive in real passport, write log, recover)
// -----------------------------------------------------------------------

#[test]
fn end_to_end_recovery_clean_with_derived_key() {
    let tmp = TempDir::new().unwrap();
    let log_path: PathBuf = tmp.path().join("receipts.log");

    let dch = hash_from_hex("aaaa000000000000000000000000000000000000000000000000000000000001");
    let (passport, _json) =
        happy_signed_passport(1000, 2000, dch, "rs_canon_a", 1842);
    let mac_key = derive_key_for(&passport);

    // Sanity: derived key matches what from_passport stored.
    let auth = CompiledAuthority::from_passport(&passport, happy_registry()).unwrap();
    assert_eq!(auth.receipt_stream_key, mac_key, "from_passport stores derived key");

    // Write log entries with the derived key.
    write_log(&log_path, &mac_key, 1000, 5);

    // Reopen with from_passport_with_recovery using the same key.
    let (_auth2, report) = CompiledAuthority::from_passport_with_recovery(
        &passport,
        &happy_registry(),
        &log_path,
        mac_key,
    )
    .unwrap();
    assert_eq!(report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(report.entries_recovered, 5);
    assert_eq!(report.last_committed_sequence_id, 1004);
}

#[test]
fn end_to_end_recovery_breaks_when_signature_mutated() {
    end_to_end_mac_mismatch_after_mutation(|json| {
        // Flip one hex nibble inside the signature's hex (after the prefix).
        mutate_field_hex(json, "signature", "ed25519:")
    });
}

#[test]
fn end_to_end_recovery_breaks_when_delegation_chain_hash_mutated() {
    end_to_end_mac_mismatch_after_mutation(|json| {
        mutate_field_hex(json, "delegation_chain_hash", "sha256:")
    });
}

#[test]
fn end_to_end_recovery_breaks_when_receipt_stream_id_mutated() {
    end_to_end_mac_mismatch_after_mutation(|json| {
        replace_string_field(json, "receipt_stream_id", "rs_canon_a", "rs_canon_b")
    });
}

#[test]
fn end_to_end_recovery_breaks_when_revocation_epoch_mutated() {
    end_to_end_mac_mismatch_after_mutation(|json| {
        replace_number_field(json, "revocation_epoch", 1842, 1843)
    });
}

/// Workhorse for the four mutation tests. Build a real signed
/// passport, derive the MAC key, write a log with that key,
/// regenerate the passport JSON with one field mutated, parse it as
/// a passport (bypass signature verify since we're testing the MAC
/// key derivation, not Ed25519), derive a new MAC key from the
/// mutated passport, attempt recovery with the new key against the
/// old log, expect MacMismatch.
fn end_to_end_mac_mismatch_after_mutation<F: FnOnce(&str) -> String>(mutate: F) {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("receipts.log");

    let dch = hash_from_hex("bbbb000000000000000000000000000000000000000000000000000000000002");
    let (passport, json) =
        happy_signed_passport(1000, 2000, dch, "rs_canon_a", 1842);
    let mac_key = derive_key_for(&passport);
    write_log(&log_path, &mac_key, 1000, 3);

    let mutated_json = mutate(&json);
    let mutated_passport = RuntimePassport::from_json(&mutated_json).expect("re-parse mutated");
    let mutated_key = derive_key_for(&mutated_passport);
    assert_ne!(mac_key, mutated_key, "mutation must change derived key");

    match recover_log(&log_path, mutated_key) {
        Err(RecoveryError::InitialMacFailure) => {}
        other => panic!("expected InitialMacFailure on mutated key, got {other:?}"),
    }
}

fn write_log(path: &std::path::Path, mac_key: &[u8; 32], start_seq: u64, n: u64) {
    use aps_verifier_core::{Decision, DecisionType, ReasonCode};
    let mut w = LogWriter::open(path, *mac_key).unwrap();
    for i in 0..n {
        let d = Decision {
            decision_type: DecisionType::Allow,
            reason_code: ReasonCode::Ok,
            reserved: [0; 6],
            sequence_id: start_seq + i,
            decision_id: [0; 16],
            event_mac: [0; 32],
        };
        w.append(&d).unwrap();
    }
    w.flush().unwrap();
}

fn mutate_field_hex(json: &str, field: &str, prefix: &str) -> String {
    // serde_json round-trip so we're whitespace-independent.
    let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
    let obj = value.as_object_mut().unwrap();
    let cur = obj.get(field).and_then(|v| v.as_str()).expect("field present").to_string();
    let hex_part = cur.strip_prefix(prefix).expect("prefix present");
    let mut bytes = hex_part.as_bytes().to_vec();
    let target = bytes.len() - 1;
    bytes[target] = match bytes[target] {
        b'0' => b'1',
        b'1'..=b'9' => bytes[target] - 1,
        b'a' => b'b',
        b'b'..=b'f' => bytes[target] - 1,
        b => b,
    };
    let new_hex = String::from_utf8(bytes).unwrap();
    obj.insert(
        field.into(),
        serde_json::Value::String(format!("{prefix}{new_hex}")),
    );
    serde_json::to_string(&value).unwrap()
}

fn replace_string_field(json: &str, field: &str, _old: &str, new: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert(field.into(), serde_json::Value::String(new.into()));
    serde_json::to_string(&value).unwrap()
}

fn replace_number_field(json: &str, field: &str, _old: u64, new: u64) -> String {
    let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert(field.into(), serde_json::Value::Number(new.into()));
    serde_json::to_string(&value).unwrap()
}

// -----------------------------------------------------------------------
// 5. Negative: valid signatures produce non-zero derived keys
// -----------------------------------------------------------------------

#[test]
fn random_valid_signatures_produce_non_zero_keys() {
    // Synthesize a small sample of valid Ed25519 signatures with the
    // test gateway keypair, derive keys, assert none are all-zero.
    let (signing_key, _) = common::test_gateway_keypair();
    let dch = hash_from_hex("cccc000000000000000000000000000000000000000000000000000000000003");
    let vi_hash = *blake3::hash("vi_test".as_bytes()).as_bytes();

    let mut samples = Vec::new();
    for n in 0u64..16 {
        // Sign distinct payloads to get distinct signatures.
        let payload = format!("payload-{n}").into_bytes();
        let sig = signing_key.sign(&payload);
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let key = derive_receipt_stream_key(
            &sig_bytes,
            &vi_hash,
            &dch,
            &format!("rs_{n}"),
            n as u32,
        );
        assert_ne!(
            key, [0u8; 32],
            "derived key must not be all-zero (sample {n}, sig {} key {})",
            hex_encode_64(&sig_bytes),
            hex_encode(&key)
        );
        samples.push(key);
    }
    // Bonus: all samples should be distinct since at least one input varied per sample.
    for i in 0..samples.len() {
        for j in (i + 1)..samples.len() {
            assert_ne!(samples[i], samples[j], "samples {i} and {j} collided");
        }
    }
}
