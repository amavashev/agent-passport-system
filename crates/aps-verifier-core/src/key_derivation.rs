//! HKDF-SHA256 derivation of `receipt_stream_key` from passport-bound
//! inputs. The construction follows RFC 5869 with TLV-framed `info`
//! to prevent concatenation ambiguity on variable-length fields.
//!
//! Construction (RFC 5869):
//!
//! ```text
//! PRK = HKDF-Extract(salt = verifier_instance_id_hash, IKM = signature_bytes)
//! OKM = HKDF-Expand(PRK, info, 32)
//! info = b"aps:v1:receipt-stream-mac"
//!      || u16_be(32) || delegation_chain_hash_bytes
//!      || u16_be(len(receipt_stream_id_utf8)) || receipt_stream_id_utf8
//!      || u32_be(revocation_epoch)
//! ```
//!
//! TLV framing on variable-length fields prevents concatenation
//! ambiguity. Fixed-length fields (delegation_chain_hash always 32
//! bytes, revocation_epoch always 4 bytes big-endian) still carry
//! the explicit length prefix for the hash to keep the layout
//! self-describing.

use hkdf::Hkdf;
use sha2::Sha256;

const INFO_LABEL: &[u8] = b"aps:v1:receipt-stream-mac";

/// Derive the 32-byte `receipt_stream_key` for the rolling MAC chain.
///
/// Inputs:
/// - `signature_bytes`: passport Ed25519 signature, 64 raw bytes
///   (decoded from `passport.signature` after `verify_signature`
///   succeeds). Acts as IKM.
/// - `verifier_instance_id_hash`: 32-byte BLAKE3 of
///   `passport.verifier_instance_id`. Acts as HKDF salt; adds
///   verifier-instance binding.
/// - `delegation_chain_hash`: 32-byte hash field decoded from
///   `passport.delegation_chain_hash`. Binds the key to the
///   authority chain identity.
/// - `receipt_stream_id`: UTF-8 string from `passport.receipt_stream_id`.
///   Provides per-stream uniqueness within a passport.
/// - `revocation_epoch`: u32 from `passport.revocation_epoch`. Acts as
///   `stream_epoch`; bumping it produces a new key for the same
///   logical stream (rotation / replay boundary).
pub fn derive_receipt_stream_key(
    signature_bytes: &[u8; 64],
    verifier_instance_id_hash: &[u8; 32],
    delegation_chain_hash: &[u8; 32],
    receipt_stream_id: &str,
    revocation_epoch: u32,
) -> [u8; 32] {
    let stream_id_bytes = receipt_stream_id.as_bytes();
    let stream_id_len: u16 = u16::try_from(stream_id_bytes.len())
        .expect("receipt_stream_id length must fit in u16");

    let mut info = Vec::with_capacity(
        INFO_LABEL.len() + 2 + 32 + 2 + stream_id_bytes.len() + 4,
    );
    info.extend_from_slice(INFO_LABEL);
    info.extend_from_slice(&32u16.to_be_bytes());
    info.extend_from_slice(delegation_chain_hash);
    info.extend_from_slice(&stream_id_len.to_be_bytes());
    info.extend_from_slice(stream_id_bytes);
    info.extend_from_slice(&revocation_epoch.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(verifier_instance_id_hash.as_slice()), signature_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 expand to 32 bytes never fails");
    okm
}
