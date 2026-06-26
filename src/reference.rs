//! Atlas payload-reference (v1) parsing and offline verification.
//!
//! Under the reference-mode API the entity bytes no longer travel inside the
//! transaction. A create/update operation whose `contentType` is exactly
//! [`PAYLOAD_REFERENCE_CONTENT_TYPE`] carries a UTF-8 JSON
//! [`PayloadReference`] in `Operation.payload`; the real bytes live in the
//! `atlas-payload-provider`, content-addressed by `id`.
//!
//! This module mirrors the on-chain precompile
//! (`atlas-reth/crates/arkiv-node/src/precompile.rs::validate_payload_reference`)
//! so the verdict the decoder reports matches what the chain would accept: it
//! reconstructs the canonical provider receipt, recovers the EIP-191 signer,
//! and checks that signer against the consensus allowlist. It performs no
//! network calls — exactly like the precompile.

use alloy_primitives::{Address, B256, Signature, eip191_hash_message, hex};
use serde::{Deserialize, Serialize};

/// Reserved content type that flags an `Operation.payload` as a v1 reference.
pub const PAYLOAD_REFERENCE_CONTENT_TYPE: &str = "application/vnd.atlas.payload-reference+json";

const PAYLOAD_REFERENCE_KIND: &str = "atlas.payloadReference";
const PAYLOAD_REFERENCE_VERSION: u64 = 1;
const PAYLOAD_PROVIDER_SERVICE: &str = "atlas-payload-provider";
const PAYLOAD_PROVIDER_RECEIPT_ACTION: &str = "payloadReceived";
const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_CONTENT_TYPE_BYTES: usize = 128;

/// Chain id whose dev signer the precompile additionally trusts.
pub const DEV_CHAIN_ID: u64 = 1337;

/// Live Atlas payload-provider signer, trusted on every chain.
pub const TRUSTED_PROVIDER_SIGNER: &str = "0xbdd23fd1bab3f4075edef4738d1d78a6bc5c236c";
/// Deterministic local signer (private key `0x..01`), trusted only on chain 1337.
pub const TRUSTED_DEV_PROVIDER_SIGNER: &str = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

/// V1 detached payload reference embedded in `Operation.payload`.
///
/// Parsed leniently (unknown fields ignored) so the decoder can still display
/// a slightly malformed reference; the chain itself rejects unknown fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadReference {
    pub kind: String,
    pub version: u64,
    pub provider: String,
    pub id: String,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content_type: Option<String>,
    pub checksum: String,
    pub size_bytes: u64,
    pub submitted_at: String,
    pub nonce: String,
    pub payment: u64,
    pub signature: PayloadSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadSignature {
    pub scheme: String,
    pub signer: String,
    #[serde(alias = "claim")]
    pub receipt: PayloadReceipt,
    #[serde(rename = "messageHash")]
    pub message_hash: String,
    pub signature: String,
    pub r: String,
    pub s: String,
    pub v: u8,
}

/// Provider receipt embedded in a v1 reference. Field order is significant: the
/// canonical JSON signed by the provider serializes these fields in declaration
/// order, so the order here must match the provider and the precompile exactly.
///
/// `nonce` and `payment` are required, matching the precompile's
/// `PayloadReceiptJson` — a reference whose embedded receipt omits either field
/// fails to deserialize, so the decoder rejects exactly what the chain rejects.
/// (The payload provider also signs non-reference receipts without these fields,
/// but those never appear inside a v1 reference, which is all this type parses.)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadReceipt {
    pub service: String,
    pub action: String,
    #[serde(rename = "payloadId")]
    pub payload_id: String,
    pub namespace: String,
    pub checksum: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    #[serde(rename = "submittedAt")]
    pub submitted_at: String,
    pub nonce: String,
    pub payment: u64,
}

/// Outcome of offline reference verification, shaped for the JSON response.
#[derive(Clone, Debug, Serialize)]
pub struct ReferenceVerification {
    /// True only when every check below passed (matches on-chain acceptance).
    pub valid: bool,
    /// Whether the recovered signer is in the trusted allowlist for `chainId`.
    #[serde(rename = "signerTrusted")]
    pub signer_trusted: bool,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(rename = "claimedSigner", skip_serializing_if = "Option::is_none")]
    pub claimed_signer: Option<String>,
    #[serde(rename = "recoveredSigner", skip_serializing_if = "Option::is_none")]
    pub recovered_signer: Option<String>,
    #[serde(rename = "messageHash", skip_serializing_if = "Option::is_none")]
    pub message_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Parse the raw operation payload bytes as a v1 payload reference.
pub fn parse_reference(payload: &[u8]) -> Result<PayloadReference, String> {
    serde_json::from_slice::<PayloadReference>(payload)
        .map_err(|error| format!("payload is not a valid payload reference: {error}"))
}

/// Verify a reference exactly as the on-chain precompile does (offline).
///
/// `extra_trusted` are operator-configured signers added to the built-in
/// allowlist. `chain_id` selects whether the dev signer is also trusted.
pub fn verify_reference(
    reference: &PayloadReference,
    chain_id: u64,
    extra_trusted: &[Address],
) -> ReferenceVerification {
    let mut errors: Vec<String> = Vec::new();

    if reference.kind != PAYLOAD_REFERENCE_KIND {
        errors.push(format!(
            "kind must be {PAYLOAD_REFERENCE_KIND:?}, got {:?}",
            reference.kind
        ));
    }
    if reference.version != PAYLOAD_REFERENCE_VERSION {
        errors.push(format!(
            "unsupported reference version {} (expected {PAYLOAD_REFERENCE_VERSION})",
            reference.version
        ));
    }
    if reference.provider != PAYLOAD_PROVIDER_SERVICE {
        errors.push(format!("unknown payload provider {:?}", reference.provider));
    }

    validate_payload_id(&reference.id, &mut errors);
    validate_namespace(&reference.namespace, &mut errors);
    validate_content_type(reference.content_type.as_deref(), &mut errors);
    validate_checksum(&reference.checksum, &mut errors);
    if reference.size_bytes == 0 {
        errors.push("sizeBytes must be greater than zero".to_string());
    }
    validate_submitted_at(&reference.submitted_at, &mut errors);
    validate_nonce(&reference.nonce, &mut errors);
    if reference.payment == 0 {
        errors.push("payment must be greater than zero".to_string());
    }

    let signature = &reference.signature;
    let claimed_signer = Some(signature.signer.clone());

    if signature.scheme != "eip191" {
        errors.push(format!(
            "unsupported signature scheme {:?} (expected eip191)",
            signature.scheme
        ));
    }

    // Receipt the provider should have signed, rebuilt from the reference's own
    // metadata. The chain compares this against the embedded receipt verbatim.
    let expected_receipt = PayloadReceipt {
        service: PAYLOAD_PROVIDER_SERVICE.to_string(),
        action: PAYLOAD_PROVIDER_RECEIPT_ACTION.to_string(),
        payload_id: reference.id.clone(),
        namespace: reference.namespace.clone(),
        checksum: reference.checksum.clone(),
        size_bytes: reference.size_bytes,
        submitted_at: reference.submitted_at.clone(),
        nonce: reference.nonce.clone(),
        payment: reference.payment,
    };
    if signature.receipt != expected_receipt {
        errors.push("signature receipt does not match the reference metadata".to_string());
    }

    // Canonical receipt JSON is compact and field-ordered; this reproduces the
    // exact bytes the provider hashed under the EIP-191 prefix.
    let canonical = serde_json::to_vec(&expected_receipt)
        .expect("payload receipt serializes to JSON");
    let message_hash = eip191_hash_message(canonical);
    let message_hash_hex = hex::encode_prefixed(message_hash.as_slice());

    if !signature.message_hash.eq_ignore_ascii_case(&message_hash_hex) {
        errors.push("signature messageHash does not match the canonical receipt".to_string());
    }
    if signature.v != 27 && signature.v != 28 {
        errors.push(format!("signature v must be 27 or 28, got {}", signature.v));
    }

    let mut recovered_signer: Option<String> = None;
    let mut signer_trusted = false;

    match (
        decode_hex_32(&signature.r),
        decode_hex_32(&signature.s),
        decode_hex_exact(&signature.signature, 65),
    ) {
        (Some(r), Some(s), Some(packed)) => {
            if packed[..32] != r || packed[32..64] != s || packed[64] != signature.v {
                errors.push("signature, r, s, and v fields are inconsistent".to_string());
            }
            if signature.v == 27 || signature.v == 28 {
                let sig = Signature::from_scalars_and_parity(
                    B256::from(r),
                    B256::from(s),
                    signature.v == 28,
                );
                match sig.recover_address_from_prehash(&message_hash) {
                    Ok(address) => {
                        let recovered = address.to_checksum(None);
                        recovered_signer = Some(recovered.clone());
                        match signature.signer.parse::<Address>() {
                            Ok(claimed) => {
                                if claimed != address {
                                    errors.push(format!(
                                        "recovered signer {recovered} does not match claimed signer {}",
                                        signature.signer
                                    ));
                                }
                                signer_trusted =
                                    is_trusted_signer(address, chain_id, extra_trusted);
                                if !signer_trusted {
                                    errors.push(format!(
                                        "signer {recovered} is not in the trusted payload-provider allowlist for chain {chain_id}"
                                    ));
                                }
                            }
                            Err(_) => errors
                                .push(format!("claimed signer {:?} is not an address", signature.signer)),
                        }
                    }
                    Err(error) => errors.push(format!("signature recovery failed: {error}")),
                }
            }
        }
        _ => errors.push("signature r, s, or signature hex is malformed".to_string()),
    }

    ReferenceVerification {
        valid: errors.is_empty(),
        signer_trusted,
        chain_id,
        claimed_signer,
        recovered_signer,
        message_hash: Some(message_hash_hex),
        errors,
    }
}

/// Built-in plus operator-configured trusted signers, gated on chain id for the
/// dev signer — mirrors `is_trusted_payload_provider_signer` in the precompile.
fn is_trusted_signer(signer: Address, chain_id: u64, extra_trusted: &[Address]) -> bool {
    let prod: Address = TRUSTED_PROVIDER_SIGNER.parse().expect("valid const address");
    let dev: Address = TRUSTED_DEV_PROVIDER_SIGNER.parse().expect("valid const address");
    signer == prod
        || (chain_id == DEV_CHAIN_ID && signer == dev)
        || extra_trusted.contains(&signer)
}

fn validate_payload_id(value: &str, errors: &mut Vec<String>) {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        errors.push("id must be a 64-character lowercase hex digest".to_string());
    }
}

fn validate_checksum(value: &str, errors: &mut Vec<String>) {
    match value.strip_prefix("sha256:") {
        Some(hex) if hex.len() == 64 && hex.bytes().all(is_lower_hex) => {}
        _ => errors.push("checksum must be sha256:<64 lowercase hex>".to_string()),
    }
}

fn validate_namespace(value: &str, errors: &mut Vec<String>) {
    let ok = !value.is_empty()
        && value.len() <= MAX_NAMESPACE_BYTES
        && value
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_'));
    if !ok {
        errors.push("namespace is empty, too long, or has invalid characters".to_string());
    }
}

fn validate_content_type(value: Option<&str>, errors: &mut Vec<String>) {
    let Some(value) = value else {
        return;
    };
    let ok = !value.is_empty()
        && value.len() <= MAX_CONTENT_TYPE_BYTES
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if !ok {
        errors.push("contentType is empty, too long, or has non-printable characters".to_string());
    }
}

fn validate_submitted_at(value: &str, errors: &mut Vec<String>) {
    let ok = !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if !ok {
        errors.push("submittedAt is empty, too long, or has non-printable characters".to_string());
    }
}

fn validate_nonce(value: &str, errors: &mut Vec<String>) {
    match decode_hex_32(value) {
        Some(bytes) if bytes != [0u8; 32] => {}
        Some(_) => errors.push("nonce must be a non-zero 32-byte hex value".to_string()),
        None => errors.push("nonce must be a 0x-prefixed 32-byte hex value".to_string()),
    }
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'a'..=b'f')
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex_exact(value, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_hex_exact(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if body.len() != expected_bytes * 2 {
        return None;
    }
    hex::decode(body).ok()
}

/// Parse the operator override `TRUSTED_PROVIDER_SIGNERS` (comma-separated
/// 0x-addresses) into addresses, ignoring blank entries.
pub fn parse_extra_trusted(raw: Option<&str>) -> Result<Vec<Address>, String> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let address = trimmed
            .parse::<Address>()
            .map_err(|_| format!("invalid trusted signer address {trimmed:?}"))?;
        out.push(address);
    }
    Ok(out)
}

/// The signed fixture from atlas-reth's precompile tests. Signer is the dev key
/// (private key `0x..01`); the embedded signature is valid and the signer is
/// trusted only on chain 1337. Shared across the crate's test modules.
#[cfg(test)]
pub(crate) fn tests_fixture() -> &'static str {
    r#"{"kind":"atlas.payloadReference","version":1,"provider":"atlas-payload-provider","id":"a806b74c6c933e9c0c3cfd7c099c7c6cdbf86bef1a48da310a90bd050c37b4e5","namespace":"atlas.test","contentType":"text/plain","checksum":"sha256:86a4700d6cf4c679fb010312f20e911e86beb1336e5b78ad8b02f1ac6e10c878","sizeBytes":42,"submittedAt":"2026-06-24T15:24:30Z","nonce":"0x0000000000000000000000000000000000000000000000000000000000000001","payment":100000,"signature":{"scheme":"eip191","signer":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf","receipt":{"service":"atlas-payload-provider","action":"payloadReceived","payloadId":"a806b74c6c933e9c0c3cfd7c099c7c6cdbf86bef1a48da310a90bd050c37b4e5","namespace":"atlas.test","checksum":"sha256:86a4700d6cf4c679fb010312f20e911e86beb1336e5b78ad8b02f1ac6e10c878","sizeBytes":42,"submittedAt":"2026-06-24T15:24:30Z","nonce":"0x0000000000000000000000000000000000000000000000000000000000000001","payment":100000},"messageHash":"0xc26441853fe5760f4b5621649c8c0a2a7645b81793c3b367eb7f69f936736080","signature":"0x175505ad691cf7c80733ab39c0158d850182176090fc1365e71a13f61b2dadaa66e455ba88196d2a1570c326c3813cbc8e3b417ef79891db2ed934bdb4d687061b","r":"0x175505ad691cf7c80733ab39c0158d850182176090fc1365e71a13f61b2dadaa","s":"0x66e455ba88196d2a1570c326c3813cbc8e3b417ef79891db2ed934bdb4d68706","v":27}}"#
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        tests_fixture()
    }

    #[test]
    fn fixture_verifies_on_dev_chain() {
        let reference = parse_reference(fixture().as_bytes()).expect("parse fixture");
        let verification = verify_reference(&reference, DEV_CHAIN_ID, &[]);
        assert!(verification.valid, "errors: {:?}", verification.errors);
        assert!(verification.signer_trusted);
        assert_eq!(
            verification.recovered_signer.as_deref().map(str::to_ascii_lowercase),
            Some(TRUSTED_DEV_PROVIDER_SIGNER.to_string())
        );
        assert_eq!(
            verification.message_hash.as_deref(),
            Some("0xc26441853fe5760f4b5621649c8c0a2a7645b81793c3b367eb7f69f936736080")
        );
    }

    #[test]
    fn dev_signer_is_not_trusted_on_other_chains() {
        let reference = parse_reference(fixture().as_bytes()).expect("parse fixture");
        // Signature still recovers correctly, but the signer is not allowlisted
        // off the dev chain, so the overall verdict is invalid.
        let verification = verify_reference(&reference, 42069, &[]);
        assert!(!verification.signer_trusted);
        assert!(!verification.valid);
        assert_eq!(
            verification.recovered_signer.as_deref().map(str::to_ascii_lowercase),
            Some(TRUSTED_DEV_PROVIDER_SIGNER.to_string())
        );
    }

    #[test]
    fn tampered_checksum_fails_receipt_match() {
        let mut value: serde_json::Value = serde_json::from_str(fixture()).unwrap();
        value["checksum"] =
            serde_json::json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let reference = parse_reference(value.to_string().as_bytes()).expect("parse");
        let verification = verify_reference(&reference, DEV_CHAIN_ID, &[]);
        assert!(!verification.valid);
        assert!(
            verification
                .errors
                .iter()
                .any(|e| e.contains("receipt does not match"))
        );
    }

    #[test]
    fn tampered_signature_hash_fails() {
        let mut value: serde_json::Value = serde_json::from_str(fixture()).unwrap();
        value["signature"]["messageHash"] =
            serde_json::json!("0x0000000000000000000000000000000000000000000000000000000000000000");
        let reference = parse_reference(value.to_string().as_bytes()).expect("parse");
        let verification = verify_reference(&reference, DEV_CHAIN_ID, &[]);
        assert!(!verification.valid);
    }

    #[test]
    fn unsupported_version_is_reported() {
        let mut value: serde_json::Value = serde_json::from_str(fixture()).unwrap();
        value["version"] = serde_json::json!(2);
        let reference = parse_reference(value.to_string().as_bytes()).expect("parse");
        let verification = verify_reference(&reference, DEV_CHAIN_ID, &[]);
        assert!(!verification.valid);
        assert!(verification.errors.iter().any(|e| e.contains("version")));
    }

    #[test]
    fn extra_trusted_signer_is_honored() {
        let reference = parse_reference(fixture().as_bytes()).expect("parse fixture");
        let dev: Address = TRUSTED_DEV_PROVIDER_SIGNER.parse().unwrap();
        // On a non-dev chain the dev signer is only trusted when configured.
        let verification = verify_reference(&reference, 42069, &[dev]);
        assert!(verification.signer_trusted);
        assert!(verification.valid, "errors: {:?}", verification.errors);
    }

    #[test]
    fn parse_extra_trusted_parses_and_skips_blanks() {
        let parsed = parse_extra_trusted(Some(" 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf , ")).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parse_extra_trusted(Some("not-an-address")).is_err());
        assert!(parse_extra_trusted(None).unwrap().is_empty());
    }
}

// These modules were added while investigating the optional-field fidelity gap
// flagged in review. `PayloadReceipt.nonce`/`payment` are now required (matching
// the precompile's `PayloadReceiptJson`), so a receipt missing either field is
// rejected at deserialization — which is exactly the behavior the original
// diagnostic comments described as correct ("what SHOULD happen after the fix").
#[cfg(test)]
mod test_missing_optional_fields {
    use super::*;

    #[test]
    fn receipt_without_nonce_field_is_rejected() {
        let json_without_nonce = r#"{"service":"atlas-payload-provider","action":"payloadReceived","payloadId":"test","namespace":"test","checksum":"sha256:test","sizeBytes":42,"submittedAt":"2026-06-24T15:24:30Z","payment":100000}"#;
        let result: Result<PayloadReceipt, _> = serde_json::from_str(json_without_nonce);
        assert!(
            result.is_err(),
            "receipt without nonce must fail to deserialize, matching the precompile"
        );
    }

    #[test]
    fn receipt_without_payment_field_is_rejected() {
        let json_without_payment = r#"{"service":"atlas-payload-provider","action":"payloadReceived","payloadId":"test","namespace":"test","checksum":"sha256:test","sizeBytes":42,"submittedAt":"2026-06-24T15:24:30Z","nonce":"0x0000000000000000000000000000000000000000000000000000000000000001"}"#;
        let result: Result<PayloadReceipt, _> = serde_json::from_str(json_without_payment);
        assert!(
            result.is_err(),
            "receipt without payment must fail to deserialize, matching the precompile"
        );
    }

    #[test]
    fn receipt_without_both_fields_is_rejected() {
        let json_without_optionals = r#"{"service":"atlas-payload-provider","action":"payloadReceived","payloadId":"test","namespace":"test","checksum":"sha256:test","sizeBytes":42,"submittedAt":"2026-06-24T15:24:30Z"}"#;
        let result: Result<PayloadReceipt, _> = serde_json::from_str(json_without_optionals);
        assert!(
            result.is_err(),
            "receipt without nonce and payment must fail to deserialize"
        );
    }
}

#[cfg(test)]
mod test_mismatched_optional_fields {
    use super::*;

    #[test]
    fn reference_with_receipt_missing_nonce_fails_to_parse() {
        // A reference whose embedded signature.receipt omits nonce/payment is now
        // rejected at parse time (the receipt no longer deserializes), so the
        // decoder rejects the same input the chain would.
        let mut value: serde_json::Value = serde_json::from_str(tests_fixture()).unwrap();
        value["signature"]["receipt"]
            .as_object_mut()
            .unwrap()
            .remove("nonce");
        assert!(
            parse_reference(value.to_string().as_bytes()).is_err(),
            "reference with a nonce-less receipt must be rejected"
        );
    }

    #[test]
    fn reference_with_receipt_missing_payment_fails_to_parse() {
        let mut value: serde_json::Value = serde_json::from_str(tests_fixture()).unwrap();
        value["signature"]["receipt"]
            .as_object_mut()
            .unwrap()
            .remove("payment");
        assert!(
            parse_reference(value.to_string().as_bytes()).is_err(),
            "reference with a payment-less receipt must be rejected"
        );
    }
}
