//! Decode Arkiv `execute(Operation[])` calldata — or a signed transaction that
//! wraps it — back into human-readable operations.
//!
//! The ABI mirror of `Operation` is kept in lockstep with
//! `atlas-reth/crates/arkiv-node/src/precompile.rs` and the SDK's
//! `ENTITY_EXECUTE_ABI`. Create/update operations now carry a payload
//! *reference* instead of inline entity bytes; when the content type is the
//! reserved reference type the payload JSON is parsed and verified offline via
//! [`crate::reference`].

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, U256, hex};
use alloy_sol_types::{SolCall, sol};
use serde::Serialize;

use crate::reference::{
    PAYLOAD_REFERENCE_CONTENT_TYPE, PayloadReference, ReferenceVerification, parse_reference,
    verify_reference,
};

// Arkiv registry / precompile address. Block time is the assumed Arkiv block
// duration used to render `expiresAtBlocks` as an approximate wall-clock span.
pub const ARKIV_ADDRESS: &str = "0x4400000000000000000000000000000000000044";
const BLOCK_TIME_SECONDS: u64 = 2;

sol! {
    struct Mime128 {
        bytes32[4] data;
    }

    struct Attribute {
        bytes32 name;
        uint8 valueType;
        bytes32[4] value;
    }

    struct Operation {
        uint8 operationType;
        bytes32 entityKey;
        bytes payload;
        Mime128 contentType;
        Attribute[] attributes;
        uint32 btl;
        address newOwner;
    }

    function execute(Operation[] ops) external;
}

// Operation type tags — must match `EntityOperationType` in the SDK and the
// `OP_*` constants in the precompile.
const OP_CREATE: u8 = 1;
const OP_UPDATE: u8 = 2;
const OP_EXTEND: u8 = 3;
const OP_TRANSFER: u8 = 4;
const OP_DELETE: u8 = 5;
const OP_EXPIRE: u8 = 6;

// Attribute value type tags — match `AttributeValueType` in the SDK.
const ATTR_UINT: u8 = 1;
const ATTR_STRING: u8 = 2;
const ATTR_ENTITY_KEY: u8 = 3;

/// A decode failure that maps to an HTTP 400 with the message surfaced to the
/// caller.
#[derive(Debug)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Serialize)]
pub struct DecodedAttribute {
    pub key: String,
    #[serde(rename = "valueType")]
    pub value_type: u8,
    #[serde(rename = "valueTypeName")]
    pub value_type_name: &'static str,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct DecodedPayload {
    pub hex: String,
    pub size: usize,
    #[serde(rename = "isReference")]
    pub is_reference: bool,
    /// Present only for non-reference payloads that decode as valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DecodedOperation {
    pub index: usize,
    #[serde(rename = "operationType")]
    pub operation_type: u8,
    pub operation: String,
    #[serde(rename = "entityKey")]
    pub entity_key: String,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub payload: DecodedPayload,
    /// Parsed v1 reference, present when `contentType` is the reserved
    /// reference content type and the payload parses.
    #[serde(rename = "payloadReference", skip_serializing_if = "Option::is_none")]
    pub payload_reference: Option<PayloadReference>,
    /// Offline verification verdict for `payloadReference`.
    #[serde(rename = "referenceVerification", skip_serializing_if = "Option::is_none")]
    pub reference_verification: Option<ReferenceVerification>,
    /// Set when the content type is a reference but the payload failed to parse.
    #[serde(rename = "referenceError", skip_serializing_if = "Option::is_none")]
    pub reference_error: Option<String>,
    pub attributes: Vec<DecodedAttribute>,
    #[serde(rename = "expiresAtBlocks")]
    pub expires_at_blocks: u32,
    #[serde(rename = "approxExpiresInSeconds")]
    pub approx_expires_in_seconds: u64,
    #[serde(rename = "newOwner", skip_serializing_if = "Option::is_none")]
    pub new_owner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DecodedTransaction {
    #[serde(rename = "functionName")]
    pub function_name: &'static str,
    /// Present only when a full serialized transaction (not bare calldata) was
    /// supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Set when `to` is present and differs from the Arkiv registry address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(rename = "operationCount")]
    pub operation_count: usize,
    pub operations: Vec<DecodedOperation>,
}

/// Decode either bare `execute(...)` calldata or a signed (EIP-2718) serialized
/// transaction whose input is an `execute(...)` call.
///
/// `chain_id` selects the trusted-signer set used to verify any payload
/// references; `extra_trusted` adds operator-configured signers.
pub fn decode_input(
    input: &str,
    chain_id: u64,
    extra_trusted: &[Address],
) -> Result<DecodedTransaction, DecodeError> {
    let bytes = parse_hex(input)?;
    let selector = executeCall::SELECTOR;

    if bytes.len() >= 4 && bytes[..4] == selector {
        return decode_calldata(&bytes, None, chain_id, extra_trusted);
    }

    // Not bare calldata — try to interpret it as a signed serialized
    // transaction whose input is an execute() call.
    let mut slice: &[u8] = &bytes;
    let envelope = TxEnvelope::decode_2718(&mut slice).map_err(|error| {
        DecodeError(format!(
            "input is neither Arkiv execute() calldata (selector 0x{}) nor a decodable signed transaction: {error}",
            hex::encode(selector)
        ))
    })?;

    let input_bytes = envelope.input();
    if input_bytes.len() < 4 || input_bytes[..4] != selector {
        return Err(DecodeError(format!(
            "serialized transaction does not call Arkiv execute() (selector 0x{})",
            hex::encode(selector)
        )));
    }

    let to = envelope.to().map(|address| address.to_checksum(None));
    decode_calldata(input_bytes, to, chain_id, extra_trusted)
}

fn decode_calldata(
    data: &[u8],
    to: Option<String>,
    chain_id: u64,
    extra_trusted: &[Address],
) -> Result<DecodedTransaction, DecodeError> {
    // Callers only reach here after a selector match, but guard the slice
    // explicitly so this can never panic regardless of how it is called.
    if data.len() < 4 {
        return Err(DecodeError(
            "calldata is too short for a function selector".to_string(),
        ));
    }
    let decoded = executeCall::abi_decode_raw(&data[4..])
        .map_err(|error| DecodeError(format!("not a valid Arkiv execute() call: {error}")))?;

    let operations = decoded
        .ops
        .iter()
        .enumerate()
        .map(|(index, op)| decode_operation(index, op, chain_id, extra_trusted))
        .collect::<Vec<_>>();

    let warning = match to.as_deref() {
        Some(address) if !address.eq_ignore_ascii_case(ARKIV_ADDRESS) => Some(format!(
            "transaction target {address} is not the known Arkiv registry {ARKIV_ADDRESS}"
        )),
        _ => None,
    };

    Ok(DecodedTransaction {
        function_name: "execute",
        to,
        warning,
        operation_count: operations.len(),
        operations,
    })
}

fn decode_operation(
    index: usize,
    op: &Operation,
    chain_id: u64,
    extra_trusted: &[Address],
) -> DecodedOperation {
    let payload_bytes = op.payload.as_ref();
    let content_type_bytes = pack_bytes128(&op.contentType.data);
    let is_reference = content_type_bytes == PAYLOAD_REFERENCE_CONTENT_TYPE.as_bytes();

    let mut payload_reference = None;
    let mut reference_verification = None;
    let mut reference_error = None;
    let mut text = None;

    if is_reference {
        match parse_reference(payload_bytes) {
            Ok(reference) => {
                reference_verification =
                    Some(verify_reference(&reference, chain_id, extra_trusted));
                payload_reference = Some(reference);
            }
            Err(error) => reference_error = Some(error),
        }
    } else if !payload_bytes.is_empty() {
        text = std::str::from_utf8(payload_bytes).ok().map(str::to_string);
    }

    DecodedOperation {
        index,
        operation_type: op.operationType,
        operation: operation_name(op.operationType),
        entity_key: hex::encode_prefixed(op.entityKey.as_slice()),
        content_type: bytes_to_utf8(&content_type_bytes),
        payload: DecodedPayload {
            hex: hex::encode_prefixed(payload_bytes),
            size: payload_bytes.len(),
            is_reference,
            text,
        },
        payload_reference,
        reference_verification,
        reference_error,
        attributes: op.attributes.iter().map(decode_attribute).collect(),
        expires_at_blocks: op.btl,
        approx_expires_in_seconds: op.btl as u64 * BLOCK_TIME_SECONDS,
        new_owner: decode_new_owner(op.newOwner),
    }
}

fn decode_attribute(attr: &Attribute) -> DecodedAttribute {
    let key = ident32_to_string(attr.name.as_slice());
    match attr.valueType {
        ATTR_UINT => DecodedAttribute {
            key,
            value_type: attr.valueType,
            value_type_name: "uint",
            // value[0] holds a big-endian uint256; upper words are zero.
            value: U256::from_be_slice(attr.value[0].as_slice()).to_string(),
        },
        ATTR_STRING => {
            let bytes = pack_bytes128(&attr.value);
            DecodedAttribute {
                key,
                value_type: attr.valueType,
                value_type_name: "string",
                value: bytes_to_utf8(&bytes)
                    .unwrap_or_else(|| hex::encode_prefixed(&bytes)),
            }
        }
        ATTR_ENTITY_KEY => DecodedAttribute {
            key,
            value_type: attr.valueType,
            value_type_name: "entityKey",
            value: hex::encode_prefixed(attr.value[0].as_slice()),
        },
        other => DecodedAttribute {
            key,
            value_type: other,
            value_type_name: "unknown",
            value: hex::encode_prefixed(&pack_bytes128(&attr.value)),
        },
    }
}

fn operation_name(operation_type: u8) -> String {
    match operation_type {
        OP_CREATE => "create".to_string(),
        OP_UPDATE => "update".to_string(),
        OP_EXTEND => "extend".to_string(),
        OP_TRANSFER => "transfer".to_string(),
        OP_DELETE => "delete".to_string(),
        OP_EXPIRE => "expire".to_string(),
        other => format!("unknown({other})"),
    }
}

fn decode_new_owner(owner: Address) -> Option<String> {
    if owner == Address::ZERO {
        None
    } else {
        Some(owner.to_checksum(None))
    }
}

/// Pack a `bytes32[4]` container into 128 bytes, then strip trailing zeros to
/// recover the left-aligned content (Mime128 / string attribute values).
fn pack_bytes128(words: &[alloy_primitives::FixedBytes<32>; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    for word in words {
        out.extend_from_slice(word.as_slice());
    }
    strip_trailing_zeros(out)
}

/// Ident32: a left-aligned string in a single `bytes32`.
fn ident32_to_string(name: &[u8]) -> String {
    let trimmed = strip_trailing_zeros(name.to_vec());
    bytes_to_utf8(&trimmed).unwrap_or_else(|| hex::encode_prefixed(name))
}

fn strip_trailing_zeros(mut value: Vec<u8>) -> Vec<u8> {
    while matches!(value.last(), Some(0)) {
        value.pop();
    }
    value
}

/// UTF-8 decode, returning `None` for empty input or invalid UTF-8.
fn bytes_to_utf8(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

fn parse_hex(input: &str) -> Result<Vec<u8>, DecodeError> {
    let trimmed = input.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if body.is_empty() {
        return Err(DecodeError("input is empty".to_string()));
    }
    hex::decode(body).map_err(|error| DecodeError(format!("input is not valid hex: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::DEV_CHAIN_ID;
    use alloy_primitives::{B256, Bytes, FixedBytes};

    fn mime(value: &str) -> Mime128 {
        let mut buf = [0u8; 128];
        buf[..value.len()].copy_from_slice(value.as_bytes());
        Mime128 {
            data: [
                FixedBytes::from_slice(&buf[..32]),
                FixedBytes::from_slice(&buf[32..64]),
                FixedBytes::from_slice(&buf[64..96]),
                FixedBytes::from_slice(&buf[96..128]),
            ],
        }
    }

    fn ident(value: &str) -> B256 {
        let mut buf = [0u8; 32];
        buf[..value.len()].copy_from_slice(value.as_bytes());
        B256::from(buf)
    }

    fn string_attr(key: &str, value: &str) -> Attribute {
        let mut buf = [0u8; 128];
        buf[..value.len()].copy_from_slice(value.as_bytes());
        Attribute {
            name: ident(key),
            valueType: ATTR_STRING,
            value: [
                FixedBytes::from_slice(&buf[..32]),
                FixedBytes::from_slice(&buf[32..64]),
                FixedBytes::from_slice(&buf[64..96]),
                FixedBytes::from_slice(&buf[96..128]),
            ],
        }
    }

    fn uint_attr(key: &str, value: u64) -> Attribute {
        Attribute {
            name: ident(key),
            valueType: ATTR_UINT,
            value: [
                FixedBytes::from(U256::from(value).to_be_bytes::<32>()),
                FixedBytes::ZERO,
                FixedBytes::ZERO,
                FixedBytes::ZERO,
            ],
        }
    }

    fn encode_execute(ops: Vec<Operation>) -> Vec<u8> {
        executeCall { ops }.abi_encode()
    }

    #[test]
    fn decodes_inline_create_operation() {
        let op = Operation {
            operationType: OP_CREATE,
            entityKey: B256::repeat_byte(0x11),
            payload: Bytes::from_static(b"Hello Arkiv"),
            contentType: mime("text/plain"),
            attributes: vec![string_attr("category", "greeting"), uint_attr("version", 42)],
            btl: 1800,
            newOwner: Address::ZERO,
        };
        let calldata = encode_execute(vec![op]);
        let decoded = decode_input(&hex::encode_prefixed(&calldata), DEV_CHAIN_ID, &[]).unwrap();

        assert_eq!(decoded.function_name, "execute");
        assert!(decoded.to.is_none());
        assert_eq!(decoded.operation_count, 1);
        let op = &decoded.operations[0];
        assert_eq!(op.operation, "create");
        assert_eq!(op.content_type.as_deref(), Some("text/plain"));
        assert_eq!(op.payload.text.as_deref(), Some("Hello Arkiv"));
        assert!(!op.payload.is_reference);
        assert_eq!(op.expires_at_blocks, 1800);
        assert_eq!(op.approx_expires_in_seconds, 3600);
        assert!(op.new_owner.is_none());
        assert_eq!(op.attributes[0].value_type_name, "string");
        assert_eq!(op.attributes[0].value, "greeting");
        assert_eq!(op.attributes[1].value_type_name, "uint");
        assert_eq!(op.attributes[1].value, "42");
    }

    #[test]
    fn decodes_reference_create_and_verifies() {
        let reference = crate::reference::tests_fixture();
        let op = Operation {
            operationType: OP_CREATE,
            entityKey: B256::ZERO,
            payload: Bytes::copy_from_slice(reference.as_bytes()),
            contentType: mime(PAYLOAD_REFERENCE_CONTENT_TYPE),
            attributes: vec![],
            btl: 10,
            newOwner: Address::ZERO,
        };
        let calldata = encode_execute(vec![op]);
        let decoded = decode_input(&hex::encode_prefixed(&calldata), DEV_CHAIN_ID, &[]).unwrap();
        let op = &decoded.operations[0];

        assert!(op.payload.is_reference);
        assert!(op.payload.text.is_none());
        assert_eq!(op.content_type.as_deref(), Some(PAYLOAD_REFERENCE_CONTENT_TYPE));
        let reference = op.payload_reference.as_ref().expect("reference parsed");
        assert_eq!(reference.id, "a806b74c6c933e9c0c3cfd7c099c7c6cdbf86bef1a48da310a90bd050c37b4e5");
        let verification = op.reference_verification.as_ref().expect("verified");
        assert!(verification.valid, "errors: {:?}", verification.errors);
        assert!(verification.signer_trusted);
    }

    #[test]
    fn rejects_non_execute_calldata() {
        let error = decode_input("0xdeadbeef", DEV_CHAIN_ID, &[]).unwrap_err();
        assert!(error.0.contains("execute"));
    }

    #[test]
    fn rejects_non_hex_input() {
        let error = decode_input("hello world", 1, &[]).unwrap_err();
        assert!(error.0.contains("hex"));
    }
}
