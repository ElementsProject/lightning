use anyhow::anyhow;
use anyhow::Result;
use cln_rpc::primitives::PublicKey;
use core::fmt;
use serde_json::Value;
use std::str::FromStr;

/// Errors that can occur when unwrapping payload data
#[derive(Debug, Clone, PartialEq)]
pub enum UnwrapError {
    /// The public key bytes are invalid
    InvalidPublicKey(String),
    /// Failed to deserialize json value,
    SerdeFailure(String),
}

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnwrapError::InvalidPublicKey(e) => {
                write!(f, "Invalid public key: {}", e)
            }
            UnwrapError::SerdeFailure(e) => {
                write!(f, "Failed to serialize or deserialize json value: {}", e)
            }
        }
    }
}

impl std::error::Error for UnwrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            _ => None,
        }
    }
}

/// Wraps a payload with a peer ID for internal LSPS message transmission.
pub fn try_wrap_payload_with_peer_id(payload: &[u8], peer_id: PublicKey) -> Result<Vec<u8>> {
    // We expect the payload to be valid json, so no empty payload allowed, also
    // checks that we have curly braces at start and end.
    if payload.is_empty() || payload[0] != b'{' || payload[payload.len() - 1] != b'}' {
        return Err(anyhow!("payload no valid json"));
    }

    let pubkey_hex = peer_id.to_string();
    let mut result = Vec::with_capacity(pubkey_hex.len() + payload.len() + 13);

    result.extend_from_slice(&payload[..payload.len() - 1]);
    result.extend_from_slice(b",\"peer_id\":\"");
    result.extend_from_slice(pubkey_hex.as_bytes());
    result.extend_from_slice(b"\"}");
    Ok(result)
}

/// Safely unwraps payload data and a peer ID
pub fn try_unwrap_payload_with_peer_id(data: &[u8]) -> Result<(Vec<u8>, PublicKey)> {
    let mut json: Value =
        serde_json::from_slice(data).map_err(|e| UnwrapError::SerdeFailure(e.to_string()))?;

    if let Value::Object(ref mut map) = json {
        if let Some(Value::String(peer_id)) = map.remove("peer_id") {
            let modified_json = serde_json::to_string(&json)
                .map_err(|e| UnwrapError::SerdeFailure(e.to_string()))?;
            return Ok((
                modified_json.into_bytes(),
                PublicKey::from_str(&peer_id)
                    .map_err(|e| UnwrapError::InvalidPublicKey(e.to_string()))?,
            ));
        }
    }
    Err(UnwrapError::InvalidPublicKey(String::from(
        "public key missing",
    )))?
}

/// Unwraps payload data and peer ID, panicking on error
///
/// This is a convenience function for cases where one knows the data is valid.
pub fn unwrap_payload_with_peer_id(data: &[u8]) -> (Vec<u8>, PublicKey) {
    try_unwrap_payload_with_peer_id(data).expect("Failed to unwrap payload with peer_id")
}

/// Wraps payload data and peer ID, panicking on error
///
/// This is a convenience function for cases where one knows that the payload is
/// valid.
pub fn wrap_payload_with_peer_id(payload: &[u8], peer_id: PublicKey) -> Vec<u8> {
    try_wrap_payload_with_peer_id(payload, peer_id).expect("Failed to wrap payload with peer_id")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // Valid test public key
    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    #[test]
    fn test_wrap_and_unwrap_roundtrip() {
        let peer_id = PublicKey::from_slice(&PUBKEY).unwrap();
        let payload =
            json!({"jsonrpc": "2.0","method": "some-method","params": {},"id": "some-id"});
        let wrapped = wrap_payload_with_peer_id(payload.to_string().as_bytes(), peer_id);

        let (unwrapped_payload, unwrapped_peer_id) = unwrap_payload_with_peer_id(&wrapped);
        let value: serde_json::Value = serde_json::from_slice(&unwrapped_payload).unwrap();

        assert_eq!(value, payload);
        assert_eq!(unwrapped_peer_id, peer_id);
    }

    #[test]
    fn test_invalid_pubkey() {
        let mut invalid_data = vec![0u8; 40];
        // Set an invalid public key (all zeros)
        invalid_data[0] = 0x02; // Valid prefix
                                // But rest remains zeros which is invalid
        let payload = json!({"jsonrpc": "2.0","method": "some-method","params": {},"id": "some-id","peer_id": hex::encode(&invalid_data)});

        let result = try_unwrap_payload_with_peer_id(payload.to_string().as_bytes());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().downcast_ref::<UnwrapError>(),
            Some(UnwrapError::InvalidPublicKey(_))
        ));
    }
}
