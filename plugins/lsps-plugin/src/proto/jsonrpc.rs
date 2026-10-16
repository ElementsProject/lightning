use lsps_types::jsonrpc::{JsonRpcRequest, RequestObject};
use rand::{TryRng, rngs::SysRng};

/// Builds JSON-RPC request objects with a random `id`.
pub trait JsonRpcRequestExt: JsonRpcRequest + Sized {
    fn into_request(self) -> RequestObject<Self> {
        self.into_request_with_id(Some(generate_random_id()))
    }
}

impl<T: JsonRpcRequest> JsonRpcRequestExt for T {}

/// Generates a random ID for JSON-RPC requests.
///
/// Uses a secure random number generator to create a hex-encoded ID. Falls back
/// to a timestamp-based ID if random generation fails.
fn generate_random_id() -> String {
    let mut bytes = [0u8; 10];
    match SysRng.try_fill_bytes(&mut bytes) {
        Ok(_) => hex::encode(bytes),
        Err(_) => {
            // Fallback to a timestamp-based ID if random generation fails
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("fallback-{}", timestamp)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_into_request_sets_random_id() {
        #[derive(Debug, Serialize, Deserialize)]
        pub struct SayHelloRequest;
        impl JsonRpcRequest for SayHelloRequest {
            const METHOD: &'static str = "say_hello";
        }
        let a = SayHelloRequest.into_request();
        let b = SayHelloRequest.into_request();
        assert_eq!(a.method, "say_hello");
        assert_eq!(a.id.as_ref().map(String::len), Some(20));
        assert_ne!(a.id, b.id);
    }
}
