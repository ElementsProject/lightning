use async_trait::async_trait;
use core::fmt::Debug;
use log::{debug, error};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::sync::Arc;

use crate::jsonrpc::{
    Error, JsonRpcRequest, JsonRpcResponse, RequestObject, ResponseObject, Result,
};

/// Defines the interface for transporting JSON-RPC messages.
///
/// Implementors of this trait are responsible for actually sending the JSON-RPC
/// request over some transport mechanism (RPC, Bolt8, etc.)
#[async_trait]
pub trait Transport {
    async fn send(&self, request: String) -> core::result::Result<String, Error>;
    async fn notify(&self, request: String) -> core::result::Result<(), Error>;
}

/// A typed JSON-RPC client that works with any transport implementation.
///
/// This client handles the JSON-RPC protocol details including message
/// formatting, request ID generation, and response parsing.
#[derive(Clone)]
pub struct JsonRpcClient<T: Transport> {
    transport: Arc<T>,
}

impl<T: Transport> JsonRpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport: Arc::new(transport),
        }
    }

    /// Makes a JSON-RPC method call with raw JSON parameters and returns a raw
    /// JSON result.
    pub async fn call_raw(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let id = generate_random_id();

        debug!("Preparing request: method={}, id={}", method, id);
        let request = RequestObject {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: Some(id.clone().into()),
        };
        let res_obj = self.send_request(method, &request, id).await?;
        Value::from_response(res_obj)
    }

    /// Makes a typed JSON-RPC method call with a request object and returns a
    /// typed response.
    ///
    /// This method provides type safety by using request and response types
    /// that implement the necessary traits.
    pub async fn call_typed<RQ, RS>(&self, request: RQ) -> Result<RS>
    where
        RQ: JsonRpcRequest + Serialize + Send + Sync,
        RS: DeserializeOwned + Serialize + Debug + Send + Sync,
    {
        let method = RQ::METHOD;
        let id = generate_random_id();

        debug!("Preparing request: method={}, id={}", method, id);
        let request = request.into_request(Some(id.clone().into()));
        let res_obj = self.send_request(method, &request, id).await?;
        RS::from_response(res_obj)
    }

    /// Sends a notification with raw JSON parameters (no response expected).
    pub async fn notify_raw(&self, method: &str, params: Option<Value>) -> Result<()> {
        debug!("Preparing notification: method={}", method);
        let request = RequestObject {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: None,
        };
        Ok(self.send_notification(method, &request).await?)
    }

    /// Sends a typed notification (no response expected).
    pub async fn notify_typed<RQ>(&self, request: RQ) -> Result<()>
    where
        RQ: JsonRpcRequest + Serialize + Send + Sync,
    {
        let method = RQ::METHOD;

        debug!("Preparing notification: method={}", method);
        let request = request.into_request(None);
        Ok(self.send_notification(method, &request).await?)
    }

    async fn send_request<RS, RP>(
        &self,
        method: &str,
        payload: &RP,
        id: String,
    ) -> Result<ResponseObject<RS>>
    where
        RP: Serialize + Send + Sync,
        RS: DeserializeOwned + Serialize + Debug + Send + Sync,
    {
        let request_json = serde_json::to_string(&payload)?;
        debug!(
            "Sending request: method={}, id={}, request={:?}",
            method, id, &request_json
        );
        let start = tokio::time::Instant::now();
        let res_str = self.transport.send(request_json).await?;
        let elapsed = start.elapsed();
        debug!(
            "Received response: method={}, id={}, response={}, elapsed={}ms",
            method,
            id,
            &res_str,
            elapsed.as_millis()
        );
        Ok(serde_json::from_str(&res_str)?)
    }

    async fn send_notification<RP>(&self, method: &str, payload: &RP) -> Result<()>
    where
        RP: Serialize + Send + Sync,
    {
        let request_json = serde_json::to_string(&payload)?;
        debug!("Sending notification: method={}", method);
        let start = tokio::time::Instant::now();
        self.transport.notify(request_json).await?;
        let elapsed = start.elapsed();
        debug!(
            "Sent notification: method={}, elapsed={}ms",
            method,
            elapsed.as_millis()
        );
        Ok(())
    }
}

/// Generates a random ID for JSON-RPC requests.
///
/// Uses a secure random number generator to create a hex-encoded ID. Falls back
/// to a timestamp-based ID if random generation fails.
fn generate_random_id() -> String {
    let mut bytes = [0u8; 10];
    match OsRng.try_fill_bytes(&mut bytes) {
        Ok(_) => hex::encode(bytes),
        Err(e) => {
            // Fallback to a timestamp-based ID if random generation fails
            error!(
                "Failed to generate random ID: {}, falling back to timestamp",
                e
            );
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("fallback-{}", timestamp)
        }
    }
}

#[cfg(test)]

mod test_json_rpc {
    use serde::Deserialize;
    use tokio::sync::OnceCell;

    use super::*;
    use crate::jsonrpc::{self, RpcError};

    #[derive(Clone)]
    struct TestTransport {
        req: Arc<OnceCell<String>>,
        res: Arc<Option<String>>,
        err: Arc<Option<String>>,
    }

    impl TestTransport {
        // Get the last request as parsed JSON
        fn last_request_json(&self) -> Option<Value> {
            self.req
                .get()
                .and_then(|req_str| serde_json::from_str(req_str).ok())
        }
    }

    #[async_trait]
    impl Transport for TestTransport {
        async fn send(&self, req: String) -> core::result::Result<String, Error> {
            // Store the request
            let _ = self.req.set(req);

            // Check for error first
            if let Some(err) = &*self.err {
                return Err(Error::Transport(jsonrpc::TransportError::Other(err.into())));
            }

            // Then check for response
            if let Some(res) = &*self.res {
                return Ok(res.clone());
            }

            panic!("TestTransport: neither result nor error is set.");
        }

        async fn notify(&self, req: String) -> core::result::Result<(), Error> {
            // Store the request
            let _ = self.req.set(req);

            // Check for error
            if let Some(err) = &*self.err {
                return Err(Error::Transport(jsonrpc::TransportError::Other(err.into())));
            }

            Ok(())
        }
    }

    #[derive(Default, Clone, Serialize, Deserialize, Debug)]
    struct DummyCall {
        foo: String,
        bar: i32,
    }

    impl JsonRpcRequest for DummyCall {
        const METHOD: &'static str = "dummy_call";
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
    struct DummyResponse {
        foo: String,
        bar: i32,
    }

    #[tokio::test]
    async fn test_typed_call_w_response() {
        let req = DummyCall {
            foo: String::from("hello world!"),
            bar: 13,
        };

        let expected_res = DummyResponse {
            foo: String::from("hello client!"),
            bar: 10,
        };

        let res_obj = expected_res
            .clone()
            .into_response(String::from("unique-id-123"));
        let res_str = serde_json::to_string(&res_obj).unwrap();

        let transport = TestTransport {
            req: Arc::new(OnceCell::const_new()),
            res: Arc::new(Some(res_str)),
            err: Arc::new(None),
        };

        let client_1 = JsonRpcClient::new(transport.clone());
        let res = client_1
            .call_typed::<_, DummyResponse>(req.clone())
            .await
            .expect("Should have an OK result");
        assert_eq!(res, expected_res);
        let transport_req = transport
            .last_request_json()
            .expect("Transport should have gotten a request");
        assert_eq!(
            transport_req
                .get("jsonrpc")
                .and_then(|v| v.as_str())
                .unwrap(),
            "2.0"
        );
        assert_eq!(
            transport_req
                .get("params")
                .and_then(|v| v.as_object())
                .unwrap(),
            serde_json::to_value(&req).unwrap().as_object().unwrap()
        );
    }

    #[tokio::test]
    async fn test_typed_call_w_rpc_error() {
        let req = DummyCall {
            foo: "hello world!".into(),
            bar: 13,
        };

        let err_res = RpcError::custom_error_with_data(
            -32099,
            "got a custom error",
            serde_json::json!({"got": "some"}),
        );

        let res_obj = err_res.clone().into_response("unique-id-123".into());
        let res_str = serde_json::to_string(&res_obj).unwrap();

        let transport = TestTransport {
            req: Arc::new(OnceCell::const_new()),
            res: Arc::new(Some(res_str)),
            err: Arc::new(None),
        };

        let client_1 = JsonRpcClient::new(transport);
        let res = client_1
            .call_typed::<_, DummyResponse>(req)
            .await
            .expect_err("Expected error response");
        assert!(match res {
            Error::Rpc(rpc_error) => {
                assert_eq!(rpc_error, err_res);
                true
            }
            _ => false,
        });
    }

    #[tokio::test]
    async fn test_typed_call_w_transport_error() {
        let req = DummyCall {
            foo: "hello world!".into(),
            bar: 13,
        };

        let transport = TestTransport {
            req: Arc::new(OnceCell::const_new()),
            res: Arc::new(None),
            err: Arc::new(Some(String::from("transport error"))),
        };

        let client_1 = JsonRpcClient::new(transport);
        let res = client_1
            .call_typed::<_, DummyResponse>(req)
            .await
            .expect_err("Expected error response");
        assert!(match res {
            Error::Transport(err) => {
                assert_eq!(err.to_string(), "Other error: transport error");
                true
            }
            _ => false,
        });
    }
}
