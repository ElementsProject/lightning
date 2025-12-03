use crate::proto::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RequestObject};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use core::fmt::Debug;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Transport-specific errors that may occur when sending or receiving JSON-RPC
/// messages.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Timeout")]
    Timeout,
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Couldn't parse JSON-RPC request")]
    ParseRequest {
        #[source]
        source: serde_json::Error,
    },
    #[error("request is missing id")]
    MissingId,
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::ParseRequest { source: value }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Defines the interface for transporting JSON-RPC messages.
///
/// Implementors of this trait are responsible for actually sending the JSON-RPC
/// request over some transport mechanism (RPC, Bolt8, etc.)
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, peer: &PublicKey, request: &str) -> Result<String>;
    async fn notify(&self, peer: &PublicKey, request: &str) -> Result<()>;
    async fn request<P, R>(
        &self,
        _peer_id: &PublicKey,
        _request: &RequestObject<P>,
    ) -> Result<JsonRpcResponse<R>>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        unimplemented!();
    }
}

/// A typed JSON-RPC client that works with any transport implementation.
///
/// This client handles the JSON-RPC protocol details including message
/// formatting, request ID generation, and response parsing.
#[derive(Clone)]
pub struct JsonRpcClient<T: Transport> {
    transport: T,
}

impl<T: Transport> JsonRpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Makes a JSON-RPC method call with raw JSON parameters and returns a raw
    /// JSON result.
    pub async fn call_raw(
        &self,
        peer_id: &PublicKey,
        method: &str,
        params: Option<Value>,
        id: Option<String>,
    ) -> Result<JsonRpcResponse<Value>> {
        let request = RequestObject {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id,
        };
        self.send_request(peer_id, &request).await
    }

    /// Makes a typed JSON-RPC method call with a request object and returns a
    /// typed response.
    ///
    /// This method provides type safety by using request and response types
    /// that implement the necessary traits.
    pub async fn call_typed<RQ, RS>(
        &self,
        peer_id: &PublicKey,
        request: RQ,
    ) -> Result<JsonRpcResponse<RS>>
    where
        RQ: JsonRpcRequest + Send + Sync,
        RS: DeserializeOwned + Serialize + Send,
    {
        let request = request.into_request();
        self.send_request(peer_id, &request).await
    }

    async fn send_request<RP, RS>(
        &self,
        peer: &PublicKey,
        request: &RequestObject<RP>,
    ) -> Result<JsonRpcResponse<RS>>
    where
        RP: Serialize + Send + Sync,
        RS: DeserializeOwned + Serialize + Send,
    {
        self.transport.request(peer, request).await
    }
}

#[cfg(test)]
mod test_json_rpc {
    use super::*;
    use crate::proto::jsonrpc::RpcError;
    use serde::Deserialize;
    use std::{str::FromStr as _, sync::Arc};
    use tokio::sync::OnceCell;

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
        async fn request<P, R>(
            &self,
            _peer_id: &PublicKey,
            request: &RequestObject<P>,
        ) -> Result<JsonRpcResponse<R>>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned + Send,
        {
            // Store the request
            let req = serde_json::to_string(request).unwrap();
            let _ = self.req.set(req);

            // Check for error first
            if let Some(err) = &*self.err {
                return Err(Error::Internal(err.into()));
            }

            // Then check for response
            if let Some(res) = &*self.res {
                let res: JsonRpcResponse<R> = match serde_json::from_str(&res) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("GOT ERROR {}", e);
                        panic!();
                    }
                };
                return Ok(res);
            }
            panic!("TestTransport: neither result nor error is set.");
        }
        async fn send(
            &self,
            _peer_id: &PublicKey,
            _req: &str,
        ) -> core::result::Result<String, Error> {
            unimplemented!();
        }

        async fn notify(
            &self,
            _peer_id: &PublicKey,
            _req: &str,
        ) -> core::result::Result<(), Error> {
            unimplemented!();
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
        let peer_id = PublicKey::from_str(
            "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc",
        )
        .unwrap();

        let req = DummyCall {
            foo: String::from("hello world!"),
            bar: 13,
        };

        let expected_res = DummyResponse {
            foo: String::from("hello client!"),
            bar: 10,
        };

        let res_obj = JsonRpcResponse::success(&expected_res, "my-id-123");
        let res_str = serde_json::to_string(&res_obj).unwrap();

        let transport = TestTransport {
            req: Arc::new(OnceCell::const_new()),
            res: Arc::new(Some(res_str)),
            err: Arc::new(None),
        };

        let client_1 = JsonRpcClient::new(transport.clone());
        let res = client_1
            .call_typed::<_, DummyResponse>(&peer_id, req.clone())
            .await
            .expect("Should have an OK result")
            .expect("Should not be a JSON-RPC error");
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
        let peer_id = PublicKey::from_str(
            "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc",
        )
        .unwrap();

        let req = DummyCall {
            foo: "hello world!".into(),
            bar: 13,
        };

        let err_res = RpcError::custom_error_with_data(
            -32099,
            "got a custom error",
            serde_json::json!({"got": "some"}),
        );

        let res_obj = JsonRpcResponse::error(err_res.clone(), "unique-id-123");
        let res_str = serde_json::to_string(&res_obj).unwrap();

        let transport = TestTransport {
            req: Arc::new(OnceCell::const_new()),
            res: Arc::new(Some(res_str)),
            err: Arc::new(None),
        };

        let client_1 = JsonRpcClient::new(transport);
        let res = client_1
            .call_typed::<_, DummyResponse>(&peer_id, req)
            .await
            .expect("only inner rpc error")
            .expect_err("expect rpc error");
        assert_eq!(res, err_res);
    }

    #[tokio::test]
    async fn test_typed_call_w_internal_error() {
        let peer_id = PublicKey::from_str(
            "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc",
        )
        .unwrap();

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
            .call_typed::<_, DummyResponse>(&peer_id, req)
            .await
            .expect_err("Expected error response");
        assert!(matches!(res, Error::Internal(..)));
    }
}
