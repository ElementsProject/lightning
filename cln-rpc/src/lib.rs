//! # A Core Lightning RPC-client
//!
//! Core Lightning exposes a JSON-RPC interface over unix-domain sockets.
//! The unix-domain socket appears like file and located by default in
//! `~/.lightning/<network>/lightning-rpc`.
//!
//! This crate contains an RPC-client called [ClnRpc] and models
//! for most [requests](crate::model::requests) and [responses](crate::model::responses).
//!
//! The example below shows how to initiate the client and celss the `getinfo`-rpc method.
//!
//! ```no_run
//! use std::path::Path;
//! use tokio_test;
//! use cln_rpc::{ClnRpc, TypedRequest};
//! use cln_rpc::model::requests::GetinfoRequest;
//! use cln_rpc::model::responses::GetinfoResponse;
//!
//! tokio_test::block_on( async {
//!     let path = Path::new("path_to_lightning_dir");
//!     let mut rpc = ClnRpc::new(path).await.unwrap();
//!     let request = GetinfoRequest {};
//!     let response : GetinfoResponse = rpc.call_typed(&request).await.unwrap();
//! });
//! ```
//!
//! If the required model is not available you can implement [`TypedRequest`]
//! and use [`ClnRpc::call_typed`] without a problem.
//!
//! ```no_run
//! use std::path::Path;
//! use tokio_test;
//! use cln_rpc::{ClnRpc, TypedRequest};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Debug)]
//! struct CustomMethodRequest {
//!     param_a : String
//! };
//! #[derive(Deserialize, Debug)]
//! struct CustomMethodResponse {
//!     field_a : String
//! };
//!
//! impl TypedRequest for CustomMethodRequest {
//!     type Response = CustomMethodResponse;
//!
//!     fn method(&self) -> &str {
//!         "custommethod"
//!     }
//! }
//!
//! tokio_test::block_on( async {
//!     let path = Path::new("path_to_lightning_dir");
//!     let mut rpc = ClnRpc::new(path).await.unwrap();
//!
//!     let request = CustomMethodRequest { param_a : String::from("example")};
//!     let response = rpc.call_typed(&request).await.unwrap();
//! })
//! ```
//!
//! An alternative is to use [`ClnRpc::call_raw`].
//!
//! ```no_run
//! use std::path::Path;
//! use tokio_test;
//! use cln_rpc::{ClnRpc, TypedRequest};
//!
//! tokio_test::block_on( async {
//!     let path = Path::new("path_to_lightning_dir");
//!     let mut rpc = ClnRpc::new(path).await.unwrap();
//!     let method = "custommethod";
//!     let request = serde_json::json!({"param_a" : "example"});
//!     let response : serde_json::Value = rpc.call_raw(method, &request).await.unwrap();
//! })
//! ```
//!
use crate::codec::JsonCodec;
pub use anyhow::Error;
use anyhow::Result;
use core::fmt::Debug;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use log::{debug, trace};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

pub mod codec;
pub mod jsonrpc;
pub mod model;
pub mod notifications;
pub mod primitives;

pub use crate::model::TypedRequest;
pub use crate::{
    model::{Request, Response},
    notifications::Notification,
    primitives::RpcError,
};

/// An RPC-client for Core Lightning
///
///
///
pub struct ClnRpc {
    next_id: AtomicUsize,

    #[allow(dead_code)]
    read: FramedRead<OwnedReadHalf, JsonCodec>,
    write: FramedWrite<OwnedWriteHalf, JsonCodec>,
}

impl ClnRpc {
    pub async fn new<P>(path: P) -> Result<ClnRpc>
    where
        P: AsRef<Path>,
    {
        debug!(
            "Connecting to socket at {}",
            path.as_ref().to_string_lossy()
        );
        ClnRpc::from_stream(UnixStream::connect(path).await?)
    }

    fn from_stream(stream: UnixStream) -> Result<ClnRpc> {
        let (read, write) = stream.into_split();

        Ok(ClnRpc {
            next_id: AtomicUsize::new(1),
            read: FramedRead::new(read, JsonCodec::default()),
            write: FramedWrite::new(write, JsonCodec::default()),
        })
    }

    /// Low-level API to call the rpc.
    ///
    /// An interesting choice of `R` and `P` is [`serde_json::Value`] because it allows
    /// ad-hoc calls to custom RPC-methods
    ///
    /// If you are using a model such as [`crate::model::requests::GetinfoRequest`] you'd
    /// probably want to use [`Self::call_typed`] instead.
    ///
    /// Example:
    /// ```no_run
    /// use cln_rpc::ClnRpc;
    /// use cln_rpc::model::{requests::GetinfoRequest, responses::GetinfoResponse, responses::ListfundsResponse};
    /// use std::path::Path;
    /// use tokio_test;
    /// tokio_test::block_on( async {
    ///
    ///    // Call using json-values
    ///    let mut cln = ClnRpc::new(Path::new("./lightningd/rpc")).await.unwrap();
    ///    let request = serde_json::json!({});
    ///    let response : serde_json::Value = cln.call_raw("getinfo", &request).await.unwrap();
    ///
    ///    // Using a model
    ///    // Prefer to use call_typed instead
    ///    let request = GetinfoRequest {};
    ///    let response : GetinfoResponse = cln.call_raw("getinfo", &request).await.unwrap();
    /// })
    /// ```
    pub async fn call_raw<R, P>(&mut self, method: &str, params: &P) -> Result<R, RpcError>
    where
        P: Serialize + Debug,
        R: DeserializeOwned + Debug,
    {
        trace!("Sending request {} with params {:?}", method, &params);
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // TODO: Can we make this nicer
        // I don't want to have this json_rpc : 2.0 floating everywhere
        let req = serde_json::json!({
            "jsonrpc" : "2.0",
            "id" : id,
            "method" : method,
            "params" : params,
        });

        let response: serde_json::Value = self.call_raw_request(req).await?;

        serde_json::from_value(response).map_err(|e| RpcError {
            code: None,
            message: format!("Failed to parse response {:?}", e),
            data: None,
        })
    }

    /// A low level method to call raw requests
    ///
    /// This method is private by intention.
    /// The caller is (implicitly) providing the `id` of the JsonRpcRequest.
    /// This is dangerous because the caller might pick a non-unique id.
    ///
    /// The request should serialize to a valid JsonRpcMessage.
    /// If the response is succesful the content of the "result" field is returned
    /// If the response is an error the content of the "error" field is returned
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use cln_rpc::ClnRpc;
    /// use tokio_test;
    /// tokio_test::block_on( async {
    ///     let request = serde_json::json!({
    ///       "id" : 1,
    ///       "jsonrpc" : "2.0",
    ///       "method" : "some_method",
    ///       "params" : {}
    ///      }
    ///     );
    ///     let rpc = ClnRpc::new(Path::new("my_path_to_rpc_file"));
    ///     // let resp : serde_json::Value = rpc.call_raw_request(request).await.unwrap();
    /// })
    /// ```
    ///
    async fn call_raw_request(
        &mut self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError>
where {
        trace!("Sending request {:?}", request);
        self.write.send(request).await.map_err(|e| RpcError {
            code: None,
            message: format!("Error passing request to lightningd: {}", e),
            data: None,
        })?;

        let mut response: serde_json::Value = self
            .read
            .next()
            .await
            .ok_or_else(|| RpcError {
                code: None,
                message: "no response from lightningd".to_string(),
                data: None,
            })?
            .map_err(|_| RpcError {
                code: None,
                message: "reading response from socket".to_string(),
                data: None,
            })?;

        match response.get("result") {
            Some(_) => Ok(response["result"].take()),
            None => {
                let _ = response.get("error").ok_or(
                    RpcError {
                        code : None,
                        message : "Invalid response from lightningd. Neither `result` or `error` field is present".to_string(),
                        data : None
                    })?;
                let rpc_error: RpcError = serde_json::from_value(response["error"].take())
                    .map_err(|e| RpcError {
                        code: None,
                        message: format!(
                            "Invalid response from lightningd. Failed to parse `error`. {:?}",
                            e
                        ),
                        data: None,
                    })?;
                Err(rpc_error)
            }
        }
    }

    pub async fn call(&mut self, req: Request) -> Result<Response, RpcError> {
        self.call_enum(req).await
    }

    /// Performs an rpc-call
    pub async fn call_enum(&mut self, req: Request) -> Result<Response, RpcError> {
        trace!("call : Serialize and deserialize request {:?}", req);
        // A little bit hacky. But serialize the request to get the method name
        let mut ser = serde_json::to_value(&req).unwrap();
        let method: String = if let serde_json::Value::String(method) = ser["method"].take() {
            method
        } else {
            panic!("Method should be string")
        };
        let params: serde_json::Value = ser["params"].take();

        let response: serde_json::Value = self.call_raw(&method, &params).await?;
        let response = serde_json::json!({
            "method" : method,
            "result" : response
        });

        // Parse the response
        // We add the `method` here because the Response-enum uses it to determine the type
        serde_json::from_value(response).map_err(|e| RpcError {
            code: None,
            message: format!("Failed to deserialize response : {}", e),
            data: None,
        })
    }

    /// Performs an rpc-call and performs type-checking.
    ///
    /// ```no_run
    /// use cln_rpc::ClnRpc;
    /// use cln_rpc::model::requests::GetinfoRequest;
    /// use std::path::Path;
    /// use tokio_test;
    /// tokio_test::block_on( async {
    ///    let mut rpc = ClnRpc::new(Path::new("path_to_rpc")).await.unwrap();
    ///    let request = GetinfoRequest {};
    ///    let response = rpc.call_typed(&request);
    /// })
    /// ```
    pub async fn call_typed<R>(&mut self, request: &R) -> Result<R::Response, RpcError>
    where
        R: TypedRequest + Serialize + std::fmt::Debug,
        R::Response: DeserializeOwned + std::fmt::Debug,
    {
        let method = request.method();
        self.call_raw::<R::Response, R>(method, request).await
    }
}

/// Used to skip optional arrays when serializing requests.
fn is_none_or_empty<T>(f: &Option<Vec<T>>) -> bool
where
    T: Clone,
{
    f.as_ref().map_or(true, |value| value.is_empty())
}

#[cfg(test)]
mod test {
    use self::notifications::{BlockAddedNotification, CustomMsgNotification};

    use super::*;
    use crate::model::*;
    use crate::primitives::PublicKey;
    use futures_util::StreamExt;
    use serde_json::json;
    use std::str::FromStr;
    use tokio_util::codec::{Framed, FramedRead};

    #[tokio::test]
    async fn call_raw_request() {
        // Set up a pair of unix-streams
        // The frame is a mock rpc-server
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();
        let mut frame = Framed::new(uds2, JsonCodec::default());

        // Define the request and response send in the RPC-message
        let rpc_request = serde_json::json!({
            "id" : 1,
            "jsonrpc" : "2.0",
            "params" : {},
            "method" : "some_method"
        });
        let rpc_request2 = rpc_request.clone();

        let rpc_response = serde_json::json!({
            "jsonrpc" : "2.0",
            "id" : "1",
            "result" : {"field_6" : 6}
        });

        // Spawn the task that performs the RPC-call
        // Check that it reads the response correctly
        let handle = tokio::task::spawn(async move { cln.call_raw_request(rpc_request2).await });

        // Verify that our emulated server received a request
        // and sendt the response
        let read_req = dbg!(frame.next().await.unwrap().unwrap());
        assert_eq!(&rpc_request, &read_req);
        frame.send(rpc_response).await.unwrap();

        // Get the result from `call_raw_request` and verify
        let actual_response: Result<serde_json::Value, RpcError> = handle.await.unwrap();
        let actual_response = actual_response.unwrap();
        assert_eq!(actual_response, json!({"field_6" : 6}));
    }

    #[tokio::test]
    async fn call_raw() {
        let req = serde_json::json!({});
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();

        let mut read = FramedRead::new(uds2, JsonCodec::default());
        tokio::task::spawn(async move {
            let _: serde_json::Value = cln.call_raw("getinfo", &req).await.unwrap();
        });

        let read_req = dbg!(read.next().await.unwrap().unwrap());

        assert_eq!(
            json!({"id": 1, "method": "getinfo", "params": {}, "jsonrpc": "2.0"}),
            read_req
        );
    }

    #[tokio::test]
    async fn test_call_enum_remote_error() {
        // Set up the rpc-connection
        // The frame represents a Mock rpc-server
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();
        let mut frame = Framed::new(uds2, JsonCodec::default());

        // Construct the request and response
        let req = Request::Ping(requests::PingRequest {
            id: PublicKey::from_str(
                "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
            )
            .unwrap(),
            len: None,
            pongbytes: None,
        });

        let mock_resp = json!({
            "id" : 1,
            "jsonrpc" : "2.0",
            "error" : {
                "code" : 666,
                "message" : "MOCK_ERROR"
            }
        });

        // Spawn the task which calls the rpc
        let handle = tokio::task::spawn(async move { cln.call(req).await });

        // Ensure the mock receives the request and returns a response
        let _ = dbg!(frame.next().await.unwrap().unwrap());
        frame.send(mock_resp).await.unwrap();

        let rpc_response: Result<_, RpcError> = handle.await.unwrap();
        let rpc_error: RpcError = rpc_response.unwrap_err();

        println!("RPC_ERROR : {:?}", rpc_error);
        assert_eq!(rpc_error.code.unwrap(), 666);
        assert_eq!(rpc_error.message, "MOCK_ERROR");
    }

    #[tokio::test]
    async fn test_call_enum() {
        // Set up the rpc-connection
        // The frame represents a Mock rpc-server
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();
        let mut frame = Framed::new(uds2, JsonCodec::default());

        // We'll use the Ping request here because both the request
        // and response have few arguments
        let req = Request::Ping(requests::PingRequest {
            id: PublicKey::from_str(
                "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
            )
            .unwrap(),
            len: None,
            pongbytes: None,
        });
        let mock_resp = json!({
            "id" : 1,
            "jsonrpc" : "2.0",
            "result" : { "totlen" : 123 }
        });

        // we create a task that sends the response and returns the response
        let handle = tokio::task::spawn(async move { cln.call(req).await });

        // Ensure our mock receives the request and sends the response
        let read_req = dbg!(frame.next().await.unwrap().unwrap());
        assert_eq!(
            read_req,
            json!({"id" : 1, "jsonrpc" : "2.0", "method" : "ping", "params" : {"id" : "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b"}})
        );
        frame.send(mock_resp).await.unwrap();

        // Verify that the error response is correct
        let rpc_response: Result<_, RpcError> = handle.await.unwrap();
        match rpc_response.unwrap() {
            Response::Ping(ping) => {
                assert_eq!(ping.totlen, 123);
            }
            _ => panic!("A Request::Getinfo should return Response::Getinfo"),
        }
    }

    #[tokio::test]
    async fn test_call_typed() {
        // Set up the rpc-connection
        // The frame represents a Mock rpc-server
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();
        let mut frame = Framed::new(uds2, JsonCodec::default());

        // We'll use the Ping request here because both the request
        // and response have few arguments
        let req = requests::PingRequest {
            id: PublicKey::from_str(
                "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
            )
            .unwrap(),
            len: None,
            pongbytes: None,
        };
        let mock_resp = json!({
            "id" : 1,
            "jsonrpc" : "2.0",
            "result" : { "totlen" : 123 }
        });

        // we create a task that sends the response and returns the response
        let handle = tokio::task::spawn(async move { cln.call_typed(&req).await });

        // Ensure our mock receives the request and sends the response
        _ = dbg!(frame.next().await.unwrap().unwrap());
        frame.send(mock_resp).await.unwrap();

        // Verify that the error response is correct
        let rpc_response: Result<_, RpcError> = handle.await.unwrap();
        let ping_response = rpc_response.unwrap();
        assert_eq!(ping_response.totlen, 123);
    }

    #[tokio::test]
    async fn test_call_typed_remote_error() {
        // Create a dummy rpc-request
        let req = requests::GetinfoRequest {};

        // Create a dummy error response
        let response = json!({
        "id" : 1,
        "jsonrpc" : "2.0",
        "error" : {
            "code" : 666,
            "message" : "MOCK_ERROR",
        }});

        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();

        // Send out the request
        let mut frame = Framed::new(uds2, JsonCodec::default());

        let handle = tokio::task::spawn(async move { cln.call_typed(&req).await });

        // Dummy-server ensures the request has been received and send the error response
        let _ = dbg!(frame.next().await.unwrap().unwrap());
        frame.send(response).await.unwrap();

        let rpc_response = handle.await.unwrap();
        let rpc_error = rpc_response.expect_err("Must be an RPC-error response");

        assert_eq!(rpc_error.code.unwrap(), 666);
        assert_eq!(rpc_error.message, "MOCK_ERROR");
    }

    #[test]
    fn serialize_custom_msg_notification() {
        let msg = CustomMsgNotification {
            peer_id : PublicKey::from_str("0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b").unwrap(),
            payload : String::from("941746573749")
        };

        let notification = Notification::CustomMsg(msg);

        assert_eq!(
            serde_json::to_value(notification).unwrap(),
            serde_json::json!(
                {
                    "custommsg" : {
                        "peer_id" : "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
                        "payload" : "941746573749"
                    }
                }
            )
        );

    }

    #[test]
    fn serialize_block_added_notification() {
        let block_added = BlockAddedNotification {
            hash : crate::primitives::Sha256::from_str("000000000000000000000acab8abe0c67a52ed7e5a90a19c64930ff11fa84eca").unwrap(),
            height : 830702
        };

        let notification = Notification::BlockAdded(block_added);

        assert_eq!(
            serde_json::to_value(notification).unwrap(),
            serde_json::json!({
                "block_added" : {
                    "hash" : "000000000000000000000acab8abe0c67a52ed7e5a90a19c64930ff11fa84eca",
                    "height" : 830702
                }
            })
        )
    }

    #[test]
    fn deserialize_connect_notification() {
        let connect_json = serde_json::json!({
            "connect" :  {
                "address" : {
                    "address" : "127.0.0.1",
                    "port" : 38012,
                    "type" : "ipv4"
                },
                "direction" : "in",
                "id" : "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
            }
        });

        let _ : Notification = serde_json::from_value(connect_json).unwrap();
    }
}
