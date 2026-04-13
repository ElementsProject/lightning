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
use futures_util::StreamExt;
use futures_util::sink::SinkExt;
use log::{debug, trace};
use serde::{Serialize, de::DeserializeOwned};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

pub mod codec;
pub mod hooks;
pub mod jsonrpc;
pub mod model;
pub mod notifications;
pub mod primitives;

#[cfg(test)]
mod test;

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
