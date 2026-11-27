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
use crate::codec::{RawJsonEncoder, RawMultiLineCodec};
pub use anyhow::Error;
use anyhow::Result;
use core::fmt::Debug;
use futures_util::StreamExt;
use futures_util::sink::SinkExt;
use log::{debug, trace};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
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
    dirty_write: bool,

    #[allow(dead_code)]
    read: FramedRead<OwnedReadHalf, RawMultiLineCodec>,
    write: FramedWrite<OwnedWriteHalf, RawJsonEncoder>,
}

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize + ?Sized> {
    jsonrpc: &'static str,
    id: usize,
    method: &'a str,
    params: &'a P,
}

fn deserialize_present_raw<'de, D>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <&'de RawValue>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct RawRpcResponse<'a> {
    #[serde(default, borrow, deserialize_with = "deserialize_present_raw")]
    id: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "deserialize_present_raw")]
    result: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "deserialize_present_raw")]
    error: Option<&'a RawValue>,
}

#[derive(Copy, Clone, Debug)]
enum ExpectedId<'a> {
    Usize(usize),
    Value(&'a serde_json::Value),
}

enum IdMatch {
    Match,
    Stale,
    Mismatch,
}

fn match_response_id(raw_id: &RawValue, expected: ExpectedId<'_>) -> IdMatch {
    match expected {
        ExpectedId::Usize(exp) => match raw_id.get().parse::<u64>() {
            Ok(got) if got == exp as u64 => IdMatch::Match,
            Ok(got) if got < exp as u64 => IdMatch::Stale,
            _ => IdMatch::Mismatch,
        },
        ExpectedId::Value(exp) => match serde_json::from_str::<serde_json::Value>(raw_id.get()) {
            Ok(ref got) if got == exp => IdMatch::Match,
            Ok(ref got)
                if matches!(
                    (got.as_u64(), exp.as_u64()),
                    (Some(g), Some(e)) if g < e
                ) =>
            {
                IdMatch::Stale
            }
            _ => IdMatch::Mismatch,
        },
    }
}

/// Deserializes a `#[serde(tag = "method", content = "result")]` enum (such as
/// `Response`) directly from a method name and a raw JSON slice without building
/// an intermediate `serde_json::Value` DOM tree.
struct TaggedRawDeserializer<'a> {
    method: &'a str,
    raw: &'a str,
}

impl<'de> serde::de::Deserializer<'de> for TaggedRawDeserializer<'de> {
    type Error = serde_json::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        struct TaggedMapAccess<'de> {
            method: &'de str,
            raw: &'de str,
            step: u8,
        }

        impl<'de> serde::de::MapAccess<'de> for TaggedMapAccess<'de> {
            type Error = serde_json::Error;

            fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
            where
                K: serde::de::DeserializeSeed<'de>,
            {
                match self.step {
                    0 => {
                        self.step = 1;
                        seed.deserialize(serde::de::value::BorrowedStrDeserializer::new("method"))
                            .map(Some)
                    }
                    1 => {
                        self.step = 2;
                        seed.deserialize(serde::de::value::BorrowedStrDeserializer::new("result"))
                            .map(Some)
                    }
                    _ => Ok(None),
                }
            }

            fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
            where
                V: serde::de::DeserializeSeed<'de>,
            {
                match self.step {
                    1 => seed
                        .deserialize(serde::de::value::BorrowedStrDeserializer::new(self.method)),
                    2 => {
                        let mut de = serde_json::Deserializer::from_str(self.raw);
                        let val = seed.deserialize(&mut de)?;
                        de.end()?;
                        Ok(val)
                    }
                    _ => unreachable!(),
                }
            }
        }

        visitor.visit_map(TaggedMapAccess {
            method: self.method,
            raw: self.raw,
            step: 0,
        })
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct struct enum identifier ignored_any
    }
}

fn extract_raw_result<'a>(envelope: RawRpcResponse<'a>) -> Result<&'a RawValue, RpcError> {
    if let Some(result) = envelope.result {
        Ok(result)
    } else if let Some(error) = envelope.error {
        let rpc_error: RpcError = serde_json::from_str(error.get()).map_err(|e| RpcError {
            code: None,
            message: format!(
                "Invalid response from lightningd. Failed to parse `error`. {:?}",
                e
            ),
            data: None,
        })?;
        Err(rpc_error)
    } else {
        Err(RpcError {
            code: None,
            message:
                "Invalid response from lightningd. Neither `result` or `error` field is present"
                    .to_string(),
            data: None,
        })
    }
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
            dirty_write: false,
            read: FramedRead::new(read, RawMultiLineCodec::default()),
            write: FramedWrite::new(write, RawJsonEncoder),
        })
    }

    async fn send_and_read_response<T, R, F>(
        &mut self,
        request: &T,
        expected_id: ExpectedId<'_>,
        parse_result: F,
    ) -> Result<R, RpcError>
    where
        T: Serialize,
        F: FnOnce(&RawValue) -> Result<R, RpcError>,
    {
        if self.dirty_write {
            SinkExt::<&()>::flush(&mut self.write)
                .await
                .map_err(|e| RpcError {
                    code: None,
                    message: format!("Error flushing previous request to lightningd: {}", e),
                    data: None,
                })?;
            self.dirty_write = false;
        }

        self.dirty_write = true;
        self.write.send(request).await.map_err(|e| RpcError {
            code: None,
            message: format!("Error passing request to lightningd: {}", e),
            data: None,
        })?;
        self.dirty_write = false;

        loop {
            let frame = self
                .read
                .next()
                .await
                .ok_or_else(|| RpcError {
                    code: None,
                    message: "no response from lightningd".to_string(),
                    data: None,
                })?
                .map_err(|e| RpcError {
                    code: None,
                    message: format!("Error reading response from socket: {}", e),
                    data: None,
                })?;

            let envelope: RawRpcResponse<'_> =
                serde_json::from_slice(&frame).map_err(|e| RpcError {
                    code: None,
                    message: format!("Error reading response from socket: {}", e),
                    data: None,
                })?;

            match envelope.id {
                Some(raw_id) => match match_response_id(raw_id, expected_id) {
                    IdMatch::Match => return extract_raw_result(envelope).and_then(parse_result),
                    IdMatch::Stale => {
                        debug!(
                            "Discarding stale response for cancelled request id {} (expected {:?})",
                            raw_id.get(),
                            expected_id
                        );
                    }
                    IdMatch::Mismatch => {
                        let data = serde_json::from_slice(&frame).ok();
                        return Err(RpcError {
                            code: None,
                            message: format!(
                                "Unexpected response id {} from lightningd (expected {:?})",
                                raw_id.get(),
                                expected_id
                            ),
                            data,
                        });
                    }
                },
                None => {
                    debug!(
                        "Ignoring notification without `id` while awaiting {:?}",
                        expected_id
                    );
                }
            }
        }
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

        let req = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        self.send_and_read_response(&req, ExpectedId::Usize(id), |raw_result| {
            serde_json::from_str(raw_result.get()).map_err(|e| RpcError {
                code: None,
                message: format!("Failed to parse response {:?}", e),
                data: None,
            })
        })
        .await
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
    #[allow(dead_code)]
    async fn call_raw_request(
        &mut self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let expected_id = request.get("id").ok_or_else(|| RpcError {
            code: None,
            message: "Request is missing an `id` field".to_string(),
            data: None,
        })?;

        trace!("Sending request {:?}", request);
        self.send_and_read_response(&request, ExpectedId::Value(expected_id), |raw_result| {
            serde_json::from_str(raw_result.get()).map_err(|e| RpcError {
                code: None,
                message: format!("Failed to parse response {:?}", e),
                data: None,
            })
        })
        .await
    }

    pub async fn call(&mut self, req: Request) -> Result<Response, RpcError> {
        self.call_enum(req).await
    }

    /// Performs an rpc-call
    pub async fn call_enum(&mut self, req: Request) -> Result<Response, RpcError> {
        trace!("call : Serialize and deserialize request {:?}", req);
        #[derive(Deserialize)]
        struct RequestParts<'a> {
            method: &'a str,
            #[serde(borrow)]
            params: &'a RawValue,
        }

        let req_bytes = serde_json::to_vec(&req).map_err(|e| RpcError {
            code: None,
            message: format!("Failed to serialize request: {}", e),
            data: None,
        })?;
        let parts: RequestParts<'_> = serde_json::from_slice(&req_bytes).map_err(|e| RpcError {
            code: None,
            message: format!("Failed to inspect serialized request: {}", e),
            data: None,
        })?;

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let rpc_req = RpcRequest {
            jsonrpc: "2.0",
            id,
            method: parts.method,
            params: parts.params,
        };

        self.send_and_read_response(&rpc_req, ExpectedId::Usize(id), |raw_result| {
            Response::deserialize(TaggedRawDeserializer {
                method: parts.method,
                raw: raw_result.get(),
            })
            .map_err(|e| RpcError {
                code: None,
                message: format!("Failed to deserialize response : {}", e),
                data: None,
            })
        })
        .await
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
