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

use crate::model::TypedRequest;
pub use crate::{
    model::{Request, Response},
    notifications::Notification,
    primitives::RpcError,
};

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
    /// It is the responsibility of the caller to pick valid types `R` and `P`.
    /// It's useful for ad-hoc calls to methods that are not present in [`crate::model`].
    /// Users can use [`serde_json::Value`] and don't have to implement any custom structs.
    /// 
    /// Most users would prefer to use [call_typed](crate::ClnRpc::call_typed) instead.
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
    ///    let response : serde_json::Value = cln.call_raw("getinfo", request).await.unwrap();
    ///
    ///    // Using a model
    ///    // Prefer to use call_typed instead
    ///    let request = GetinfoRequest {};
    ///    let response : GetinfoResponse = cln.call_raw("getinfo", request.clone()).await.unwrap();
   /// })
    /// ```
    pub async fn call_raw<R, P>(&mut self, method: &str, params: P) -> Result<R, RpcError>
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

        let mut response: serde_json::Value = self.call_raw_request(&req).await?;
        trace!("Read response {:?}", response);

        // Annotate the response with the method from the request, so
        // serde_json knows which variant of [`Request`] should be
        // used.
        response["method"] = serde_json::Value::String(method.into());
        if let Some(_) = response.get("result") {
            serde_json::from_value(response).map_err(|e| RpcError {
                code: None,
                message: format!("Malformed response from lightningd: {}", e),
                data: None,
            })
        } else if let Some(e) = response.get("error") {
            let e: RpcError = serde_json::from_value(e.clone()).unwrap();
            Err(e)
        } else {
            Err(RpcError {
                code: None,
                message: format!("Malformed response from lightningd: {}", response),
                data: None,
            })
        }
    }

    /// A low level method to call raw reqeusts
    ///
    /// This method is private by intention.
    /// The caller is (implicitly) providing the `id` of the JsonRpcRequest.
    /// This is dangerous because the caller might pick a non-unique id.
    ///
    /// The request should serialize to a valid JsonRpcMessage and the response
    /// should be able to deserialize any successful JsonRpcResponse.
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
    async fn call_raw_request<Req, Resp>(&mut self, request: &Req) -> Result<Resp, RpcError>
    where
        Req: Serialize + Debug,
        Resp: DeserializeOwned,
    {
        trace!("Sending request {:?}", request);
        let request = serde_json::to_value(request).unwrap();
        self.write.send(request).await.map_err(|e| RpcError {
            code: None,
            message: format!("Error passing request to lightningd: {}", e),
            data: None,
        })?;

        let response = self
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

        serde_json::from_value(response).map_err(|_| RpcError {
            code: None,
            message: "Failed to parse response".to_string(),
            data: None,
        })
    }

    pub async fn call(&mut self, req: Request) -> Result<Response, RpcError> {
        self.call_enum(req).await
    }

    /// Performs an rpc-call
    pub async fn call_enum(&mut self, req: Request) -> Result<Response, RpcError> {
        trace!("call : Serialize and deserialize request {:?}", req);
        // Construct the full JsonRpcRequest
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut value = serde_json::to_value(req).map_err(|e| RpcError {
            code: None,
            message: format!("Failed to serialize request: {}", e),
            data: None,
        })?;
        value["jsonrpc"] = "2.0".into();
        value["id"] = id.into();
        let method = value["method"].clone();

        //
        let mut response: serde_json::Value = self.call_raw_request(&value).await?;

        // Parse the response
        // We add the `method` here because the Response-enum uses it to determine the type
        response["method"] = method;
        serde_json::from_value(response).map_err(|e| RpcError {
            code: None,
            message: format!("Failed to deserializer response : {}", e),
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
    ///    let response = rpc.call_typed(request);
    /// })
    /// ```
    pub async fn call_typed<R>(&mut self, request: R) -> Result<R::Response, RpcError>
    where
        R: TypedRequest + Serialize + std::fmt::Debug,
        R::Response: DeserializeOwned + std::fmt::Debug,
    {
        let method = request.method();
        self.call_raw(method, &request).await?
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
    use super::*;
    use crate::model::*;
    use futures_util::StreamExt;
    use serde_json::json;
    use tokio_util::codec::{Framed, FramedRead};

    #[tokio::test]
    async fn call_raw_request() {
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
        let rpc_response2 = rpc_response.clone();

        // Set up a pair of unix-streams
        // The ClnRpc will read and write from usd1
        // Im our test will read and write from usd2 and emulate Core Lightning behavior
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();

        // Open the test dummy reader
        let mut frame = Framed::new(uds2, JsonCodec::default());

        // Spawn the task that performs the RPC-call
        tokio::task::spawn(async move {
            let returned: serde_json::Value = cln.call_raw_request(&rpc_request2).await.unwrap();
            assert_eq!(&returned, &rpc_response2)
        });

        // Verify that our emulated server received a request
        let read_req = dbg!(frame.next().await.unwrap().unwrap());
        assert_eq!(&rpc_request, &read_req);

        frame.send(rpc_response).await.unwrap();
    }

    #[tokio::test]
    async fn call_raw() {
        let req = serde_json::json!({});
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();

        let mut read = FramedRead::new(uds2, JsonCodec::default());
        tokio::task::spawn(async move {
            let _: serde_json::Value = cln.call_raw("getinfo", req).await.unwrap();
        });

        let read_req = dbg!(read.next().await.unwrap().unwrap());

        assert_eq!(
            json!({"id": 1, "method": "getinfo", "params": {}, "jsonrpc": "2.0"}),
            read_req
        );
    }

    #[tokio::test]
    async fn test_call() {
        let req = Request::Getinfo(requests::GetinfoRequest {});
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();

        let mut read = FramedRead::new(uds2, JsonCodec::default());
        tokio::task::spawn(async move {
            cln.call(req).await.unwrap();
        });

        let read_req = dbg!(read.next().await.unwrap().unwrap());

        assert_eq!(
            json!({"id": 1, "method": "getinfo", "params": {}, "jsonrpc": "2.0"}),
            read_req
        );
    }

    #[tokio::test]
    async fn test_typed_call() {
        let req = requests::GetinfoRequest {};
        let (uds1, uds2) = UnixStream::pair().unwrap();
        let mut cln = ClnRpc::from_stream(uds1).unwrap();

        let mut read = FramedRead::new(uds2, JsonCodec::default());
        tokio::task::spawn(async move {
            let _: responses::GetinfoResponse = cln.call_typed(req).await.unwrap();
        });

        let read_req = dbg!(read.next().await.unwrap().unwrap());

        assert_eq!(
            json!({"id": 1, "method": "getinfo", "params": {}, "jsonrpc": "2.0"}),
            read_req
        );
    }
}
