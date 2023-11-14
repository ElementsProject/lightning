use crate::codec::JsonCodec;
use crate::codec::JsonRpc;
pub use anyhow::Error;
use anyhow::Result;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use log::{debug, trace};
use serde_json::json;
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

use crate::model::IntoRequest;
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

    pub async fn call(&mut self, req: Request) -> Result<Response, RpcError> {
        trace!("Sending request {:?}", req);

        // Wrap the raw request in a well-formed JSON-RPC outer dict.
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req: JsonRpc<Notification, Request> = JsonRpc::Request(json!(id), req);
        let req = serde_json::to_value(req).map_err(|e| RpcError {
            code: None,
            message: format!("Error parsing request: {}", e),
            data: None,
        })?;
        let req2 = req.clone();
        self.write.send(req).await.map_err(|e| RpcError {
            code: None,
            message: format!("Error passing request to lightningd: {}", e),
            data: None,
        })?;

        let mut response = self
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
        trace!("Read response {:?}", response);

        // Annotate the response with the method from the request, so
        // serde_json knows which variant of [`Request`] should be
        // used.
        response["method"] = req2["method"].clone();
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

    pub async fn call_typed<R: IntoRequest>(
        &mut self,
        request: R,
    ) -> Result<R::Response, RpcError> {
        Ok(self
            .call(request.into())
            .await?
            .try_into()
            .expect("CLN will reply correctly"))
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
