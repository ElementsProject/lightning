use anyhow::{Context, Error, Result};
use cln_plugins::codec::JsonCodec;
use cln_plugins::codec::JsonRpc;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use log::{debug, trace};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, FramedWrite};

pub mod notifications;
pub mod primitives;
pub mod requests;
pub mod responses;

pub use crate::{notifications::Notification, requests::Request, responses::Response};

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

    pub async fn call(&mut self, req: Request) -> Result<Response, Error> {
        trace!("Sending request {:?}", req);

        // Wrap the raw request in a well-formed JSON-RPC outer dict.
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req: JsonRpc<Notification, Request> = dbg!(JsonRpc::Request(id, req));
        let req = serde_json::to_value(req)?;
	let req2 = req.clone();
        self.write.send(req).await?;

        let mut response = self
            .read
            .next()
            .await
            .context("no response from lightningd")?
            .context("reading response from socket")?;
        trace!("Read response {:?}", response);

        // Annotate the response with the method from the request, so
        // serde_json knows which variant of [`Request`] should be
        // used.
	response["method"] = req2["method"].clone();

        serde_json::from_value(response).context("converting response into enum")
    }
}

mod codec {
    use crate::JsonCodec;
    use crate::{notifications::Notification, requests::Request};
    use anyhow::Error;
    use bytes::BytesMut;
    use cln_plugins::codec::JsonRpc;
    use tokio_util::codec::Decoder;

    /// A codec that reads fully formed [crate::messages::JsonRpc]
    /// messages. Internally it uses the [JsonCodec] which itself is built
    /// on the [MultiLineCodec].
    #[derive(Default)]
    pub(crate) struct JsonRpcCodec {
        inner: JsonCodec,
    }

    impl Decoder for JsonRpcCodec {
        type Item = JsonRpc<Notification, Request>;
        type Error = Error;

        fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Error> {
            match self.inner.decode(buf) {
                Ok(None) => Ok(None),
                Err(e) => Err(e),
                Ok(Some(s)) => {
                    let req: Self::Item = serde_json::from_value(s)?;
                    Ok(Some(req))
                }
            }
        }
    }
}

