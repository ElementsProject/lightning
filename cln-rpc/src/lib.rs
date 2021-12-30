use anyhow::{Error, Result};
use std::path::Path;
mod primitives;
mod responses;

#[macro_use]
extern crate serde_json;
///
pub struct ClnRpc {}

impl ClnRpc {
    pub fn new<P>(path: P) -> Result<ClnRpc>
    where
        P: AsRef<Path>,
    {
        todo!();
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

