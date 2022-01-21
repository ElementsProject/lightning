use crate::codec::{JsonCodec, JsonRpcCodec};
pub use anyhow::Error;
use futures::sink::SinkExt;
extern crate log;
use log::{trace, warn};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tokio_util::codec::FramedWrite;

pub mod codec;
pub mod logging;
mod messages;

#[macro_use]
extern crate serde_json;

/// Builder for a new plugin.
pub struct Builder<S, I, O>
where
    S: Clone + Send,
    I: AsyncRead + Unpin,
    O: Send + AsyncWrite + Unpin,
{
    state: S,

    input: I,
    output: O,

    #[allow(dead_code)]
    hooks: Hooks,

    #[allow(dead_code)]
    subscriptions: Subscriptions,
}

impl<S, I, O> Builder<S, I, O>
where
    O: Send + AsyncWrite + Unpin + 'static,
    S: Clone + Send + 'static,
    I: AsyncRead + Send + Unpin + 'static,
{
    pub fn new(state: S, input: I, output: O) -> Self {
        Self {
            state,
            input,
            output,
            hooks: Hooks::default(),
            subscriptions: Subscriptions::default(),
        }
    }

    pub fn build(self) -> (Plugin<S, I, O>, I) {
        let output = Arc::new(Mutex::new(FramedWrite::new(
            self.output,
            JsonCodec::default(),
        )));

        // Now configure the logging, so any `log` call is wrapped
        // in a JSON-RPC notification and sent to c-lightning
        tokio::spawn(async move {});
        (
            Plugin {
                state: Arc::new(Mutex::new(self.state)),
                output,
                input_type: PhantomData,
            },
            self.input,
        )
    }
}

pub struct Plugin<S, I, O>
where
    S: Clone + Send,
    I: AsyncRead,
    O: Send + AsyncWrite + 'static,
{
    //input: FramedRead<Stdin, JsonCodec>,
    output: Arc<Mutex<FramedWrite<O, JsonCodec>>>,

    /// The state gets cloned for each request
    state: Arc<Mutex<S>>,
    input_type: PhantomData<I>,
}
impl<S, I, O> Plugin<S, I, O>
where
    S: Clone + Send,
    I: AsyncRead + Send + Unpin,
    O: Send + AsyncWrite + Unpin + 'static,
{
    /// Read incoming requests from `c-lightning and dispatch their handling.
    #[allow(unused_mut)]
    pub async fn run(mut self, input: I) -> Result<(), Error> {
        crate::logging::init(self.output.clone()).await?;
        trace!("Plugin logging initialized");

        let mut input = FramedRead::new(input, JsonRpcCodec::default());
        loop {
            match input.next().await {
                Some(Ok(msg)) => {
                    trace!("Received a message: {:?}", msg);
                    match msg {
                        messages::JsonRpc::Request(id, p) => {
                            self.dispatch_request(id, p).await?
                            // Use a match to detect Ok / Error and return an error if we failed.
                        }
                        messages::JsonRpc::Notification(n) => self.dispatch_notification(n).await?,
                    }
                }
                Some(Err(e)) => {
                    warn!("Error reading command: {}", e);
                    break;
                }
                None => break,
            }
        }
        Ok(())
    }

    async fn dispatch_request(
        &mut self,
        id: usize,
        request: messages::Request,
    ) -> Result<(), Error> {
        trace!("Dispatching request {:?}", request);
        let state = self.state.clone();
        let res: serde_json::Value = match request {
            messages::Request::Getmanifest(c) => {
                serde_json::to_value(Plugin::<S, I, O>::handle_get_manifest(c, state).await?)
                    .unwrap()
            }
            messages::Request::Init(c) => {
                serde_json::to_value(Plugin::<S, I, O>::handle_init(c, state).await?).unwrap()
            }
            o => panic!("Request {:?} is currently unhandled", o),
        };
        trace!("Sending respone {:?}", res);

        let mut out = self.output.lock().await;
        out.send(json!({
            "jsonrpc": "2.0",
            "result": res,
            "id": id,
        }))
        .await
        .unwrap();
        Ok(())
    }

    async fn dispatch_notification(
        &mut self,
        notification: messages::Notification,
    ) -> Result<(), Error> {
        trace!("Dispatching notification {:?}", notification);
        unimplemented!()
    }

    async fn handle_get_manifest(
        _call: messages::GetManifestCall,
        _state: Arc<Mutex<S>>,
    ) -> Result<messages::GetManifestResponse, Error> {
        Ok(messages::GetManifestResponse::default())
    }

    async fn handle_init(
        _call: messages::InitCall,
        _state: Arc<Mutex<S>>,
    ) -> Result<messages::InitResponse, Error> {
        Ok(messages::InitResponse::default())
    }
}

/// A container for all the configure hooks. It is just a collection
/// of callbacks that can be registered by the users of the
/// library. Based on this configuration we can then generate the
/// [`messages::GetManifestResponse`] from, populating our subscriptions
#[derive(Debug, Default)]
struct Hooks {}

/// A container for all the configured notifications.
#[derive(Debug, Default)]
struct Subscriptions {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn init() {
        let builder = Builder::new((), tokio::io::stdin(), tokio::io::stdout());
        let plugin = builder.build();
    }
}
