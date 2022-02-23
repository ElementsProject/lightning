use crate::codec::{JsonCodec, JsonRpcCodec};
pub use anyhow::{anyhow, Context};
use futures::sink::SinkExt;
extern crate log;
use log::trace;
use std::collections::HashMap;
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

pub mod options;

use options::ConfigOption;

/// Need to tell us about something that went wrong? Use this error
/// type to do that. Use this alias to be safe from future changes in
/// our internal error handling, since we'll implement any necessary
/// conversions for you :-)
pub type Error = anyhow::Error;

/// Builder for a new plugin.
pub struct Builder<S, I, O>
where
    I: AsyncRead + Unpin,
    O: Send + AsyncWrite + Unpin,
    S: Clone + Send,
{
    state: S,

    input: Option<I>,
    output: Option<O>,

    hooks: HashMap<String, Hook<S>>,
    options: Vec<ConfigOption>,
    rpcmethods: HashMap<String, RpcMethod<S>>,
    subscriptions: HashMap<String, Subscription<S>>,
}

impl<S, I, O> Builder<S, I, O>
where
    O: Send + AsyncWrite + Unpin + 'static,
    S: Clone + Sync + Send + Clone + 'static,
    I: AsyncRead + Send + Unpin + 'static,
{
    pub fn new(state: S, input: I, output: O) -> Self {
        Self {
            state,
            input: Some(input),
            output: Some(output),
            hooks: HashMap::new(),
            subscriptions: HashMap::new(),
            options: vec![],
            rpcmethods: HashMap::new(),
        }
    }

    pub fn option(mut self, opt: options::ConfigOption) -> Builder<S, I, O> {
        self.options.push(opt);
        self
    }

    /// Subscribe to notifications for the given `topic`.
    pub fn subscribe(mut self, topic: &str, callback: NotificationCallback<S>) -> Builder<S, I, O> {
        self.subscriptions
            .insert(topic.to_string(), Subscription { callback });
        self
    }

    /// Add a subscription to a given `hookname`
    pub fn hook(mut self, hookname: &str, callback: Callback<S>) -> Self {
        self.hooks.insert(hookname.to_string(), Hook { callback });
        self
    }

    /// Register a custom RPC method for the RPC passthrough from the
    /// main daemon
    pub fn rpcmethod(
        mut self,
        name: &str,
        description: &str,
        callback: Callback<S>,
    ) -> Builder<S, I, O> {
        self.rpcmethods.insert(
            name.to_string(),
            RpcMethod {
                name: name.to_string(),
                description: description.to_string(),
                callback,
            },
        );
        self
    }

    /// Build and start the plugin loop. This performs the handshake
    /// and spawns a new task that accepts incoming messages from
    /// c-lightning and dispatches them to the handlers. It only
    /// returns after completing the handshake to ensure that the
    /// configuration and initialization was successfull.
    pub async fn start(mut self) -> Result<Plugin<S>, anyhow::Error> {
        let mut input = FramedRead::new(self.input.take().unwrap(), JsonRpcCodec::default());

        // Sadly we need to wrap the output in a mutex in order to
        // enable early logging, i.e., logging that is done before the
        // PluginDriver is processing events during the
        // handshake. Otherwise we could just write the log events to
        // the event queue and have the PluginDriver be the sole owner
        // of `Stdout`.
        let output = Arc::new(Mutex::new(FramedWrite::new(
            self.output.take().unwrap(),
            JsonCodec::default(),
        )));

        // Now configure the logging, so any `log` call is wrapped
        // in a JSON-RPC notification and sent to c-lightning
        crate::logging::init(output.clone()).await?;
        trace!("Plugin logging initialized");

        // Read the `getmanifest` message:
        match input.next().await {
            Some(Ok(messages::JsonRpc::Request(id, messages::Request::Getmanifest(m)))) => {
                output
                    .lock()
                    .await
                    .send(json!({
                        "jsonrpc": "2.0",
                        "result": self.handle_get_manifest(m),
                        "id": id,
                    }))
                    .await?
            }
            o => return Err(anyhow!("Got unexpected message {:?} from lightningd", o)),
        };

        match input.next().await {
            Some(Ok(messages::JsonRpc::Request(id, messages::Request::Init(m)))) => {
                output
                    .lock()
                    .await
                    .send(json!({
                        "jsonrpc": "2.0",
                        "result": self.handle_init(m)?,
                        "id": id,
                    }))
                    .await?
            }

            o => return Err(anyhow!("Got unexpected message {:?} from lightningd", o)),
        };

        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        // An MPSC pair used by anything that needs to send messages
        // to the main daemon.
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let plugin = Plugin {
            state: self.state,
            options: self.options,
            wait_handle,
            sender,
        };

        // TODO Split the two hashmaps once we fill in the hook
        // payload structs in messages.rs
        let mut rpcmethods: HashMap<String, Callback<S>> =
            HashMap::from_iter(self.rpcmethods.drain().map(|(k, v)| (k, v.callback)));
        rpcmethods.extend(self.hooks.clone().drain().map(|(k, v)| (k, v.callback)));

        // Start the PluginDriver to handle plugin IO
        tokio::spawn(
            PluginDriver {
                plugin: plugin.clone(),
                rpcmethods,
                hooks: HashMap::from_iter(self.hooks.drain().map(|(k, v)| (k, v.callback))),
                subscriptions: HashMap::from_iter(
                    self.subscriptions.drain().map(|(k, v)| (k, v.callback)),
                ),
            }
            .run(receiver, input, output),
        );

        Ok(plugin)
    }

    fn handle_get_manifest(
        &mut self,
        _call: messages::GetManifestCall,
    ) -> messages::GetManifestResponse {
        let rpcmethods: Vec<_> = self
            .rpcmethods
            .values()
            .map(|v| messages::RpcMethod {
                name: v.name.clone(),
                description: v.description.clone(),
                usage: String::new(),
            })
            .collect();

        messages::GetManifestResponse {
            options: self.options.clone(),
            subscriptions: self.subscriptions.keys().map(|s| s.clone()).collect(),
            hooks: self.hooks.keys().map(|s| s.clone()).collect(),
            rpcmethods,
        }
    }

    fn handle_init(&mut self, call: messages::InitCall) -> Result<messages::InitResponse, Error> {
        use options::Value as OValue;
        use serde_json::Value as JValue;

        // Match up the ConfigOptions and fill in their values if we
        // have a matching entry.
        for opt in self.options.iter_mut() {
            if let Some(val) = call.options.get(opt.name()) {
                opt.value = Some(match (opt.default(), &val) {
                    (OValue::String(_), JValue::String(s)) => OValue::String(s.clone()),
                    (OValue::Integer(_), JValue::Number(n)) => OValue::Integer(n.as_i64().unwrap()),
                    (OValue::Boolean(_), JValue::Bool(n)) => OValue::Boolean(*n),

                    // It's ok to panic, if we get here c-lightning
                    // has not enforced the option type.
                    (_, _) => panic!("Mismatching types in options: {:?} != {:?}", opt, val),
                });
            }
        }

        Ok(messages::InitResponse::default())
    }
}

type Callback<S> = Box<fn(Plugin<S>, &serde_json::Value) -> Result<serde_json::Value, Error>>;
type NotificationCallback<S> = Box<fn(Plugin<S>, &serde_json::Value) -> Result<(), Error>>;

/// A struct collecting the metadata required to register a custom
/// rpcmethod with the main daemon upon init. It'll get deconstructed
/// into just the callback after the init.
struct RpcMethod<S>
where
    S: Clone + Send,
{
    callback: Callback<S>,
    description: String,
    name: String,
}

struct Subscription<S>
where
    S: Clone + Send,
{
    callback: NotificationCallback<S>,
}

#[derive(Clone)]
struct Hook<S>
where
    S: Clone + Send,
{
    callback: Callback<S>,
}

#[derive(Clone)]
pub struct Plugin<S>
where
    S: Clone + Send,
{
    /// The state gets cloned for each request
    state: S,
    options: Vec<ConfigOption>,

    /// A signal that allows us to wait on the plugin's shutdown.
    wait_handle: tokio::sync::broadcast::Sender<()>,

    sender: tokio::sync::mpsc::Sender<serde_json::Value>,
}

/// The [PluginDriver] is used to run the IO loop, reading messages
/// from the Lightning daemon, dispatching calls and notifications to
/// the plugin, and returning responses to the the daemon. We also use
/// it to handle spontaneous messages like Notifications and logging
/// events.
struct PluginDriver<S>
where
    S: Send + Clone,
{

    plugin: Plugin<S>,
    rpcmethods: HashMap<String, Callback<S>>,

    #[allow(dead_code)] // Unused until we fill in the Hook structs.
    hooks: HashMap<String, Callback<S>>,
    subscriptions: HashMap<String, NotificationCallback<S>>,
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
impl<S> PluginDriver<S>
where
    S: Send + Clone,
{
    /// Run the plugin until we get a shutdown command.
    async fn run<I, O>(
        self,
        mut receiver: tokio::sync::mpsc::Receiver<serde_json::Value>,
        mut input: FramedRead<I, JsonRpcCodec>,
        output: Arc<Mutex<FramedWrite<O, JsonCodec>>>,
    ) -> Result<(), Error>
    where
        I: Send + AsyncReadExt + Unpin,
        O: Send + AsyncWriteExt + Unpin,
    {
        loop {
            tokio::select! {
                    _ = self.dispatch_one(&mut input, &self.plugin) => {},
            v = receiver.recv() => {output.lock().await.send(v.unwrap()).await?},
                }
        }
    }

    /// Dispatch one server-side event and then return. Just so we
    /// have a nicer looking `select` statement in `run` :-)
    async fn dispatch_one<I>(
        &self,
        input: &mut FramedRead<I, JsonRpcCodec>,
        plugin: &Plugin<S>,
    ) -> Result<(), Error>
    where
        I: Send + AsyncReadExt + Unpin,
    {
        match input.next().await {
            Some(Ok(msg)) => {
                trace!("Received a message: {:?}", msg);
                match msg {
                    messages::JsonRpc::Request(id, p) => {
                        PluginDriver::<S>::dispatch_request(id, p, plugin).await
                    }
                    messages::JsonRpc::Notification(n) => {
                        self.dispatch_notification(n, plugin).await
                    }
                    messages::JsonRpc::CustomRequest(id, p) => {
                        match self.dispatch_custom_request(id, p, plugin).await {
                            Ok(v) => plugin
                                .sender
                                .send(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": v
                                }))
                                .await
                                .context("returning custom result"),
                            Err(e) => plugin
                                .sender
                                .send(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": e.to_string(),
                                }))
                                .await
                                .context("returning custom error"),
                        }
                    }
                    messages::JsonRpc::CustomNotification(n) => {
                        self.dispatch_custom_notification(n, plugin).await
                    }
                }
            }
            Some(Err(e)) => Err(anyhow!("Error reading command: {}", e)),
            None => Ok(()),
        }
    }

    async fn dispatch_request(
        _id: usize,
        _request: messages::Request,
        _plugin: &Plugin<S>,
    ) -> Result<(), Error> {
        todo!("This is unreachable until we start filling in messages:Request. Until then the custom dispatcher below is used exclusively.")
    }

    async fn dispatch_notification(
        &self,
        _notification: messages::Notification,
        _plugin: &Plugin<S>,
    ) -> Result<(), Error>
    where
        S: Send + Clone,
    {
        todo!("As soon as we define the full structure of the messages::Notification we'll get here. Until then the custom dispatcher below is used.")
    }

    async fn dispatch_custom_request(
        &self,
        _id: usize,
        request: serde_json::Value,
        plugin: &Plugin<S>,
    ) -> Result<serde_json::Value, Error> {
        let method = request
            .get("method")
            .context("Missing 'method' in request")?
            .as_str()
            .context("'method' is not a string")?;

        let params = request
            .get("params")
            .context("Missing 'params' field in request")?;
        let callback = self
            .rpcmethods
            .get(method)
            .with_context(|| anyhow!("No handler for method '{}' registered", method))?;

        trace!(
            "Dispatching custom request: method={}, params={}",
            method,
            params
        );
        callback(plugin.clone(), params)
    }

    async fn dispatch_custom_notification(
        &self,
        notification: serde_json::Value,
        plugin: &Plugin<S>,
    ) -> Result<(), Error>
    where
        S: Send + Clone,
    {
        trace!("Dispatching custom notification {:?}", notification);
        let method = notification
            .get("method")
            .context("Missing 'method' in notification")?
            .as_str()
            .context("'method' is not a string")?;
        let params = notification
            .get("params")
            .context("Missing 'params' field in notification")?;
        let callback = self
            .subscriptions
            .get(method)
            .with_context(|| anyhow!("No handler for method '{}' registered", method))?;
        trace!(
            "Dispatching custom request: method={}, params={}",
            method,
            params
        );
        if let Err(e) = callback(plugin.clone(), params) {
            log::error!("Error in notification handler '{}': {}", method, e);
        }
        Ok(())
    }
}

impl<S> Plugin<S>
where
    S: Clone + Send,
{
    pub fn options(&self) -> Vec<ConfigOption> {
        self.options.clone()
    }
    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<S> Plugin<S>
where
    S: Send + Clone,
{
    pub async fn join(&self) -> Result<(), Error> {
        self.wait_handle
            .subscribe()
            .recv()
            .await
            .context("error waiting for shutdown")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn init() {
        let builder = Builder::new((), tokio::io::stdin(), tokio::io::stdout());
        let _ = builder.start();
    }
}
