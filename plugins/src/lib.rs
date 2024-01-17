use crate::codec::{JsonCodec, JsonRpcCodec};
pub use anyhow::anyhow;
use anyhow::Context;
use futures::sink::SinkExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
extern crate log;
use log::trace;
use messages::{Configuration, NotificationTopic};
use options::ConfigOption;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tokio_util::codec::FramedWrite;

mod codec;
mod logging;
pub mod messages;

#[macro_use]
extern crate serde_json;

pub mod options;

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
    input: Option<I>,
    output: Option<O>,

    hooks: HashMap<String, Hook<S>>,
    options: Vec<ConfigOption>,
    rpcmethods: HashMap<String, RpcMethod<S>>,
    subscriptions: HashMap<String, Subscription<S>>,
    notifications: Vec<NotificationTopic>,
    custommessages : Vec<u16>,
    dynamic: bool,
    // Do we want the plugin framework to automatically register a logging handler?
    logging: bool,
}

/// A plugin that has registered with the lightning daemon, and gotten
/// its options filled, however has not yet acknowledged the `init`
/// message. This is a mid-state allowing a plugin to disable itself,
/// based on the options.
pub struct ConfiguredPlugin<S, I, O>
where
    S: Clone + Send,
{
    init_id: serde_json::Value,
    input: FramedRead<I, JsonRpcCodec>,
    output: Arc<Mutex<FramedWrite<O, JsonCodec>>>,
    options: Vec<ConfigOption>,
    configuration: Configuration,
    rpcmethods: HashMap<String, AsyncCallback<S>>,
    hooks: HashMap<String, AsyncCallback<S>>,
    subscriptions: HashMap<String, AsyncNotificationCallback<S>>,
    #[allow(dead_code)] // unsure why rust thinks this field isn't used
    notifications: Vec<NotificationTopic>,
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
    rpcmethods: HashMap<String, AsyncCallback<S>>,

    #[allow(dead_code)] // Unused until we fill in the Hook structs.
    hooks: HashMap<String, AsyncCallback<S>>,
    subscriptions: HashMap<String, AsyncNotificationCallback<S>>,
}

#[derive(Clone)]
pub struct Plugin<S>
where
    S: Clone + Send,
{
    /// The state gets cloned for each request
    state: S,
    /// "options" field of "init" message sent by cln
    options: Vec<ConfigOption>,
    /// "configuration" field of "init" message sent by cln
    configuration: Configuration,
    /// A signal that allows us to wait on the plugin's shutdown.
    wait_handle: tokio::sync::broadcast::Sender<()>,

    sender: tokio::sync::mpsc::Sender<serde_json::Value>,
}

impl<S, I, O> Builder<S, I, O>
where
    O: Send + AsyncWrite + Unpin + 'static,
    S: Clone + Sync + Send + 'static,
    I: AsyncRead + Send + Unpin + 'static,
{
    pub fn new(input: I, output: O) -> Self {
        Self {
            input: Some(input),
            output: Some(output),
            hooks: HashMap::new(),
            subscriptions: HashMap::new(),
            options: vec![],
            rpcmethods: HashMap::new(),
            notifications: vec![],
            dynamic: false,
            custommessages : vec![],
            logging: true,
        }
    }

    pub fn option(mut self, opt: options::ConfigOption) -> Builder<S, I, O> {
        self.options.push(opt);
        self
    }

    pub fn notification(mut self, notif: messages::NotificationTopic) -> Builder<S, I, O> {
        self.notifications.push(notif);
        self
    }

    /// Subscribe to notifications for the given `topic`. The handler
    /// is an async function that takes a `Plugin<S>` and the
    /// notification as a `serde_json::Value` as inputs. Since
    /// notifications do not expect a result the handler should only
    /// report errors while processing. Any error reported while
    /// processing the notification will be logged in the cln logs.
    ///
    /// ```
    /// use cln_plugin::{options, Builder, Error, Plugin};
    ///
    /// async fn connect_handler(_p: Plugin<()>, v: serde_json::Value) -> Result<(), Error> {
    ///     println!("Got a connect notification: {}", v);
    ///     Ok(())
    /// }
    ///
    /// let b = Builder::new(tokio::io::stdin(), tokio::io::stdout())
    ///     .subscribe("connect", connect_handler);
    /// ```
    pub fn subscribe<C, F>(mut self, topic: &str, callback: C) -> Builder<S, I, O>
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Request) -> F + 'static,
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.subscriptions.insert(
            topic.to_string(),
            Subscription {
                callback: Box::new(move |p, r| Box::pin(callback(p, r))),
            },
        );
        self
    }

    /// Add a subscription to a given `hookname`
    pub fn hook<C, F>(mut self, hookname: &str, callback: C) -> Self
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Request) -> F + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.hooks.insert(
            hookname.to_string(),
            Hook {
                callback: Box::new(move |p, r| Box::pin(callback(p, r))),
            },
        );
        self
    }

    /// Register a custom RPC method for the RPC passthrough from the
    /// main daemon
    pub fn rpcmethod<C, F>(mut self, name: &str, description: &str, callback: C) -> Builder<S, I, O>
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Request) -> F + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.rpcmethods.insert(
            name.to_string(),
            RpcMethod {
                name: name.to_string(),
                description: description.to_string(),
                usage: String::default(),
                callback: Box::new(move |p, r| Box::pin(callback(p, r))),
            },
        );
        self
    }

    pub fn rpcmethod_from_builder(mut self, rpc_method: RpcMethodBuilder<S>) -> Builder<S, I, O> {
        self.rpcmethods
            .insert(rpc_method.name.to_string(), rpc_method.build());
        self
    }

    /// Send true value for "dynamic" field in "getmanifest" response
    pub fn dynamic(mut self) -> Builder<S, I, O> {
        self.dynamic = true;
        self
    }

    /// Should the plugin automatically register a logging handler? If
    /// not you may need to register a logging handler yourself. Be
    /// careful not to print raw lines to `stdout` if you do, since
    /// that'll interfere with the plugin communication. See the CLN
    /// documentation on logging to see what logging events should
    /// look like.
    pub fn with_logging(mut self, log: bool) -> Builder<S, I, O> {
        self.logging = log;
        self
    }

    /// Tells lightningd explicitly to allow custommmessages of the provided
    /// type
    pub fn custommessages(mut self, custommessages : Vec<u16>) -> Self {
        self.custommessages = custommessages;
        self
    }

    /// Communicate with `lightningd` to tell it about our options,
    /// RPC methods and subscribe to hooks, and then process the
    /// initialization, configuring the plugin.
    ///
    /// Returns `None` if we were invoked with `--help` and thus
    /// should exit after this handshake
    pub async fn configure(mut self) -> Result<Option<ConfiguredPlugin<S, I, O>>, anyhow::Error> {
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
        // in a JSON-RPC notification and sent to Core Lightning
        if self.logging {
            crate::logging::init(output.clone()).await?;
            trace!("Plugin logging initialized");
        }

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
            Some(o) => return Err(anyhow!("Got unexpected message {:?} from lightningd", o)),
            None => {
                return Err(anyhow!(
                    "Lost connection to lightning expecting getmanifest"
                ))
            }
        };
        let (init_id, configuration) = match input.next().await {
            Some(Ok(messages::JsonRpc::Request(id, messages::Request::Init(m)))) => {
                (id, self.handle_init(m)?)
            }

            Some(o) => return Err(anyhow!("Got unexpected message {:?} from lightningd", o)),
            None => {
                // If we are being called with --help we will get
                // disconnected here. That's expected, so don't
                // complain about it.
                return Ok(None);
            }
        };

        // TODO Split the two hashmaps once we fill in the hook
        // payload structs in messages.rs
        let mut rpcmethods: HashMap<String, AsyncCallback<S>> =
            HashMap::from_iter(self.rpcmethods.drain().map(|(k, v)| (k, v.callback)));
        rpcmethods.extend(self.hooks.drain().map(|(k, v)| (k, v.callback)));

        let subscriptions =
            HashMap::from_iter(self.subscriptions.drain().map(|(k, v)| (k, v.callback)));

        // Leave the `init` reply pending, so we can disable based on
        // the options if required.
        Ok(Some(ConfiguredPlugin {
            // The JSON-RPC `id` field so we can reply correctly.
            init_id,
            input,
            output,
            rpcmethods,
            notifications: self.notifications,
            subscriptions,
            options: self.options,
            configuration,
            hooks: HashMap::new(),
        }))
    }

    /// Build and start the plugin loop. This performs the handshake
    /// and spawns a new task that accepts incoming messages from
    /// Core Lightning and dispatches them to the handlers. It only
    /// returns after completing the handshake to ensure that the
    /// configuration and initialization was successfull.
    ///
    /// If `lightningd` was called with `--help` we won't get a
    /// `Plugin` instance and return `None` instead. This signals that
    /// we should exit, and not continue running. `start()` returns in
    /// order to allow user code to perform cleanup if necessary.
    pub async fn start(self, state: S) -> Result<Option<Plugin<S>>, anyhow::Error> {
        if let Some(cp) = self.configure().await? {
            Ok(Some(cp.start(state).await?))
        } else {
            Ok(None)
        }
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
                usage: v.usage.clone(),
            })
            .collect();

        messages::GetManifestResponse {
            options: self.options.clone(),
            subscriptions: self.subscriptions.keys().map(|s| s.clone()).collect(),
            hooks: self.hooks.keys().map(|s| s.clone()).collect(),
            rpcmethods,
            notifications: self.notifications.clone(),
            dynamic: self.dynamic,
            nonnumericids: true,
            custommessages : self.custommessages.clone()
        }
    }

    fn handle_init(&mut self, call: messages::InitCall) -> Result<Configuration, Error> {
        use options::Value as OValue;
        use serde_json::Value as JValue;

        // Match up the ConfigOptions and fill in their values if we
        // have a matching entry.
        for opt in self.options.iter_mut() {
            let val = call.options.get(opt.name());
            opt.value = match (&opt, &opt.default(), &val) {
                (_, OValue::String(_), Some(JValue::String(s))) => Some(OValue::String(s.clone())),
                (_, OValue::OptString, Some(JValue::String(s))) => Some(OValue::String(s.clone())),
                (_, OValue::OptString, None) => None,

                (_, OValue::Integer(_), Some(JValue::Number(s))) => {
                    Some(OValue::Integer(s.as_i64().unwrap()))
                }
                (_, OValue::OptInteger, Some(JValue::Number(s))) => {
                    Some(OValue::Integer(s.as_i64().unwrap()))
                }
                (_, OValue::OptInteger, None) => None,

                (_, OValue::Boolean(_), Some(JValue::Bool(s))) => Some(OValue::Boolean(*s)),
                (_, OValue::OptBoolean, Some(JValue::Bool(s))) => Some(OValue::Boolean(*s)),
                (_, OValue::OptBoolean, None) => None,

                (o, _, _) => panic!("Type mismatch for option {:?}", o),
            }
        }

        Ok(call.configuration)
    }
}

impl<S> RpcMethodBuilder<S>
where
    S: Send + Clone,
{
    pub fn new<C, F>(name: &str, callback: C) -> Self
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Request) -> F + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        Self {
            name: name.to_string(),
            callback: Box::new(move |p, r| Box::pin(callback(p, r))),
            usage: None,
            description: None,
        }
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn usage(mut self, usage: &str) -> Self {
        self.usage = Some(usage.to_string());
        self
    }

    fn build(self) -> RpcMethod<S> {
        RpcMethod {
            callback: self.callback,
            name: self.name,
            description: self.description.unwrap_or_default(),
            usage: self.usage.unwrap_or_default(),
        }
    }
}

// Just some type aliases so we don't get confused in a lisp-like sea
// of parentheses.
type Request = serde_json::Value;
type Response = Result<serde_json::Value, Error>;
type AsyncCallback<S> =
    Box<dyn Fn(Plugin<S>, Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;
type AsyncNotificationCallback<S> = Box<
    dyn Fn(Plugin<S>, Request) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>
        + Send
        + Sync,
>;

/// A struct collecting the metadata required to register a custom
/// rpcmethod with the main daemon upon init. It'll get deconstructed
/// into just the callback after the init.
struct RpcMethod<S>
where
    S: Clone + Send,
{
    callback: AsyncCallback<S>,
    description: String,
    name: String,
    usage: String,
}

pub struct RpcMethodBuilder<S>
where
    S: Clone + Send,
{
    callback: AsyncCallback<S>,
    name: String,
    description: Option<String>,
    usage: Option<String>,
}

struct Subscription<S>
where
    S: Clone + Send,
{
    callback: AsyncNotificationCallback<S>,
}

struct Hook<S>
where
    S: Clone + Send,
{
    callback: AsyncCallback<S>,
}

impl<S> Plugin<S>
where
    S: Clone + Send,
{
    pub fn option(&self, name: &str) -> Option<options::Value> {
        self.options
            .iter()
            .filter(|o| o.name() == name)
            .next()
            .map(|co| co.value.clone().unwrap_or(co.default().clone()))
    }
}

impl<S, I, O> ConfiguredPlugin<S, I, O>
where
    S: Send + Clone + Sync + 'static,
    I: AsyncRead + Send + Unpin + 'static,
    O: Send + AsyncWrite + Unpin + 'static,
{
    #[allow(unused_mut)]
    pub async fn start(mut self, state: S) -> Result<Plugin<S>, anyhow::Error> {
        let output = self.output;
        let input = self.input;
        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        // An MPSC pair used by anything that needs to send messages
        // to the main daemon.
        let (sender, receiver) = tokio::sync::mpsc::channel(4);

        let plugin = Plugin {
            state,
            options: self.options,
            configuration: self.configuration,
            wait_handle,
            sender,
        };

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods: self.rpcmethods,
            hooks: self.hooks,
            subscriptions: self.subscriptions,
        };

        output
            .lock()
            .await
            .send(json!(
                {
                    "jsonrpc": "2.0",
                    "id": self.init_id,
            "result": crate::messages::InitResponse{disable: None}
                }
            ))
            .await
            .context("sending init response")?;

        let joiner = plugin.wait_handle.clone();
        // Start the PluginDriver to handle plugin IO
        tokio::spawn(async move {
            if let Err(e) = driver.run(receiver, input, output).await {
                log::warn!("Plugin loop returned error {:?}", e);
            }

            // Now that we have left the reader loop its time to
            // notify any waiting tasks. This most likely will cause
            // the main task to exit and the plugin to terminate.
            joiner.send(())
        });
        Ok(plugin)
    }

    /// Abort the plugin startup. Communicate that we're about to exit
    /// voluntarily, and this is not an error.
    #[allow(unused_mut)]
    pub async fn disable(mut self, reason: &str) -> Result<(), anyhow::Error> {
        self.output
            .lock()
            .await
            .send(json!(
                {
                    "jsonrpc": "2.0",
                    "id": self.init_id,
            "result": crate::messages::InitResponse{
            disable: Some(reason.to_string())
            }
                }
            ))
            .await
            .context("sending init response")?;
        Ok(())
    }

    pub fn option(&self, name: &str) -> Option<options::Value> {
        self.options
            .iter()
            .filter(|o| o.name() == name)
            .next()
            .map(|co| co.value.clone().unwrap_or(co.default().clone()))
    }

    /// return the cln configuration send to the
    /// plugin after the initialization.
    pub fn configuration(&self) -> Configuration {
        self.configuration.clone()
    }
}

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
            // If we encounter any error reading or writing from/to
            // the master we hand them up, so we can return control to
            // the user-code, which may require some cleanups or
            // similar.
            tokio::select! {
                    e = self.dispatch_one(&mut input, &self.plugin) => {
                        if let Err(e) = e {
                return Err(e)
                        }
            },
            v = receiver.recv() => {
                        output.lock().await.send(
                v.context("internal communication error")?
                        ).await?;
            },
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
                    messages::JsonRpc::Request(_id, _p) => {
                        todo!("This is unreachable until we start filling in messages:Request. Until then the custom dispatcher below is used exclusively.");
                    }
                    messages::JsonRpc::Notification(_n) => {
                        todo!("As soon as we define the full structure of the messages::Notification we'll get here. Until then the custom dispatcher below is used.")
                    }
                    messages::JsonRpc::CustomRequest(id, request) => {
                        trace!("Dispatching custom method {:?}", request);
                        let method = request
                            .get("method")
                            .context("Missing 'method' in request")?
                            .as_str()
                            .context("'method' is not a string")?;
                        let callback = self.rpcmethods.get(method).with_context(|| {
                            anyhow!("No handler for method '{}' registered", method)
                        })?;
                        let params = request
                            .get("params")
                            .context("Missing 'params' field in request")?
                            .clone();

                        let plugin = plugin.clone();
                        let call = callback(plugin.clone(), params);

                        tokio::spawn(async move {
                            match call.await {
                                Ok(v) => plugin
                                    .sender
                                    .send(json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": v
                                    }))
                                    .await
                                    .context("returning custom response"),
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
                        });
                        Ok(())
                    }
                    messages::JsonRpc::CustomNotification(request) => {
                        trace!("Dispatching custom notification {:?}", request);
                        let method = request
                            .get("method")
                            .context("Missing 'method' in request")?
                            .as_str()
                            .context("'method' is not a string")?;
                        let callback = self.subscriptions.get(method).with_context(|| {
                            anyhow!("No handler for notification '{}' registered", method)
                        })?;
                        let params = request
                            .get("params")
                            .context("Missing 'params' field in request")?
                            .clone();

                        let plugin = plugin.clone();
                        let call = callback(plugin.clone(), params);

                        tokio::spawn(async move { call.await.unwrap() });
                        Ok(())
                    }
                }
            }
            Some(Err(e)) => Err(anyhow!("Error reading command: {}", e)),
            None => Err(anyhow!("Error reading from master")),
        }
    }
}

impl<S> Plugin<S>
where
    S: Clone + Send,
{
    pub fn options(&self) -> Vec<ConfigOption> {
        self.options.clone()
    }
    pub fn configuration(&self) -> Configuration {
        self.configuration.clone()
    }
    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<S> Plugin<S>
where
    S: Send + Clone,
{
    pub async fn send_custom_notification(
        &self,
        method: String,
        v: serde_json::Value,
    ) -> Result<(), Error> {
        self.sender
            .send(json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": v,
            }))
            .await
            .context("sending custom notification")?;
        Ok(())
    }

    /// Wait for plugin shutdown
    pub async fn join(&self) -> Result<(), Error> {
        self.wait_handle
            .subscribe()
            .recv()
            .await
            .context("error waiting for shutdown")
    }

    /// Request plugin shutdown
    pub fn shutdown(&self) -> Result<(), Error> {
        self.wait_handle
            .send(())
            .context("error waiting for shutdown")?;
        Ok(())
    }
}
