//! A library for writing Core Lightning plugins in Rust.
//!
//! # Logging
//!
//! Records emitted through the `log` and `tracing` facades are forwarded to
//! `lightningd` as JSON-RPC `log` notifications, and appear in the node's log.
//!
//! Which records are forwarded is controlled by the `CLN_PLUGIN_LOG`
//! environment variable, which accepts the same comma-separated directives as
//! `RUST_LOG`. Directives that fail to parse are reported on `stderr` and
//! ignored.
//!
//! If `CLN_PLUGIN_LOG` is unset or empty the filter defaults to `info`, so
//! `info` and above are forwarded while `debug` and `trace` are dropped.
//! Setting the variable *replaces* that default rather than adding to it, so
//! `CLN_PLUGIN_LOG=cln_plugin=trace` also silences every other target; append
//! a bare level, as in `cln_plugin=trace,warn`, to keep a fallback for the
//! rest.
//!
//! `lightningd` applies its own `log-level` setting on top of this filter, so
//! a record must pass both to be written to the node's log.

use crate::codec::{JsonCodec, JsonRpcCodec};
pub use anyhow::anyhow;
use anyhow::{Context, Result};
use futures::FutureExt;
use futures::sink::SinkExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
extern crate log;
use log::trace;
use messages::{Configuration, FeatureBits, NotificationTopic};
use options::{OptionType, UntypedConfigOption};
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
    options: HashMap<String, UntypedConfigOption>,
    option_values: HashMap<String, Option<options::Value>>,
    rpcmethods: HashMap<String, RpcMethod<S>>,
    setconfig_callback: Option<AsyncCallback<S>>,
    subscriptions: HashMap<String, Subscription<S>>,
    // Contains a Subscription if the user subscribed to "*"
    wildcard_subscription: Option<Subscription<S>>,
    notifications: Vec<NotificationTopic>,
    custommessages: Vec<u16>,
    featurebits: FeatureBits,
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
    options: HashMap<String, UntypedConfigOption>,
    option_values: HashMap<String, Option<options::Value>>,
    configuration: Configuration,
    rpcmethods: HashMap<String, AsyncCallback<S>>,
    setconfig_callback: Option<AsyncCallback<S>>,
    hooks: HashMap<String, AsyncCallback<S>>,
    subscriptions: HashMap<String, AsyncNotificationCallback<S>>,
    wildcard_subscription: Option<AsyncNotificationCallback<S>>,
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
    setconfig_callback: Option<AsyncCallback<S>>,

    #[allow(dead_code)] // Unused until we fill in the Hook structs.
    hooks: HashMap<String, AsyncCallback<S>>,
    subscriptions: HashMap<String, AsyncNotificationCallback<S>>,
    wildcard_subscription: Option<AsyncNotificationCallback<S>>,
}

#[derive(Clone)]
pub struct Plugin<S>
where
    S: Clone + Send,
{
    /// The state gets cloned for each request
    state: S,
    /// "options" field of "init" message sent by cln
    options: HashMap<String, UntypedConfigOption>,
    option_values: Arc<std::sync::Mutex<HashMap<String, Option<options::Value>>>>,
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
            wildcard_subscription: None,
            options: HashMap::new(),
            // Should not be configured by user.
            // This values are set when parsing the init-call
            option_values: HashMap::new(),
            rpcmethods: HashMap::new(),
            setconfig_callback: None,
            notifications: vec![],
            featurebits: FeatureBits::default(),
            dynamic: false,
            custommessages: vec![],
            logging: true,
        }
    }

    pub fn option<'a, V: options::OptionType<'a>>(
        mut self,
        opt: options::ConfigOption<'a, V>,
    ) -> Builder<S, I, O> {
        self.options.insert(opt.name().to_string(), opt.build());
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
        let subscription = Subscription {
            callback: Box::new(move |p, r| Box::pin(callback(p, r))),
        };

        if topic == "*" {
            self.wildcard_subscription = Some(subscription);
        } else {
            self.subscriptions.insert(topic.to_string(), subscription);
        };
        self
    }

    /// Add a hook subscription for `hookname` with a raw [`serde_json::Value`] request and response.
    /// Prefer [`Builder::hook_typed`] for type-safe hooks, or [`Builder::hook_from_builder`] if you
    /// need to configure `before`, `after`, or `filters`.
    pub fn hook<C, F>(mut self, hookname: &str, callback: C) -> Self
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Request) -> F + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.hooks.insert(
            hookname.to_string(),
            Hook {
                name: hookname.to_string(),
                callback: Box::new(move |p, r| Box::pin(callback(p, r))),
                before: Vec::new(),
                after: Vec::new(),
                filters: None,
            },
        );
        self
    }

    /// Add a hook subscription using a [`HookBuilder`], which allows configuring `before`, `after`,
    /// and `filters` in addition to the callback. Use [`HookBuilder::new`] for raw
    /// [`serde_json::Value`] hooks or [`HookBuilder::new_typed`] for type-safe hooks.
    pub fn hook_from_builder(mut self, hook: HookBuilder<S>) -> Builder<S, I, O> {
        self.hooks.insert(hook.name.clone(), hook.build());
        self
    }

    /// Add a hook subscription for `hookname` with typed request and response. The request is
    /// deserialized from JSON into `Req` and the response is serialized from `Resp` back to JSON
    /// automatically. If deserialization of the request fails, an error is returned and handled
    /// according to the hook fallback policy.
    /// Use [`Builder::hook_from_builder`] with [`HookBuilder::new_typed`] if you additionally need
    /// to configure `before`, `after`, or `filters`.
    pub fn hook_typed<C, F, Req, Resp>(mut self, hookname: &str, callback: C) -> Self
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Req) -> F + 'static,
        F: Future<Output = Result<Resp, Error>> + Send + 'static,
        Req: DeserializeOwned + Send + 'static,
        Resp: Serialize + Send + 'static,
    {
        let hookname = hookname.to_string();
        self.hooks.insert(
            hookname.clone(),
            Hook {
                name: hookname.clone(),
                callback: Box::new(move |p, r| {
                    let hookname = hookname.clone();
                    let typed_req = match serde_json::from_value(r) {
                        Ok(req) => req,
                        Err(e) => {
                            let error = format!(
                                "cln-plugin: hook '{hookname}' received a request that doesn't \
                                match the expected schema. Error: {e}"
                            );
                            log::warn!("{error}");
                            return Box::pin(async move { Err(anyhow!("{error}")) });
                        }
                    };
                    let fut = callback(p, typed_req);
                    Box::pin(async move {
                        let typed_resp = fut.await?;
                        serde_json::to_value(typed_resp).map_err(Error::from)
                    })
                }),
                before: Vec::new(),
                after: Vec::new(),
                filters: None,
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

    /// Register a callback for setconfig to accept changes for dynamic options
    pub fn setconfig_callback<C, F>(mut self, setconfig_callback: C) -> Builder<S, I, O>
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Request) -> F + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.setconfig_callback = Some(Box::new(move |p, r| Box::pin(setconfig_callback(p, r))));
        self
    }

    /// Send true value for "dynamic" field in "getmanifest" response
    pub fn dynamic(mut self) -> Builder<S, I, O> {
        self.dynamic = true;
        self
    }

    /// Sets the "featurebits" in the "getmanifest" response
    pub fn featurebits(mut self, kind: FeatureBitsKind, hex: String) -> Self {
        match kind {
            FeatureBitsKind::Node => self.featurebits.node = Some(hex),
            FeatureBitsKind::Channel => self.featurebits.channel = Some(hex),
            FeatureBitsKind::Init => self.featurebits.init = Some(hex),
            FeatureBitsKind::Invoice => self.featurebits.invoice = Some(hex),
        }
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
    pub fn custommessages(mut self, custommessages: Vec<u16>) -> Self {
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
                ));
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

        let rpcmethods: HashMap<String, AsyncCallback<S>> =
            HashMap::from_iter(self.rpcmethods.drain().map(|(k, v)| (k, v.callback)));
        let hooks: HashMap<String, AsyncCallback<S>> =
            HashMap::from_iter(self.hooks.drain().map(|(k, v)| (k, v.callback)));

        let subscriptions =
            HashMap::from_iter(self.subscriptions.drain().map(|(k, v)| (k, v.callback)));
        let all_subscription = self.wildcard_subscription.map(|s| s.callback);

        // Leave the `init` reply pending, so we can disable based on
        // the options if required.
        Ok(Some(ConfiguredPlugin {
            // The JSON-RPC `id` field so we can reply correctly.
            init_id,
            input,
            output,
            rpcmethods,
            setconfig_callback: self.setconfig_callback,
            notifications: self.notifications,
            subscriptions,
            wildcard_subscription: all_subscription,
            options: self.options,
            option_values: self.option_values,
            configuration,
            hooks,
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

        let subscriptions = self
            .subscriptions
            .keys()
            .map(|s| s.clone())
            .chain(self.wildcard_subscription.iter().map(|_| String::from("*")))
            .collect();

        let hooks: Vec<messages::Hook> = self
            .hooks
            .values()
            .map(|v| messages::Hook {
                name: v.name.clone(),
                before: v.before.clone(),
                after: v.after.clone(),
                filters: v.filters.clone(),
            })
            .collect();

        messages::GetManifestResponse {
            options: self.options.values().cloned().collect(),
            subscriptions,
            hooks,
            rpcmethods,
            notifications: self.notifications.clone(),
            featurebits: self.featurebits.clone(),
            dynamic: self.dynamic,
            nonnumericids: true,
            custommessages: self.custommessages.clone(),
        }
    }

    fn handle_init(&mut self, call: messages::InitCall) -> Result<Configuration, Error> {
        use options::Value as OValue;
        use serde_json::Value as JValue;

        // Match up the ConfigOptions and fill in their values if we
        // have a matching entry.
        for (name, option) in self.options.iter() {
            let json_value = call.options.get(name);
            let default_value = option.default();

            let option_value: Option<options::Value> = match (json_value, default_value) {
                (None, None) => None,
                (None, Some(default)) => Some(default.clone()),
                (Some(JValue::Array(a)), _) => match a.first() {
                    Some(JValue::String(_)) => Some(OValue::StringArray(
                        a.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
                    )),
                    Some(JValue::Number(_)) => Some(OValue::IntegerArray(
                        a.iter().map(|x| x.as_i64().unwrap()).collect(),
                    )),
                    _ => panic!("Array type not supported for option: {}", name),
                },
                (Some(JValue::String(s)), _) => Some(OValue::String(s.to_string())),
                (Some(JValue::Number(i)), _) => Some(OValue::Integer(i.as_i64().unwrap())),
                (Some(JValue::Bool(b)), _) => Some(OValue::Boolean(*b)),
                _ => panic!("Type mismatch for option {}", name),
            };

            self.option_values.insert(name.to_string(), option_value);
        }
        Ok(call.configuration)
    }
}

impl<S> HookBuilder<S>
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
            before: Vec::new(),
            after: Vec::new(),
            filters: None,
        }
    }

    pub fn new_typed<C, F, Req, Resp>(name: &str, callback: C) -> Self
    where
        C: Send + Sync + 'static,
        C: Fn(Plugin<S>, Req) -> F + 'static,
        F: Future<Output = Result<Resp, Error>> + Send + 'static,
        Req: DeserializeOwned + Send + 'static,
        Resp: Serialize + Send + 'static,
    {
        let hookname = name.to_string();
        Self {
            name: hookname.clone(),
            callback: Box::new(move |p, r| {
                let hookname = hookname.clone();
                let typed_req = match serde_json::from_value(r) {
                    Ok(req) => req,
                    Err(e) => {
                        let error = format!(
                            "cln-plugin: hook '{hookname}' received a request that doesn't match \
                            the expected schema. Error: {e}"
                        );
                        log::warn!("{error}");
                        return Box::pin(async move { Err(anyhow!("{error}")) });
                    }
                };
                let fut = callback(p, typed_req);
                Box::pin(async move {
                    let typed_resp = fut.await?;
                    serde_json::to_value(typed_resp).map_err(Error::from)
                })
            }),
            before: Vec::new(),
            after: Vec::new(),
            filters: None,
        }
    }

    pub fn before(mut self, before: Vec<String>) -> Self {
        self.before = before;
        self
    }

    pub fn after(mut self, after: Vec<String>) -> Self {
        self.after = after;
        self
    }

    pub fn filters(mut self, filters: Vec<HookFilter>) -> Self {
        // Empty Vec would filter everything, must be None instead to not get serialized
        if filters.is_empty() {
            self.filters = None;
        } else {
            self.filters = Some(filters);
        }
        self
    }

    fn build(self) -> Hook<S> {
        Hook {
            callback: self.callback,
            name: self.name,
            before: self.before,
            after: self.after,
            filters: self.filters,
        }
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
    name: String,
    callback: AsyncCallback<S>,
    before: Vec<String>,
    after: Vec<String>,
    filters: Option<Vec<HookFilter>>,
}

pub struct HookBuilder<S>
where
    S: Clone + Send,
{
    name: String,
    callback: AsyncCallback<S>,
    before: Vec<String>,
    after: Vec<String>,
    filters: Option<Vec<HookFilter>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum HookFilter {
    Str(String),
    Int(i64),
}

impl<S> Plugin<S>
where
    S: Clone + Send,
{
    pub fn option_str(&self, name: &str) -> Result<Option<options::Value>> {
        self.option_values
            .lock()
            .unwrap()
            .get(name)
            .ok_or(anyhow!("No option named {}", name))
            .cloned()
    }

    pub fn option<'a, OV: OptionType<'a>>(
        &self,
        config_option: &options::ConfigOption<'a, OV>,
    ) -> Result<OV::OutputValue> {
        let value = self.option_str(config_option.name())?;
        Ok(OV::from_value(&value))
    }

    pub fn set_option_str(&self, name: &str, value: options::Value) -> Result<()> {
        *self
            .option_values
            .lock()
            .unwrap()
            .get_mut(name)
            .ok_or(anyhow!("No option named {}", name))? = Some(value);
        Ok(())
    }

    pub fn set_option<'a, OV: OptionType<'a>>(
        &self,
        config_option: &options::ConfigOption<'a, OV>,
        value: options::Value,
    ) -> Result<()> {
        self.set_option_str(config_option.name(), value)?;
        Ok(())
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
            option_values: Arc::new(std::sync::Mutex::new(self.option_values)),
            configuration: self.configuration,
            wait_handle,
            sender,
        };

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods: self.rpcmethods,
            setconfig_callback: self.setconfig_callback,
            hooks: self.hooks,
            subscriptions: self.subscriptions,
            wildcard_subscription: self.wildcard_subscription,
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

    pub fn option_str(&self, name: &str) -> Result<Option<options::Value>> {
        self.option_values
            .get(name)
            .ok_or(anyhow!("No option named '{}'", name))
            .map(|c| c.clone())
    }

    pub fn option<'a, OV: OptionType<'a>>(
        &self,
        config_option: &options::ConfigOption<'a, OV>,
    ) -> Result<OV::OutputValue> {
        let value = self.option_str(config_option.name())?;
        Ok(OV::from_value(&value))
    }

    /// return the cln configuration send to the
    /// plugin after the initialization.
    pub fn configuration(&self) -> Configuration {
        self.configuration.clone()
    }
}

fn hook_fallback(hookname: &str) -> Option<serde_json::Value> {
    match hookname {
        "htlc_accepted" => Some(json!({
            "result": "fail",
            "failure_message": "2002"
        })),
        "peer_connected"
        | "invoice_payment"
        | "rpc_command"
        | "custommsg"
        | "onion_message_recv"
        | "onion_message_recv_secret"
        | "recover" => Some(json!({"result": "continue"})),
        "openchannel"
        | "openchannel2"
        | "openchannel2_changed"
        | "openchannel2_sign"
        | "rbf_channel" => Some(json!({"result": "reject"})),
        // commitment_revocation and db_write cannot recover from failing, let lightningd crash
        _ => None,
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
                        todo!(
                            "This is unreachable until we start filling in messages:Request. Until then the custom dispatcher below is used exclusively."
                        );
                    }
                    messages::JsonRpc::Notification(_n) => {
                        todo!(
                            "As soon as we define the full structure of the messages::Notification we'll get here. Until then the custom dispatcher below is used."
                        )
                    }
                    messages::JsonRpc::CustomRequest(id, request) => {
                        trace!("Dispatching custom method {:?}", request);
                        let method = request
                            .get("method")
                            .context("Missing 'method' in request")?
                            .as_str()
                            .context("'method' is not a string")?;
                        let params = request
                            .get("params")
                            .context("Missing 'params' field in request")?
                            .clone();

                        let plugin = plugin.clone();
                        let method_str = method.to_string();

                        if let Some(callback) = self.hooks.get(method) {
                            let call = callback(plugin.clone(), params);
                            tokio::spawn(async move {
                                let res = std::panic::AssertUnwindSafe(call).catch_unwind().await;
                                match res {
                                    Ok(Ok(v)) => {
                                        let _ = plugin
                                            .sender
                                            .send(json!({
                                                "jsonrpc": "2.0",
                                                "id": id,
                                                "result": v
                                            }))
                                            .await
                                            .context("returning custom response");
                                    }
                                    Ok(Err(e)) => {
                                        if let Some(fallback) = hook_fallback(&method_str) {
                                            log::error!(
                                                "Hook handler for '{method_str}' failed with \
                                                error: {e}. Returning safe fallback response to \
                                                avoid crashing the main daemon."
                                            );
                                            let _ = plugin
                                                .sender
                                                .send(json!({
                                                    "jsonrpc": "2.0",
                                                    "id": id,
                                                    "result": fallback
                                                }))
                                                .await
                                                .context("returning hook fallback response");
                                        } else {
                                            let _ = plugin
                                                .sender
                                                .send(json!({
                                                    "jsonrpc": "2.0",
                                                    "id": id,
                                                    "error": parse_error(&e),
                                                }))
                                                .await
                                                .context("returning custom error");
                                        }
                                    }
                                    Err(_) => {
                                        if let Some(fallback) = hook_fallback(&method_str) {
                                            log::error!(
                                                "Hook handler for '{method_str}' panicked. \
                                                Returning safe fallback response to avoid hanging \
                                                the main daemon."
                                            );
                                            let _ = plugin
                                                .sender
                                                .send(json!({
                                                    "jsonrpc": "2.0",
                                                    "id": id,
                                                    "result": fallback
                                                }))
                                                .await
                                                .context("returning hook fallback response");
                                        } else {
                                            log::error!(
                                                "Hook handler for '{method_str}' panicked."
                                            );
                                            let err =
                                                anyhow!("Hook handler for '{method_str}' panicked");
                                            let _ = plugin
                                                .sender
                                                .send(json!({
                                                    "jsonrpc": "2.0",
                                                    "id": id,
                                                    "error": parse_error(&err),
                                                }))
                                                .await
                                                .context("returning hook panic error");
                                        }
                                    }
                                }
                            });
                        } else {
                            let callback = match method {
                                name if name.eq("setconfig") => {
                                    self.setconfig_callback.as_ref().ok_or_else(|| {
                                        anyhow!("No handler for method '{method}' registered")
                                    })?
                                }
                                _ => self.rpcmethods.get(method).with_context(|| {
                                    anyhow!("No handler for method '{method}' registered")
                                })?,
                            };

                            let call = callback(plugin.clone(), params);
                            tokio::spawn(async move {
                                let res = std::panic::AssertUnwindSafe(call).catch_unwind().await;
                                match res {
                                    Ok(Ok(v)) => {
                                        let _ = plugin
                                            .sender
                                            .send(json!({
                                                "jsonrpc": "2.0",
                                                "id": id,
                                                "result": v
                                            }))
                                            .await
                                            .context("returning custom response");
                                    }
                                    Ok(Err(e)) => {
                                        let _ = plugin
                                            .sender
                                            .send(json!({
                                                "jsonrpc": "2.0",
                                                "id": id,
                                                "error": parse_error(&e),
                                            }))
                                            .await
                                            .context("returning custom error");
                                    }
                                    Err(_) => {
                                        log::error!("RPC handler for '{method_str}' panicked.");
                                        let err = anyhow!("RPC method '{method_str}' panicked");
                                        let _ = plugin
                                            .sender
                                            .send(json!({
                                                "jsonrpc": "2.0",
                                                "id": id,
                                                "error": parse_error(&err),
                                            }))
                                            .await
                                            .context("returning rpc panic error");
                                    }
                                }
                            });
                        }
                        Ok(())
                    }
                    messages::JsonRpc::CustomNotification(request) => {
                        // This code handles notifications
                        trace!("Dispatching custom notification {:?}", request);
                        let method = request
                            .get("method")
                            .context("Missing 'method' in request")?
                            .as_str()
                            .context("'method' is not a string")?;

                        let params = request
                            .get("params")
                            .context("Missing 'params' field in request")?;

                        // Send to notification to the wildcard
                        // subscription "*" it it exists
                        if let Some(cb) = &self.wildcard_subscription {
                            let call = cb(plugin.clone(), params.clone());
                            tokio::spawn(async move {
                                match std::panic::AssertUnwindSafe(call).catch_unwind().await {
                                    Ok(Err(e)) => {
                                        log::warn!("Wildcard notification handler error: '{e}'");
                                    }
                                    Err(_) => {
                                        log::error!("Wildcard notification handler panicked");
                                    }
                                    Ok(Ok(())) => {}
                                }
                            });
                        }

                        // Find the appropriate callback and process it
                        // We'll log a warning if no handler is defined
                        match self.subscriptions.get(method) {
                            Some(cb) => {
                                let call = cb(plugin.clone(), params.clone());
                                tokio::spawn(async move {
                                    match std::panic::AssertUnwindSafe(call).catch_unwind().await {
                                        Ok(Err(e)) => {
                                            log::warn!("Notification handler error: '{e}'");
                                        }
                                        Err(_) => {
                                            log::error!(
                                                "Notification handler error: handler panicked"
                                            );
                                        }
                                        Ok(Ok(())) => {}
                                    }
                                });
                            }
                            None => {
                                if self.wildcard_subscription.is_none() {
                                    log::warn!(
                                        "No handler for notification '{}' registered",
                                        method
                                    );
                                }
                            }
                        };
                        Ok(())
                    }
                    messages::JsonRpc::Error(rpc_error) => {
                        log::warn!("Error in json decoder: {rpc_error}");
                        plugin.sender.send(rpc_error).await?;
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
    pub fn options(&self) -> Vec<UntypedConfigOption> {
        self.options.values().cloned().collect()
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
        // Modern has them inside object of same name.
        // This is deprecated, scheduled for removal 26.09.
        let mut params = match &v {
            serde_json::Value::Object(map) => map.clone(),
            _ => return Err(anyhow::anyhow!("params must be a JSON object")),
        };
        params.insert(method.clone(), json!(v));

        self.sender
            .send(json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
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

pub enum FeatureBitsKind {
    Node,
    Channel,
    Invoice,
    Init,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct RpcError {
    pub code: Option<i32>,
    pub message: String,
    pub data: Option<serde_json::Value>,
}
fn parse_error(error: &anyhow::Error) -> RpcError {
    if let Ok(o) = serde_json::from_str::<RpcError>(&error.to_string()) {
        o
    } else {
        let message = error
            .chain()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(": ");
        RpcError {
            code: Some(-32700),
            message,
            data: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn init() {
        let state = ();
        let builder = Builder::new(tokio::io::stdin(), tokio::io::stdout());
        let _ = builder.start(state);
    }
    #[test]
    fn parse_error_includes_full_anyhow_chain() {
        let err = anyhow!("No such file or directory (os error 2)")
            .context("config file missing")
            .context("failed to load config");

        let rpc_error = parse_error(&err);

        assert_eq!(rpc_error.code, Some(-32700));
        assert_eq!(
            rpc_error.message,
            "failed to load config: config file missing: No such file or directory (os error 2)"
        );
        assert_eq!(rpc_error.data, None);
    }

    fn dummy_configuration() -> Configuration {
        Configuration {
            lightning_dir: "".into(),
            rpc_file: "".into(),
            startup: false,
            network: "".into(),
            feature_set: HashMap::new(),
            proxy: None,
            torv3_enabled: None,
            always_use_proxy: None,
        }
    }

    #[tokio::test]
    async fn test_hook_error_returns_safe_fallback() {
        let (mut client_write, server_read) = tokio::io::duplex(1024);
        let mut framed_in = FramedRead::new(server_read, JsonRpcCodec::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        let plugin = Plugin {
            state: (),
            options: HashMap::new(),
            option_values: Arc::new(std::sync::Mutex::new(HashMap::new())),
            configuration: dummy_configuration(),
            wait_handle,
            sender,
        };

        let mut hooks: HashMap<String, AsyncCallback<()>> = HashMap::new();
        hooks.insert(
            "openchannel2".to_string(),
            Box::new(|_p, _r| Box::pin(async { Err(anyhow!("something broke in openchannel2")) })),
        );

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods: HashMap::new(),
            setconfig_callback: None,
            hooks,
            subscriptions: HashMap::new(),
            wildcard_subscription: None,
        };

        client_write
            .write_all(b"{\"jsonrpc\": \"2.0\", \"id\": 42, \"method\": \"openchannel2\", \"params\": {}}\n\n")
            .await
            .unwrap();

        driver
            .dispatch_one(&mut framed_in, &driver.plugin)
            .await
            .unwrap();

        let response = receiver.recv().await.unwrap();
        assert_eq!(response["id"], 42);
        assert_eq!(response["result"], json!({"result": "reject"}));
    }

    #[tokio::test]
    async fn test_hook_panic_returns_safe_fallback() {
        let (mut client_write, server_read) = tokio::io::duplex(1024);
        let mut framed_in = FramedRead::new(server_read, JsonRpcCodec::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        let plugin = Plugin {
            state: (),
            options: HashMap::new(),
            option_values: Arc::new(std::sync::Mutex::new(HashMap::new())),
            configuration: dummy_configuration(),
            wait_handle,
            sender,
        };

        let mut hooks: HashMap<String, AsyncCallback<()>> = HashMap::new();
        hooks.insert(
            "htlc_accepted".to_string(),
            Box::new(|_p, _r| {
                Box::pin(async {
                    panic!("hook handler explicitly panicked!");
                })
            }),
        );

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods: HashMap::new(),
            setconfig_callback: None,
            hooks,
            subscriptions: HashMap::new(),
            wildcard_subscription: None,
        };

        client_write
            .write_all(b"{\"jsonrpc\": \"2.0\", \"id\": 99, \"method\": \"htlc_accepted\", \"params\": {}}\n\n")
            .await
            .unwrap();

        driver
            .dispatch_one(&mut framed_in, &driver.plugin)
            .await
            .unwrap();

        let response = receiver.recv().await.unwrap();
        assert_eq!(response["id"], 99);
        assert_eq!(
            response["result"],
            json!({"result": "fail", "failure_message": "2002"})
        );
    }

    #[tokio::test]
    async fn test_typed_hook_schema_mismatch_fallback() {
        #[derive(serde::Deserialize)]
        struct ExpectedPayload {
            #[allow(dead_code)]
            mandatory_field: String,
        }

        #[derive(serde::Serialize)]
        struct DummyResponse {
            result: String,
        }

        let builder = Builder::new(tokio::io::empty(), tokio::io::sink()).hook_typed(
            "peer_connected",
            |_p: Plugin<()>, _req: ExpectedPayload| async move {
                Ok(DummyResponse {
                    result: "continue".to_string(),
                })
            },
        );

        let (mut client_write, server_read) = tokio::io::duplex(1024);
        let mut framed_in = FramedRead::new(server_read, JsonRpcCodec::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        let plugin = Plugin {
            state: (),
            options: HashMap::new(),
            option_values: Arc::new(std::sync::Mutex::new(HashMap::new())),
            configuration: dummy_configuration(),
            wait_handle,
            sender,
        };

        let hooks: HashMap<String, AsyncCallback<()>> =
            HashMap::from_iter(builder.hooks.into_iter().map(|(k, v)| (k, v.callback)));

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods: HashMap::new(),
            setconfig_callback: None,
            hooks,
            subscriptions: HashMap::new(),
            wildcard_subscription: None,
        };

        // Send invalid payload (missing mandatory_field)
        client_write
            .write_all(b"{\"jsonrpc\": \"2.0\", \"id\": 101, \"method\": \"peer_connected\", \"params\": {}}\n\n")
            .await
            .unwrap();

        driver
            .dispatch_one(&mut framed_in, &driver.plugin)
            .await
            .unwrap();

        let response = receiver.recv().await.unwrap();
        assert_eq!(response["id"], 101);
        assert_eq!(response["result"], json!({"result": "continue"}));
    }

    #[tokio::test]
    async fn test_crash_only_hook_returns_error() {
        let (mut client_write, server_read) = tokio::io::duplex(1024);
        let mut framed_in = FramedRead::new(server_read, JsonRpcCodec::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        let plugin = Plugin {
            state: (),
            options: HashMap::new(),
            option_values: Arc::new(std::sync::Mutex::new(HashMap::new())),
            configuration: dummy_configuration(),
            wait_handle,
            sender,
        };

        let mut hooks: HashMap<String, AsyncCallback<()>> = HashMap::new();
        hooks.insert(
            "db_write".to_string(),
            Box::new(|_p, _r| Box::pin(async { Err(anyhow!("db disk full")) })),
        );

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods: HashMap::new(),
            setconfig_callback: None,
            hooks,
            subscriptions: HashMap::new(),
            wildcard_subscription: None,
        };

        client_write
            .write_all(b"{\"jsonrpc\": \"2.0\", \"id\": 777, \"method\": \"db_write\", \"params\": {}}\n\n")
            .await
            .unwrap();

        driver
            .dispatch_one(&mut framed_in, &driver.plugin)
            .await
            .unwrap();

        let response = receiver.recv().await.unwrap();
        assert_eq!(response["id"], 777);
        assert!(response.get("error").is_some());
    }

    #[tokio::test]
    async fn test_rpc_method_named_recover_returns_error_not_fallback() {
        let (mut client_write, server_read) = tokio::io::duplex(1024);
        let mut framed_in = FramedRead::new(server_read, JsonRpcCodec::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let (wait_handle, _) = tokio::sync::broadcast::channel(1);

        let plugin = Plugin {
            state: (),
            options: HashMap::new(),
            option_values: Arc::new(std::sync::Mutex::new(HashMap::new())),
            configuration: dummy_configuration(),
            wait_handle,
            sender,
        };

        let mut rpcmethods: HashMap<String, AsyncCallback<()>> = HashMap::new();
        rpcmethods.insert(
            "recover".to_string(),
            Box::new(|_p, _r| Box::pin(async { Err(anyhow!("recover rpc failed")) })),
        );

        let driver = PluginDriver {
            plugin: plugin.clone(),
            rpcmethods,
            setconfig_callback: None,
            hooks: HashMap::new(),
            subscriptions: HashMap::new(),
            wildcard_subscription: None,
        };

        client_write
            .write_all(
                b"{\"jsonrpc\": \"2.0\", \"id\": 888, \"method\": \"recover\", \"params\": {}}\n\n",
            )
            .await
            .unwrap();

        driver
            .dispatch_one(&mut framed_in, &driver.plugin)
            .await
            .unwrap();

        let response = receiver.recv().await.unwrap();
        assert_eq!(response["id"], 888);
        assert!(response.get("error").is_some());
        assert_eq!(response["error"]["message"], "recover rpc failed");
    }
}
