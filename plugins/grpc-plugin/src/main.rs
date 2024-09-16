use anyhow::{Context, Result};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::{options, Builder, Plugin};
use cln_rpc::notifications::Notification;
use log::{debug, warn};
use router::{GrpcRouterConfig, GrpcRouterScheme};
use std::path::PathBuf;
use tokio::sync::broadcast;
use tonic::transport::ServerTlsConfig;

mod router;
mod tls;

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    events: broadcast::Sender<cln_rpc::notifications::Notification>,
}

const OPTION_GRPC_SCHEME: options::DefaultStringConfigOption =
    options::ConfigOption::new_str_with_default(
        "grpc-scheme",
        "https",
        "The scheme used by the gprc-plugin. Either 'http' or 'https'",
    );

const OPTION_GRPC_PORT: options::DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "grpc-port",
        9736,
        "Which port should the grpc plugin listen for incoming connections?"
    );

const OPTION_GRPC_HOST: options::DefaultStringConfigOption = options::ConfigOption::new_str_with_default(
    "grpc-host",
    "127.0.0.1",
    "Which host should the grpc listen for incomming connections?"
);

const OPTION_GRPC_MSG_BUFFER_SIZE : options::DefaultIntegerConfigOption = options::ConfigOption::new_i64_with_default(
    "grpc-msg-buffer-size",
    1024,
    "Number of notifications which can be stored in the grpc message buffer. Notifications can be skipped if this buffer is full");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    debug!("Starting grpc plugin");

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_GRPC_SCHEME)
        .option(OPTION_GRPC_PORT)
        .option(OPTION_GRPC_HOST)
        .option(OPTION_GRPC_MSG_BUFFER_SIZE)
        // TODO: Use the catch-all subscribe method
        // However, doing this breaks the plugin at the time begin
        // We should fix this
        // .subscribe("*", handle_notification)
        .subscribe("block_added", handle_notification)
        .subscribe("channel_open_failed", handle_notification)
        .subscribe("channel_opened", handle_notification)
        .subscribe("channel_state_changed", handle_notification)
        .subscribe("connect", handle_notification)
        .subscribe("custommsg", handle_notification)
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let router_config = match GrpcRouterConfig::from_configured_plugin(&plugin) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            log::info!("Running on default 'grpc-port' 9736.");
            return Ok(());
        }
        Err(err) => {
          log::warn!("{:?}", err);
          plugin.disable(&format!("Invalid configuration: {:?}", err)).await?;
          return Err(err)
        }
    };

    let buffer_size: i64 = plugin.option(&OPTION_GRPC_MSG_BUFFER_SIZE).unwrap();
    let buffer_size = match usize::try_from(buffer_size) {
        Ok(b) => b,
        Err(_) => {
            plugin
                .disable("'grpc-msg-buffer-size' should be strictly positive")
                .await?;
            return Ok(());
        }
    };

    let (sender, _) = broadcast::channel(buffer_size);

    let state = PluginState {
        rpc_path: PathBuf::from(plugin.configuration().rpc_file.as_str()),
        events: sender,
    };

    let plugin = plugin.start(state.clone()).await?;

    tokio::select! {
        _ = plugin.join() => {
        // This will likely never be shown, if we got here our
        // parent process is exiting and not processing out log
        // messages anymore.
            debug!("Plugin loop terminated")
        }
        e = run_interface(router_config, state) => {
            warn!("Error running grpc interface: {:?}", e)
        }
    }
    Ok(())
}

fn create_server_tls_config() -> anyhow::Result<ServerTlsConfig> {
    let directory = std::env::current_dir()?;
    let (identity, ca_cert) = tls::init(&directory)?;

    let identity = identity.to_tonic_identity();
    let ca_cert = tonic::transport::Certificate::from_pem(ca_cert);

    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    return Ok(tls);
}

async fn run_interface(router_config: GrpcRouterConfig, state: PluginState) -> Result<()> {
    let bind_addr = router_config.socket_addr();

    let mut server = match router_config.scheme {
        GrpcRouterScheme::HTTP => tonic::transport::Server::builder(),
        GrpcRouterScheme::HTTPS => {
            let server_tls_config = create_server_tls_config()?;
            tonic::transport::Server::builder()
                .tls_config(server_tls_config)
                .context("Configuring tls")?
        }
    };

    let svc_handle = server
        .add_service(NodeServer::new(
            cln_grpc::Server::new(&state.rpc_path, state.events.clone())
                .await
                .context("creating NodeServer instance")?,
        ))
        .serve(router_config.socket_addr());

    debug!(
        "Connecting to {:?} and serving grpc on {:?}",
        &state.rpc_path, &bind_addr
    );

    svc_handle.await.context("serving requests")?;

    Ok(())
}

async fn handle_notification(plugin: Plugin<PluginState>, value: serde_json::Value) -> Result<()> {
    let notification: Result<Notification, _> = serde_json::from_value(value);
    match notification {
        Err(err) => {
            log::debug!("Failed to parse notification from lightningd {:?}", err);
        }
        Ok(notification) => {
            if let Err(err) = plugin.state().events.send(notification) {
                log::warn!("Failed to broadcast notification {:?}", err)
            }
        }
    };
    Ok(())
}
