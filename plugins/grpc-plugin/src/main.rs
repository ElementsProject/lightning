use anyhow::{Context, Result};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::{options, Builder, Plugin};
use cln_rpc::notifications::Notification;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::broadcast;

mod tls;

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    identity: tls::Identity,
    ca_cert: Vec<u8>,
    events: broadcast::Sender<cln_rpc::notifications::Notification>,
}

const OPTION_GRPC_PORT: options::DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "grpc-port",
        9736,
        "Which port should the grpc plugin listen for incoming connections?",
    );

const OPTION_GRPC_HOST: options::DefaultStringConfigOption =
    options::ConfigOption::new_str_with_default(
        "grpc-host",
        "127.0.0.1",
        "Which host should the grpc listen for incomming connections?",
    );

const OPTION_GRPC_MSG_BUFFER_SIZE : options::DefaultIntegerConfigOption = options::ConfigOption::new_i64_with_default(
    "grpc-msg-buffer-size",
    1024,
    "Number of notifications which can be stored in the grpc message buffer. Notifications can be skipped if this buffer is full");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    std::env::set_var(
        "CLN_PLUGIN_LOG",
        "cln_plugin=info,cln_rpc=info,cln_grpc=debug,debug",
    );

    let directory = std::env::current_dir()?;

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_GRPC_PORT)
        .option(OPTION_GRPC_HOST)
        .option(OPTION_GRPC_MSG_BUFFER_SIZE)
        .subscribe("*", handle_notification)
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let bind_port: i64 = plugin.option(&OPTION_GRPC_PORT).unwrap();
    let bind_host: String = plugin.option(&OPTION_GRPC_HOST).unwrap();
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

    let (identity, ca_cert) = match tls::init(&directory) {
        Ok(o) => o,
        Err(e) => {
            log_error(e.to_string());
            return Err(e);
        }
    };

    let state = PluginState {
        rpc_path: PathBuf::from(plugin.configuration().rpc_file.as_str()),
        identity,
        ca_cert,
        events: sender,
    };

    let plugin = plugin.start(state.clone()).await?;

    let bind_addr: SocketAddr = format!("{}:{}", bind_host, bind_port).parse().unwrap();

    tokio::select! {
        _ = plugin.join() => {
        // This will likely never be shown, if we got here our
        // parent process is exiting and not processing out log
        // messages anymore.
            log::debug!("Plugin loop terminated")
        }
        e = run_interface(bind_addr, state) => {
            log_error(format!("Error running grpc interface: {:?}", e));
        }
    }
    Ok(())
}

async fn run_interface(bind_addr: SocketAddr, state: PluginState) -> Result<()> {
    let identity = state.identity.to_tonic_identity();
    let ca_cert = tonic::transport::Certificate::from_pem(state.ca_cert);

    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    let server = tonic::transport::Server::builder()
        .tls_config(tls)
        .context("configuring tls")?
        .add_service(NodeServer::new(
            cln_grpc::Server::new(&state.rpc_path, state.events.clone())
                .await
                .context("creating NodeServer instance")?,
        ))
        .serve(bind_addr);

    log::info!(
        "Connecting to {} and serving grpc on {:?}",
        &state.rpc_path.display(),
        &bind_addr
    );

    server.await.context("serving requests")?;

    Ok(())
}

async fn handle_notification(plugin: Plugin<PluginState>, value: serde_json::Value) -> Result<()> {
    let notification: Result<Notification, _> = serde_json::from_value(value);
    match notification {
        Err(err) => {
            log::debug!("Failed to parse notification from lightningd {:?}", err);
        }
        Ok(notification) => {
            match notification {
                Notification::Shutdown(_shutdown_notification) => {
                    let _ = plugin.shutdown();
                    std::process::exit(0)
                }
                _ => {
                    /* Depending on whether or not there is a wildcard
                     * subscription we may receive notifications for which we
                     * don't have a handler. We suppress the `SendError` which
                     * would indicate there is no subscriber for the given
                     * topic. */
                    let _ = plugin.state().events.send(notification);
                }
            }
        }
    };
    Ok(())
}

fn log_error(error: String) {
    println!(
        "{}",
        serde_json::json!({"jsonrpc": "2.0",
                          "method": "log",
                          "params": {"level":"warn", "message":error}})
    );
}
