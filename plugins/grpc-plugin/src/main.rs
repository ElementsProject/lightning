use anyhow::{anyhow, Context, Result};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::{options, Builder};
use log::{debug, warn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

mod tls;

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    identity: tls::Identity,
    ca_cert: Vec<u8>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    debug!("Starting grpc plugin");
    let path = Path::new("lightning-rpc");

    let directory = std::env::current_dir()?;

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "grpc-port",
            options::Value::Integer(-1),
            "Which port should the grpc plugin listen for incoming connections?",
        ))
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let bind_port = match plugin.option("grpc-port") {
        Some(options::Value::Integer(-1)) => {
            log::info!("`grpc-port` option is not configured, exiting.");
            plugin
                .disable("`grpc-port` option is not configured.")
                .await?;
            return Ok(());
        }
        Some(options::Value::Integer(i)) => i,
        None => return Err(anyhow!("Missing 'grpc-port' option")),
        Some(o) => return Err(anyhow!("grpc-port is not a valid integer: {:?}", o)),
    };

    let (identity, ca_cert) = tls::init(&directory)?;

    let state = PluginState {
        rpc_path: path.into(),
        identity,
        ca_cert,
    };

    let plugin = plugin.start(state.clone()).await?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse().unwrap();

    tokio::select! {
        _ = plugin.join() => {
	    // This will likely never be shown, if we got here our
	    // parent process is exiting and not processing out log
	    // messages anymore.
            debug!("Plugin loop terminated")
        }
        e = run_interface(bind_addr, state) => {
            warn!("Error running grpc interface: {:?}", e)
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
            cln_grpc::Server::new(&state.rpc_path)
                .await
                .context("creating NodeServer instance")?,
        ))
        .serve(bind_addr);

    debug!(
        "Connecting to {:?} and serving grpc on {:?}",
        &state.rpc_path, &bind_addr
    );

    server.await.context("serving requests")?;

    Ok(())
}
