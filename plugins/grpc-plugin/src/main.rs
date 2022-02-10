use anyhow::{Context, Result};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::{options, Builder};
use log::{debug, warn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

mod tls;

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    bind_address: SocketAddr,
    identity: tls::Identity,
    ca_cert: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    debug!("Starting grpc plugin");
    let path = Path::new("lightning-rpc");
    let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();

    let directory = std::env::current_dir()?;
    let (identity, ca_cert) = tls::init(&directory)?;

    let state = PluginState {
        rpc_path: path.into(),
        bind_address: addr,
        identity,
        ca_cert,
    };

    let plugin = Builder::new(state.clone(), tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "grpc-port",
            options::Value::Integer(29735),
            "Which port should the grpc plugin listen for incoming connections?",
        ))
        .start()
        .await?;

    tokio::spawn(async move {
        if let Err(e) = run_interface(state).await {
            warn!("Error running the grpc interface: {}", e);
        }
    });

    plugin.join().await
}

async fn run_interface(state: PluginState) -> Result<()> {
    debug!(
        "Connecting to {:?} and serving grpc on {:?}",
        &state.rpc_path, &state.bind_address
    );

    let identity = state.identity.to_tonic_identity();
    let ca_cert = tonic::transport::Certificate::from_pem(state.ca_cert);

    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    tonic::transport::Server::builder()
        .tls_config(tls)
        .context("configuring tls")?
        .add_service(NodeServer::new(
            cln_grpc::Server::new(&state.rpc_path)
                .await
                .context("creating NodeServer instance")?,
        ))
        .serve(state.bind_address)
        .await
        .context("serving requests")?;

    Ok(())
}
