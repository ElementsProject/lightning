use anyhow::{Context, Result};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::Builder;
use log::{debug, warn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    bind_address: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    debug!("Starting grpc plugin");
    let path = Path::new("lightning-rpc");
    let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();

    let state = PluginState {
        rpc_path: path.into(),
        bind_address: addr,
    };

    let (plugin, i) = Builder::new(state.clone(), tokio::io::stdin(), tokio::io::stdout()).build();

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
    tonic::transport::Server::builder()
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
