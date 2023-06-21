use anyhow::{anyhow, Context, Result};
use cln_grpc_hold::pb::hold_server::HoldServer;
use cln_grpc_hold::Holdstate;
use cln_plugin::{options, Builder};
use cln_rpc::model::ListinvoicesInvoices;
use log::{debug, info, warn};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod hooks;
mod tasks;
mod tls;
mod util;

#[derive(Clone, Debug)]
pub struct HoldHtlc {
    pub amount_msat: u64,
    pub cltv_expiry: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HtlcIdentifier {
    pub scid: String,
    pub htlc_id: u64,
}

#[derive(Clone, Debug)]
pub struct HoldInvoice {
    pub hold_state: Holdstate,
    pub generation: u64,
    pub htlc_data: HashMap<HtlcIdentifier, HoldHtlc>,
    pub invoice: ListinvoicesInvoices,
}

#[derive(Clone, Debug)]
pub struct PluginState {
    pub blockheight: Arc<Mutex<u32>>,
    pub holdinvoices: Arc<tokio::sync::Mutex<BTreeMap<String, HoldInvoice>>>,
    rpc_path: PathBuf,
    identity: tls::Identity,
    ca_cert: Vec<u8>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    debug!("Starting grpc-hold plugin");
    std::env::set_var("CLN_PLUGIN_LOG", "debug");
    let path = Path::new("lightning-rpc");

    let directory = std::env::current_dir()?;
    let (identity, ca_cert) = tls::init(&directory)?;

    let state = PluginState {
        blockheight: Arc::new(Mutex::new(u32::default())),
        holdinvoices: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        rpc_path: path.into(),
        identity,
        ca_cert,
    };

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "grpc-hold-port",
            options::Value::Integer(-1),
            "Which port should the grpc plugin listen for incoming connections?",
        ))
        .hook("htlc_accepted", hooks::htlc_handler)
        .subscribe("block_added", hooks::block_added)
        .configure()
        .await?
    {
        Some(p) => {
            // info!("read config");
            // match config::read_config(&p, state.clone()).await {
            //     Ok(()) => &(),
            //     Err(e) => return p.disable(format!("{}", e).as_str()).await,
            // };
            p
        }
        None => return Ok(()),
    };

    let bind_port = match plugin.option("grpc-hold-port") {
        Some(options::Value::Integer(-1)) => {
            log::info!("`grpc-hold-port` option is not configured, exiting.");
            plugin
                .disable("`grpc-hold-port` option is not configured.")
                .await?;
            return Ok(());
        }
        Some(options::Value::Integer(i)) => i,
        None => return Err(anyhow!("Missing 'grpc-hold-port' option")),
        Some(o) => return Err(anyhow!("grpc-hold-port is not a valid integer: {:?}", o)),
    };
    let confplugin;
    match plugin.start(state.clone()).await {
        Ok(p) => {
            info!("starting lookup_state task");
            confplugin = p;
            let lookupclone = confplugin.clone();
            tokio::spawn(async move {
                match tasks::lookup_state(lookupclone).await {
                    Ok(()) => (),
                    Err(e) => warn!("Error in lookup_state thread: {}", e.to_string()),
                };
            });
            let cleanupclone = confplugin.clone();
            tokio::spawn(async move {
                match tasks::clean_up(cleanupclone).await {
                    Ok(()) => (),
                    Err(e) => warn!("Error in clean_up thread: {}", e.to_string()),
                };
            });
        }
        Err(e) => return Err(anyhow!("Error starting plugin: {}", e)),
    }

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse().unwrap();

    tokio::select! {
        _ = confplugin.join() => {
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
        .add_service(HoldServer::new(
            cln_grpc_hold::Server::new(&state.rpc_path)
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
