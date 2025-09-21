use anyhow::{anyhow, Context};
use cln_lsps::jsonrpc::client::JsonRpcClient;
use cln_lsps::lsps0::{
    self,
    transport::{Bolt8Transport, CustomMessageHookManager, WithCustomMessageHookManager},
};
use cln_lsps::lsps2::model::{Lsps2GetInfoRequest, Lsps2GetInfoResponse};
use cln_lsps::util;
use cln_lsps::LSP_FEATURE_BIT;
use cln_plugin::options;
use cln_rpc::model::requests::ListpeersRequest;
use cln_rpc::primitives::PublicKey;
use cln_rpc::ClnRpc;
use log::debug;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr as _;

/// An option to enable this service.
const OPTION_ENABLED: options::FlagConfigOption = options::ConfigOption::new_flag(
    "dev-lsps-client-enabled",
    "Enables an LSPS client on the node.",
);

#[derive(Clone)]
struct State {
    hook_manager: CustomMessageHookManager,
}

impl WithCustomMessageHookManager for State {
    fn get_custommsg_hook_manager(&self) -> &CustomMessageHookManager {
        &self.hook_manager
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let hook_manager = CustomMessageHookManager::new();
    let state = State { hook_manager };

    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .hook("custommsg", CustomMessageHookManager::on_custommsg::<State>)
        .option(OPTION_ENABLED)
        .rpcmethod(
            "lsps-listprotocols",
            "list protocols supported by lsp",
            on_lsps_listprotocols,
        )
        .rpcmethod(
            "lsps-lsps2-getinfo",
            "Low-level command to request the opening fee menu of an LSP",
            on_lsps_lsps2_getinfo,
        )
        .configure()
        .await?
    {
        if !plugin.option(&OPTION_ENABLED)? {
            return plugin
                .disable(&format!("`{}` not enabled", OPTION_ENABLED.name))
                .await;
        }

        let plugin = plugin.start(state).await?;
        plugin.join().await
    } else {
        Ok(())
    }
}

/// Rpc Method handler for `lsps-lsps2-getinfo`.
async fn on_lsps_lsps2_getinfo(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: ClnRpcLsps2GetinfoRequest =
        serde_json::from_value(v).context("Failed to parse request JSON")?;
    debug!(
        "Requesting opening fee menu from lsp {} with token {:?}",
        req.lsp_id, req.token
    );

    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut cln_client = cln_rpc::ClnRpc::new(rpc_path.clone()).await?;

    // Fail early: Check that we are connected to the peer and that it has the
    // LSP feature bit set.
    ensure_lsp_connected(&mut cln_client, &req.lsp_id).await?;

    // Create Transport and Client
    let transport = Bolt8Transport::new(
        &req.lsp_id,
        rpc_path.clone(), // Clone path for potential reuse
        p.state().hook_manager.clone(),
        None, // Use default timeout
    )
    .context("Failed to create Bolt8Transport")?;
    let client = JsonRpcClient::new(transport);

    // 1. Call lsps2.get_info.
    let info_req = Lsps2GetInfoRequest { token: req.token };
    let info_res: Lsps2GetInfoResponse = client
        .call_typed(info_req)
        .await
        .context("lsps2.get_info call failed")?;
    debug!("received lsps2.get_info response: {:?}", info_res);

    Ok(serde_json::to_value(info_res)?)
}

async fn on_lsps_listprotocols(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    #[derive(Deserialize)]
    struct Request {
        lsp_id: String,
    }
    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut cln_client = cln_rpc::ClnRpc::new(rpc_path.clone()).await?;

    let req: Request = serde_json::from_value(v).context("Failed to parse request JSON")?;

    // Fail early: Check that we are connected to the peer and that it has the
    // LSP feature bit set.
    ensure_lsp_connected(&mut cln_client, &req.lsp_id).await?;

    // Create the transport first and handle potential errors
    let transport = Bolt8Transport::new(
        &req.lsp_id,
        rpc_path,
        p.state().hook_manager.clone(),
        None, // Use default timeout
    )
    .context("Failed to create Bolt8Transport")?;

    // Now create the client using the transport
    let client = JsonRpcClient::new(transport);

    let request = lsps0::model::Lsps0listProtocolsRequest {};
    let res: lsps0::model::Lsps0listProtocolsResponse = client
        .call_typed(request)
        .await
        .context("lsps0.list_protocols call failed")?;

    debug!("Received lsps0.list_protocols response: {:?}", res);
    Ok(serde_json::to_value(res)?)
}

/// Checks that the node is connected to the peer and that it has the LSP
/// feature bit set.
async fn ensure_lsp_connected(cln_client: &mut ClnRpc, lsp_id: &str) -> Result<(), anyhow::Error> {
    let res = cln_client
        .call_typed(&ListpeersRequest {
            id: Some(PublicKey::from_str(lsp_id)?),
            level: None,
        })
        .await?;

    // unwrap in next line is safe as we checked that an item exists before.
    if res.peers.is_empty() || !res.peers.first().unwrap().connected {
        debug!("Node isn't connected to lsp {lsp_id}");
        return Err(anyhow!("not connected to lsp"));
    }

    res.peers
        .first()
        .filter(|peer| {
            // Check that feature bit is set
            peer.features.as_deref().map_or(false, |f_str| {
                if let Some(feature_bits) = hex::decode(f_str).ok() {
                    let mut fb = feature_bits.clone();
                    fb.reverse();
                    util::is_feature_bit_set(&fb, LSP_FEATURE_BIT)
                } else {
                    false
                }
            })
        })
        .ok_or_else(|| {
            anyhow!(
                "peer is not an lsp, feature bit {} is missing",
                LSP_FEATURE_BIT,
            )
        })?;

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClnRpcLsps2GetinfoRequest {
    lsp_id: String,
    token: Option<String>,
}
