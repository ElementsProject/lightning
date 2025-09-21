use anyhow::{anyhow, Context};
use cln_lsps::jsonrpc::client::JsonRpcClient;
use cln_lsps::lsps0::primitives::Msat;
use cln_lsps::lsps0::{
    self,
    transport::{Bolt8Transport, CustomMessageHookManager, WithCustomMessageHookManager},
};
use cln_lsps::lsps2::model::{
    compute_opening_fee, Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest,
    Lsps2GetInfoResponse, OpeningFeeParams,
};
use cln_lsps::util;
use cln_lsps::LSP_FEATURE_BIT;
use cln_plugin::options;
use cln_rpc::model::requests::ListpeersRequest;
use cln_rpc::primitives::{AmountOrAny, PublicKey};
use cln_rpc::ClnRpc;
use log::{debug, info, warn};
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
        .rpcmethod(
            "lsps-lsps2-buy",
            "Low-level command to return the lsps2.buy result from an ",
            on_lsps_lsps2_buy,
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

/// Rpc Method handler for `lsps-lsps2-buy`.
async fn on_lsps_lsps2_buy(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: ClnRpcLsps2BuyRequest =
        serde_json::from_value(v).context("Failed to parse request JSON")?;
    debug!(
        "Asking for a channel from lsp {} with opening fee params {:?} and payment size {:?}",
        req.lsp_id, req.opening_fee_params, req.payment_size_msat
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

    // Convert from AmountOrAny to Msat.
    let payment_size_msat = if let Some(payment_size) = req.payment_size_msat {
        match payment_size {
            AmountOrAny::Amount(amount) => Some(Msat::from_msat(amount.msat())),
            AmountOrAny::Any => None,
        }
    } else {
        None
    };

    let selected_params = req.opening_fee_params;

    if let Some(payment_size) = payment_size_msat {
        if payment_size < selected_params.min_payment_size_msat {
            return Err(anyhow!(
                "Requested payment size {}msat is below minimum {}msat required by LSP",
                payment_size,
                selected_params.min_payment_size_msat
            ));
        }
        if payment_size > selected_params.max_payment_size_msat {
            return Err(anyhow!(
                "Requested payment size {}msat is above maximum {}msat allowed by LSP",
                payment_size,
                selected_params.max_payment_size_msat
            ));
        }

        let opening_fee = compute_opening_fee(
            payment_size.msat(),
            selected_params.min_fee_msat.msat(),
            selected_params.proportional.ppm() as u64,
        )
        .ok_or_else(|| {
            warn!(
                "Opening fee calculation overflowed for payment size {}",
                payment_size
            );
            anyhow!("failed to calculate opening fee")
        })?;

        info!(
            "Calculated opening fee: {}msat for payment size {}msat",
            opening_fee, payment_size
        );
    } else {
        info!("No payment size specified, requesting JIT channel for a variable-amount invoice.");
        // Check if the selected params allow for variable amount (implicitly they do if max > min)
        if selected_params.min_payment_size_msat >= selected_params.max_payment_size_msat {
            // This shouldn't happen if LSP follows spec, but good to check.
            warn!("Selected fee params seem unsuitable for variable amount: min >= max");
        }
    }

    debug!("Calling lsps2.buy for peer {}", req.lsp_id);
    let buy_req = Lsps2BuyRequest {
        opening_fee_params: selected_params, // Pass the chosen params back
        payment_size_msat,
    };
    let buy_res: Lsps2BuyResponse = client
        .call_typed(buy_req)
        .await
        .context("lsps2.buy call failed")?;

    Ok(serde_json::to_value(buy_res)?)
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
struct ClnRpcLsps2BuyRequest {
    lsp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_size_msat: Option<AmountOrAny>,
    opening_fee_params: OpeningFeeParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClnRpcLsps2GetinfoRequest {
    lsp_id: String,
    token: Option<String>,
}
