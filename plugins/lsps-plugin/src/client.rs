use anyhow::{anyhow, bail, Context};
use chrono::{Duration, Utc};
use cln_lsps::jsonrpc::client::JsonRpcClient;
use cln_lsps::lsps0::primitives::Msat;
use cln_lsps::lsps0::{
    self,
    transport::{Bolt8Transport, CustomMessageHookManager, WithCustomMessageHookManager},
};
use cln_lsps::lsps2::cln::tlv::encode_tu64;
use cln_lsps::lsps2::cln::{
    HtlcAcceptedRequest, HtlcAcceptedResponse, TLV_FORWARD_AMT, TLV_PAYMENT_SECRET,
};
use cln_lsps::lsps2::model::{
    compute_opening_fee, Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest,
    Lsps2GetInfoResponse, OpeningFeeParams,
};
use cln_lsps::util;
use cln_lsps::LSP_FEATURE_BIT;
use cln_plugin::options;
use cln_rpc::model::requests::{
    DatastoreMode, DatastoreRequest, DeldatastoreRequest, DelinvoiceRequest, DelinvoiceStatus,
    ListdatastoreRequest, ListinvoicesRequest, ListpeersRequest,
};
use cln_rpc::model::responses::InvoiceResponse;
use cln_rpc::primitives::{Amount, AmountOrAny, PublicKey, ShortChannelId};
use cln_rpc::ClnRpc;
use log::{debug, info, warn};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr as _;

/// An option to enable this service.
const OPTION_ENABLED: options::FlagConfigOption = options::ConfigOption::new_flag(
    "experimental-lsps-client",
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
        .rpcmethod(
            "lsps-lsps2-approve",
            "Low-level command to approve a jit channel opening for the given scid",
            on_lsps_lsps2_approve,
        )
        .rpcmethod(
            "lsps-jitchannel",
            "Requests a new jit channel from LSP and returns the matching invoice",
            on_lsps_jitchannel,
        )
        .hook("htlc_accepted", on_htlc_accepted)
        .hook("openchannel", on_openchannel)
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

    let lsp_status = check_peer_lsp_status(&mut cln_client, &req.lsp_id).await?;

    // Fail early: Check that we are connected to the peer.
    if !lsp_status.connected {
        bail!("Not connected to peer {}", &req.lsp_id);
    };

    // From Blip52: LSPs MAY set the features bit numbered 729
    // (option_supports_lsps)...
    // We only log that it is not set but don't fail.
    if !lsp_status.has_lsp_feature {
        debug!("Peer {} doesn't have the LSP feature bit set.", &req.lsp_id);
    }

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

    let lsp_status = check_peer_lsp_status(&mut cln_client, &req.lsp_id).await?;

    // Fail early: Check that we are connected to the peer.
    if !lsp_status.connected {
        bail!("Not connected to peer {}", &req.lsp_id);
    };

    // From Blip52: LSPs MAY set the features bit numbered 729
    // (option_supports_lsps)...
    // We only log that it is not set but don't fail.
    if !lsp_status.has_lsp_feature {
        debug!("Peer {} doesn't have the LSP feature bit set.", &req.lsp_id);
    }

    // Create Transport and Client
    let transport = Bolt8Transport::new(
        &req.lsp_id,
        rpc_path.clone(), // Clone path for potential reuse
        p.state().hook_manager.clone(),
        None, // Use default timeout
    )
    .context("Failed to create Bolt8Transport")?;
    let client = JsonRpcClient::new(transport);

    let selected_params = req.opening_fee_params;
    if let Some(payment_size) = req.payment_size_msat {
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
        payment_size_msat: req.payment_size_msat,
    };
    let buy_res: Lsps2BuyResponse = client
        .call_typed(buy_req)
        .await
        .context("lsps2.buy call failed")?;

    Ok(serde_json::to_value(buy_res)?)
}

async fn on_lsps_lsps2_approve(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: ClnRpcLsps2Approve = serde_json::from_value(v)?;
    let ds_rec = DatastoreRecord {
        jit_channel_scid: req.jit_channel_scid,
        client_trusts_lsp: req.client_trusts_lsp.unwrap_or_default(),
    };
    let ds_rec_json = serde_json::to_string(&ds_rec)?;

    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut cln_client = cln_rpc::ClnRpc::new(rpc_path.clone()).await?;

    let ds_req = DatastoreRequest {
        generation: None,
        hex: None,
        mode: Some(DatastoreMode::CREATE_OR_REPLACE),
        string: Some(ds_rec_json),
        key: vec!["lsps".to_string(), "client".to_string(), req.lsp_id.clone()],
    };
    let _ds_res = cln_client.call_typed(&ds_req).await?;
    let ds_req = DatastoreRequest {
        generation: None,
        hex: None,
        mode: Some(DatastoreMode::CREATE_OR_REPLACE),
        string: Some(req.lsp_id),
        key: vec!["lsps".to_string(), "invoice".to_string(), req.payment_hash],
    };
    let _ds_res = cln_client.call_typed(&ds_req).await?;
    Ok(serde_json::Value::default())
}

/// RPC Method handler for `lsps-jitchannel`.
/// Calls lsps2.get_info, selects parameters, calculates fee, calls lsps2.buy,
/// creates invoice.
async fn on_lsps_jitchannel(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    #[derive(Deserialize)]
    struct Request {
        lsp_id: String,
        // Optional: for discounts/API keys
        token: Option<String>,
        // Pass-through of cln invoice rpc params
        pub amount_msat: cln_rpc::primitives::AmountOrAny,
        pub description: String,
        pub label: String,
    }

    let req: Request = serde_json::from_value(v).context("Failed to parse request JSON")?;
    debug!(
        "Handling lsps-buy-jit-channel request for peer {} with payment_size {:?} and token {:?}",
        req.lsp_id, req.amount_msat, req.token
    );

    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut cln_client = cln_rpc::ClnRpc::new(rpc_path.clone()).await?;

    // 1. Get LSP's opening fee menu.
    let info_res: Lsps2GetInfoResponse = cln_client
        .call_raw(
            "lsps-lsps2-getinfo",
            &ClnRpcLsps2GetinfoRequest {
                lsp_id: req.lsp_id.clone(),
                token: req.token,
            },
        )
        .await?;

    // 2. Select Fee Parameters.
    // Simple strategy for now: choose the first valid option as LSPS2 requires
    // this to be the cheapest. Could be more sophisticated (e.g., user choice).
    let selected_params = info_res
        .opening_fee_params_menu
        .iter()
        .find(|params| {
            // Basic validation on client side: check expiry and promise length
            let fut_now = Utc::now() + Duration::minutes(1); // Add some extra time for network delay
            let expiry_valid = params.valid_until > fut_now;
            if !expiry_valid {
                warn!("Ignoring expired fee params from LSP {:?}", params);
            }
            expiry_valid
        })
        .cloned() // Clone the selected params
        .ok_or_else(|| {
            anyhow!(
                "No valid/unexpired fee parameters offered by LSP {}",
                req.lsp_id
            )
        })?;

    info!("Selected fee parameters: {:?}", selected_params);

    let payment_size_msat = match req.amount_msat {
        AmountOrAny::Amount(amount) => Some(Msat::from_msat(amount.msat())),
        AmountOrAny::Any => None,
    };

    // Check that the amount is big enough to cover the fee and a single HTLC.
    let reduced_amount_msat = if let Some(payment_msat) = payment_size_msat {
        match compute_opening_fee(
            payment_msat.msat(),
            selected_params.min_fee_msat.msat(),
            selected_params.proportional.ppm() as u64,
        ) {
            Some(fee_msat) => {
                if payment_msat.msat() - fee_msat < 1000 {
                    bail!(
                        "amount_msat {}msat is too small, needs to be at least {}msat: opening fee is {}msat",
                        payment_msat,
                        1000 + fee_msat,
                        fee_msat
                    );
                }
                Some(payment_msat.msat() - fee_msat)
            }
            None => bail!("failed to compute opening fee"),
        }
    } else {
        None
    };

    // 3. Request channel from LSP.
    let buy_res: Lsps2BuyResponse = cln_client
        .call_raw(
            "lsps-lsps2-buy",
            &ClnRpcLsps2BuyRequest {
                lsp_id: req.lsp_id.clone(),
                payment_size_msat,
                opening_fee_params: selected_params.clone(),
            },
        )
        .await?;

    debug!("Received lsps2.buy response: {:?}", buy_res);

    // We define the invoice expiry here to avoid cloning `selected_params`
    // as they are about to be moved to the `Lsps2BuyRequest`.
    let expiry = (selected_params.valid_until - Utc::now()).num_seconds();
    if expiry <= 10 {
        return Err(anyhow!(
            "Invoice lifetime is too short, options are valid until: {}",
            selected_params.valid_until,
        ));
    }

    // 4. Create and invoice with a route hint pointing to the LSP, using
    // the scid we got from the LSP.
    let hint = RoutehintHopDev {
        id: req.lsp_id.clone(),
        short_channel_id: buy_res.jit_channel_scid.to_string(),
        fee_base_msat: Some(0),
        fee_proportional_millionths: 0,
        cltv_expiry_delta: u16::try_from(buy_res.lsp_cltv_expiry_delta)?,
    };

    // Generate a preimage if we have an amount specified.
    let preimage = if payment_size_msat.is_some() {
        Some(gen_rand_preimage_hex(&mut rand::rng()))
    } else {
        None
    };

    let public_inv: cln_rpc::model::responses::InvoiceResponse = cln_client
        .call_raw(
            "invoice",
            &InvoiceRequest {
                amount_msat: req.amount_msat,
                dev_routes: Some(vec![vec![hint.clone()]]),
                description: req.description.clone(),
                label: req.label.clone(),
                expiry: Some(expiry as u64),
                cltv: None,
                deschashonly: None,
                preimage: preimage.clone(),
                exposeprivatechannels: None,
                fallbacks: None,
            },
        )
        .await?;

    // We need to reduce the expected amount if the invoice has an amount set
    if let Some(amount_msat) = reduced_amount_msat {
        debug!(
            "amount_msat is specified: create new invoice with reduced amount {}msat",
            amount_msat,
        );
        let _ = cln_client
            .call_typed(&DelinvoiceRequest {
                desconly: None,
                status: DelinvoiceStatus::UNPAID,
                label: req.label.clone(),
            })
            .await?;

        let _: cln_rpc::model::responses::InvoiceResponse = cln_client
            .call_raw(
                "invoice",
                &InvoiceRequest {
                    amount_msat: AmountOrAny::Amount(Amount::from_msat(amount_msat)),
                    dev_routes: Some(vec![vec![hint]]),
                    description: req.description,
                    label: req.label,
                    expiry: Some(expiry as u64),
                    cltv: None,
                    deschashonly: None,
                    preimage,
                    exposeprivatechannels: None,
                    fallbacks: None,
                },
            )
            .await?;
    }

    // 5. Approve jit_channel_scid for a jit channel opening.
    let appr_req = ClnRpcLsps2Approve {
        lsp_id: req.lsp_id,
        jit_channel_scid: buy_res.jit_channel_scid,
        payment_hash: public_inv.payment_hash.to_string(),
        client_trusts_lsp: Some(buy_res.client_trusts_lsp),
    };
    let _: serde_json::Value = cln_client.call_raw("lsps-lsps2-approve", &appr_req).await?;

    // 6. Return invoice.
    let out = InvoiceResponse {
        bolt11: public_inv.bolt11,
        created_index: public_inv.created_index,
        warning_capacity: public_inv.warning_capacity,
        warning_deadends: public_inv.warning_deadends,
        warning_mpp: public_inv.warning_mpp,
        warning_offline: public_inv.warning_offline,
        warning_private_unused: public_inv.warning_private_unused,
        expires_at: public_inv.expires_at,
        payment_hash: public_inv.payment_hash,
        payment_secret: public_inv.payment_secret,
    };
    Ok(serde_json::to_value(out)?)
}

async fn on_htlc_accepted(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: HtlcAcceptedRequest = serde_json::from_value(v)?;

    let htlc_amt = req.htlc.amount_msat;
    let onion_amt = match req.onion.forward_msat {
        Some(a) => a,
        None => {
            debug!("onion is missing forward_msat, continue");
            let value = serde_json::to_value(HtlcAcceptedResponse::continue_(None, None, None))?;
            return Ok(value);
        }
    };

    let Some(payment_data) = req.onion.payload.get(TLV_PAYMENT_SECRET) else {
        debug!("payment is a forward, continue");
        let value = serde_json::to_value(HtlcAcceptedResponse::continue_(None, None, None))?;
        return Ok(value);
    };

    let extra_fee_msat = req
        .htlc
        .extra_tlvs
        .as_ref()
        .map(|tlvs| tlvs.get_u64(65537))
        .transpose()?
        .flatten();
    if let Some(amt) = extra_fee_msat {
        debug!("lsp htlc is deducted by an extra_fee={amt}");
    }

    // Check that the htlc belongs to a jit-channel request.
    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut cln_client = cln_rpc::ClnRpc::new(rpc_path.clone()).await?;
    let lsp_data = cln_client
        .call_typed(&ListdatastoreRequest {
            key: Some(vec![
                "lsps".to_string(),
                "invoice".to_string(),
                hex::encode(&req.htlc.payment_hash),
            ]),
        })
        .await?;

    if lsp_data.datastore.first().is_none() {
        // Not an LSP payment, just continue
        debug!("payment is a not a jit-channel-opening, continue");
        let value = serde_json::to_value(HtlcAcceptedResponse::continue_(None, None, None))?;
        return Ok(value);
    };

    debug!(
        "incoming jit-channel htlc with htlc_amt={} and onion_amt={}",
        htlc_amt.msat(),
        onion_amt.msat()
    );

    let inv_res = cln_client
        .call_typed(&ListinvoicesRequest {
            index: None,
            invstring: None,
            label: None,
            limit: None,
            offer_id: None,
            payment_hash: Some(hex::encode(&req.htlc.payment_hash)),
            start: None,
        })
        .await?;

    let Some(invoice) = inv_res.invoices.first() else {
        debug!(
            "no invoice found for jit-channel opening with payment_hash={}",
            hex::encode(&req.htlc.payment_hash)
        );
        let value = serde_json::to_value(HtlcAcceptedResponse::continue_(None, None, None))?;
        return Ok(value);
    };

    let total_amt = match invoice.amount_msat {
        Some(a) => {
            debug!("invoice has total_amt={}msat", &a.msat());
            a.msat()
        }
        None => {
            debug!("invoice has no total amount, only accept single htlc");
            htlc_amt.msat()
        }
    };

    // Fixme: Check that we did not already pay for this channel.
    // - via datastore or invoice label.

    // Fixme: Check the if MPP or No-MPP, assuming No-MPP for now.
    // - check that extra_fee + htlc is the total_amount_msat of the onion.

    let mut payload = req.onion.payload.clone();
    payload.set_tu64(TLV_FORWARD_AMT, htlc_amt.msat());

    let mut ps = Vec::new();
    ps.extend_from_slice(&payment_data[0..32]);
    ps.extend(encode_tu64(total_amt));
    payload.insert(TLV_PAYMENT_SECRET, ps);
    let payload_bytes = match payload.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            warn!("can't encode payload to bytes {}", e);
            let value = serde_json::to_value(HtlcAcceptedResponse::continue_(None, None, None))?;
            return Ok(value);
        }
    };

    info!(
        "Amended onion payload with forward_amt={} and total_msat={}",
        htlc_amt.msat(),
        total_amt
    );
    let value = serde_json::to_value(HtlcAcceptedResponse::continue_(
        Some(payload_bytes),
        None,
        None,
    ))?;
    Ok(value)
}

/// Allows `zero_conf` channels to the client if the LSP is on the allowlist.
async fn on_openchannel(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    #[derive(Deserialize)]
    struct Request {
        id: String,
    }

    let req: Request = serde_json::from_value(v.get("openchannel").unwrap().clone())
        .context("Failed to parse request JSON")?;
    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut cln_client = cln_rpc::ClnRpc::new(rpc_path.clone()).await?;

    let ds_req = ListdatastoreRequest {
        key: Some(vec![
            "lsps".to_string(),
            "client".to_string(),
            req.id.clone(),
        ]),
    };
    let ds_res = cln_client.call_typed(&ds_req).await?;
    if let Some(_rec) = ds_res.datastore.iter().next() {
        info!("Allowing zero-conf channel from LSP {}", &req.id);
        let ds_req = DeldatastoreRequest {
            generation: None,
            key: vec!["lsps".to_string(), "client".to_string(), req.id.clone()],
        };
        if let Some(err) = cln_client.call_typed(&ds_req).await.err() {
            // We can do nothing but report that there was an issue deleting the
            // datastore record.
            warn!("Failed to delete LSP record from datastore: {}", err);
        }
        // Fixme: Check that we actually use client-trusts-LSP mode - can be
        // found in the ds record.
        return Ok(serde_json::json!({
            "result": "continue",
            "mindepth": 0,
        }));
    } else {
        // Not a requested JIT-channel opening, continue.
        Ok(serde_json::json!({"result": "continue"}))
    }
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
    let lsp_status = check_peer_lsp_status(&mut cln_client, &req.lsp_id).await?;

    // Fail early: Check that we are connected to the peer.
    if !lsp_status.connected {
        bail!("Not connected to peer {}", &req.lsp_id);
    };

    // From Blip52: LSPs MAY set the features bit numbered 729
    // (option_supports_lsps)...
    // We only log that it is not set but don't fail.
    if !lsp_status.has_lsp_feature {
        debug!("Peer {} doesn't have the LSP feature bit set.", &req.lsp_id);
    }

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
        .map_err(|e| anyhow!("lsps0.list_protocols call failed: {}", e))?;

    debug!("Received lsps0.list_protocols response: {:?}", res);
    Ok(serde_json::to_value(res)?)
}

struct PeerLspStatus {
    connected: bool,
    has_lsp_feature: bool,
}

/// Returns the `PeerLspStatus`, containing information about the connectivity
/// and the LSP feature bit.
async fn check_peer_lsp_status(
    cln_client: &mut ClnRpc,
    peer_id: &str,
) -> Result<PeerLspStatus, anyhow::Error> {
    let res = cln_client
        .call_typed(&ListpeersRequest {
            id: Some(PublicKey::from_str(peer_id)?),
            level: None,
        })
        .await?;

    let peer = match res.peers.first() {
        None => {
            return Ok(PeerLspStatus {
                connected: false,
                has_lsp_feature: false,
            })
        }
        Some(p) => p,
    };

    let connected = peer.connected;
    let has_lsp_feature = if let Some(f_str) = &peer.features {
        let feature_bits = hex::decode(f_str)
            .map_err(|e| anyhow!("Invalid feature bits hex for peer {peer_id}, {f_str}: {e}"))?;
        util::is_feature_bit_set_reversed(&feature_bits, LSP_FEATURE_BIT)
    } else {
        false
    };

    Ok(PeerLspStatus {
        connected,
        has_lsp_feature,
    })
}

pub fn gen_rand_preimage_hex<R: Rng + CryptoRng>(rng: &mut R) -> String {
    let mut pre = [0u8; 32];
    rng.fill_bytes(&mut pre);
    hex::encode(&pre)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LspsBuyJitChannelResponse {
    bolt11: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoiceRequest {
    pub amount_msat: cln_rpc::primitives::AmountOrAny,
    pub description: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cltv: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deschashonly: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposeprivatechannels: Option<Vec<String>>,
    #[serde(rename = "dev-routes", skip_serializing_if = "Option::is_none")]
    pub dev_routes: Option<Vec<Vec<RoutehintHopDev>>>,
}

// This variant is used by dev-routes, using slightly different key names.
// TODO Remove once we have consolidated the routehint format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutehintHopDev {
    pub id: String,
    pub short_channel_id: String,
    pub fee_base_msat: Option<u64>,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClnRpcLsps2BuyRequest {
    lsp_id: String,
    payment_size_msat: Option<Msat>,
    opening_fee_params: OpeningFeeParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClnRpcLsps2GetinfoRequest {
    lsp_id: String,
    token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClnRpcLsps2Approve {
    lsp_id: String,
    jit_channel_scid: ShortChannelId,
    payment_hash: String,
    #[serde(default)]
    client_trusts_lsp: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatastoreRecord {
    jit_channel_scid: ShortChannelId,
    client_trusts_lsp: bool,
}
