use anyhow::{Context, anyhow, bail};
use bitcoin::hashes::{Hash, hex::FromHex, sha256};
use chrono::{Duration, Utc};
use cln_lsps::{
    cln_adapters::{
        hooks,
        sender::ClnSender,
        state::ClientState,
        types::{
            HtlcAcceptedRequest, HtlcAcceptedResponse, InvoicePaymentRequest, OpenChannelRequest,
        },
    },
    core::{
        client::LspsClient,
        features::is_feature_bit_set_reversed,
        tlv::{TLV_FORWARD_AMT, TLV_PAYMENT_SECRET, encode_tu64},
        transport::{MultiplexedTransport, PendingRequests},
    },
};
use cln_plugin::{HookBuilder, HookFilter, options};
use cln_rpc::{
    ClnRpc,
    model::{
        requests::{
            DatastoreMode, DatastoreRequest, DeldatastoreRequest, DelinvoiceRequest,
            DelinvoiceStatus, ListdatastoreRequest, ListinvoicesRequest, ListpeerchannelsRequest,
            ListpeersRequest,
        },
        responses::{InvoiceResponse, ListdatastoreDatastore},
    },
    primitives::{Amount, AmountOrAny, ChannelState, PublicKey, ShortChannelId},
};
use log::{debug, info, warn};
use lsps_types::{
    lsps0::{LSP_FEATURE_BIT, LSPS0_MESSAGE_TYPE, Msat},
    lsps2::{Lsps2BuyResponse, Lsps2GetInfoResponse, OpeningFeeParams, compute_opening_fee},
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;

/// An option to enable this service.
const OPTION_ENABLED: options::FlagConfigOption = options::ConfigOption::new_flag(
    "experimental-lsps-client",
    "Enables an LSPS client on the node.",
);

const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone)]
pub struct State {
    rpc_path: PathBuf,
    sender: ClnSender,
    pending: PendingRequests,
    timeout: std::time::Duration,
    /// Held while reading or changing the zero-conf approvals.
    approvals: Arc<tokio::sync::Mutex<()>>,
}

impl State {
    pub fn new(rpc_path: PathBuf, timeout: std::time::Duration) -> Self {
        Self {
            sender: ClnSender::new(rpc_path.clone()),
            rpc_path,
            pending: PendingRequests::new(),
            timeout,
            approvals: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Connects to core-lightning's RPC.
    pub async fn rpc(&self) -> Result<ClnRpc, anyhow::Error> {
        ClnRpc::new(&self.rpc_path)
            .await
            .context("failed to connect to core-lightning")
    }

    pub fn client(&self) -> LspsClient<MultiplexedTransport<ClnSender>> {
        LspsClient::new(self.transport())
    }
}

impl ClientState for State {
    fn transport(&self) -> MultiplexedTransport<ClnSender> {
        MultiplexedTransport::new(self.sender.clone(), self.pending.clone(), self.timeout)
    }

    fn pending(&self) -> &PendingRequests {
        &self.pending
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .hook_from_builder(
            HookBuilder::new("custommsg", hooks::client_custommsg_hook)
                .filters(vec![HookFilter::Int(i64::from(LSPS0_MESSAGE_TYPE))]),
        )
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
            "lsps-lsps2-invoice",
            "Requests a new jit channel from LSP and returns the matching invoice",
            on_lsps_lsps2_invoice,
        )
        .hook("invoice_payment", on_invoice_payment)
        .hook("htlc_accepted", on_htlc_accepted)
        .hook("openchannel", on_openchannel)
        .hook("peer_connected", on_peer_connected)
        .subscribe("channel_opened", on_channel_opened)
        .configure()
        .await?
    {
        if !plugin.option(&OPTION_ENABLED)? {
            return plugin
                .disable(&format!("`{}` not enabled", OPTION_ENABLED.name))
                .await;
        }

        let dir = plugin.configuration().lightning_dir;
        let rpc_path = Path::new(&dir).join(&plugin.configuration().rpc_file);
        let state = State::new(rpc_path, DEFAULT_REQUEST_TIMEOUT);

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

    let lsp_id = PublicKey::from_str(&req.lsp_id).context("lsp_id is not a valid public key")?;

    let mut cln_client = p.state().rpc().await?;

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

    // 1. Call lsps2.get_info.
    let client = p.state().client();
    match client.get_info(&lsp_id, req.token).await?.as_result() {
        Ok(i) => Ok(serde_json::to_value(i)?),
        Err(e) => Ok(serde_json::to_value(e)?),
    }
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

    let lsp_id = PublicKey::from_str(&req.lsp_id).context("lsp_id is not a valid public key")?;

    let mut cln_client = p.state().rpc().await?;

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

    let client = p.state().client();

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
    match client
        .buy(&lsp_id, selected_params, req.payment_size_msat)
        .await?
        .as_result()
    {
        Ok(i) => Ok(serde_json::to_value(i)?),
        Err(e) => Ok(serde_json::to_value(e)?),
    }
}

async fn on_lsps_lsps2_approve(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: ClnRpcLsps2Approve = serde_json::from_value(v)?;

    let mut cln_client = p.state().rpc().await?;

    // The approval lasts as long as the invoice of the buy: the LSP's channel
    // can't pay it after that.
    let invoices = cln_client
        .call_typed(&ListinvoicesRequest {
            index: None,
            invstring: None,
            label: None,
            limit: None,
            offer_id: None,
            payment_hash: Some(req.payment_hash.clone()),
            start: None,
        })
        .await?;
    let invoice = invoices
        .invoices
        .first()
        .ok_or_else(|| anyhow!("No invoice with payment_hash {}", req.payment_hash))?;

    let mut key = approvals_key(&req.lsp_id);
    key.push(req.jit_channel_scid.to_string());
    let approval = Approval {
        key,
        record: DatastoreRecord {
            jit_channel_scid: req.jit_channel_scid,
            client_trusts_lsp: req.client_trusts_lsp.unwrap_or_default(),
            expires_at: invoice.expires_at,
            funding_txid: None,
            given_back_from: Vec::new(),
        },
    };
    {
        let _lock = p.state().approvals.lock().await;
        // Also deletes the single record per LSP of older versions, which
        // would keep us from creating the key for this buy below it.
        live_approvals(&mut cln_client, &req.lsp_id, unix_now()).await?;
        save_approval(&mut cln_client, &approval).await?;
    }

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

/// Selects the opening fee parameters to buy a JIT channel with.
///
/// Simple strategy for now: choose the first usable option as LSPS2 requires
/// the menu to be ordered by increasing fees. Could be more sophisticated
/// (e.g., user choice). An option is unusable if it expires within a minute
/// (extra time for network delay) or if its `min_payment_size_msat` is
/// above its `max_payment_size_msat`, so no payment size fits.
fn select_opening_fee_params(
    menu: &[OpeningFeeParams],
    now: chrono::DateTime<Utc>,
) -> Option<&OpeningFeeParams> {
    menu.iter().find(|params| {
        let fut_now = now + Duration::minutes(1);
        if params.valid_until.as_chrono() <= fut_now {
            warn!("Ignoring expired fee params from LSP {:?}", params);
            return false;
        }
        if let Err(e) = params.check_limits() {
            warn!("Ignoring unusable fee params from LSP {:?}: {}", params, e);
            return false;
        }
        true
    })
}

/// Seconds to take off an invoice's expiry so that it does not outlive the
/// params' `valid_until`. lightningd adds the expiry to its own clock when it
/// creates the invoice, so the time the `invoice` call takes counts against
/// `valid_until` too.
const INVOICE_EXPIRY_MARGIN_SECS: i64 = 5;

/// The expiry, in seconds, for an invoice created at `now` that must not
/// outlive `valid_until`.
fn invoice_expiry(valid_until: chrono::DateTime<Utc>, now: chrono::DateTime<Utc>) -> i64 {
    (valid_until - now).num_seconds() - INVOICE_EXPIRY_MARGIN_SECS
}

/// RPC Method handler for `lsps-jitchannel`.
/// Calls lsps2.get_info, selects parameters, calculates fee, calls lsps2.buy,
/// creates invoice.
async fn on_lsps_lsps2_invoice(
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

    let mut cln_client = p.state().rpc().await?;

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
    let selected_params = select_opening_fee_params(&info_res.opening_fee_params_menu, Utc::now())
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
    let valid_until = selected_params.valid_until.as_chrono();
    let expiry = invoice_expiry(valid_until, Utc::now());
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

        // Not `expiry`: creating the public invoice took time, and this
        // one must not outlive `valid_until` either. `invoice` accepts an
        // expiry of 0, so don't create one that is already expired.
        let reduced_expiry = invoice_expiry(valid_until, Utc::now());
        if reduced_expiry <= 0 {
            return Err(anyhow!(
                "Opening fee params expired while creating the invoice, they were valid until: {}",
                selected_params.valid_until,
            ));
        }

        let _: cln_rpc::model::responses::InvoiceResponse = cln_client
            .call_raw(
                "invoice",
                &InvoiceRequest {
                    amount_msat: AmountOrAny::Amount(Amount::from_msat(amount_msat)),
                    dev_routes: Some(vec![vec![hint]]),
                    description: req.description,
                    label: req.label,
                    expiry: Some(reduced_expiry as u64),
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
        jit_channel_scid: ShortChannelId::from(buy_res.jit_channel_scid.to_u64()),
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

async fn on_invoice_payment(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: InvoicePaymentRequest = ok_or_continue!(
        serde_json::from_value(v).context("failed to deserialize htlc_accepted request JSON")
    );
    let preimage = ok_or_continue!(
        <[u8; 32]>::from_hex(&req.payment.preimage).context("invalid preimage hex")
    );
    let hash = payment_hash(&preimage);

    // Delete DS-entries.
    let mut cln_client = ok_or_continue!(p.state().rpc().await);
    let invoice_key = vec!["lsps".to_string(), "invoice".to_string(), hash.to_string()];
    let lsp_id = ok_or_continue!(
        cln_client
            .call_typed(&ListdatastoreRequest {
                key: Some(invoice_key.clone()),
            })
            .await
            .context("failed to read datastore record")
    )
    .datastore
    .into_iter()
    .find(|e| e.key == invoice_key)
    .and_then(|e| e.string);
    ok_or_continue!(
        cln_client
            .call_typed(&DeldatastoreRequest {
                key: invoice_key,
                generation: None,
            })
            .await
            .context("failed to delete datastore record")
    );

    // The buy's channel is open: its spent approval is done with.
    if let Some(lsp_id) = lsp_id {
        let _lock = p.state().approvals.lock().await;
        if let Err(e) = settle_spent_approvals(&mut cln_client, &lsp_id, false).await {
            warn!("Failed to delete spent zero-conf approvals: {:#}", e);
        }
    }

    Ok(serde_json::json!({"result": "continue"}))
}

async fn on_htlc_accepted(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: HtlcAcceptedRequest = ok_or_continue!(
        serde_json::from_value(v).context("failed to deserialize htlc_accepted request JSON")
    );

    let htlc_amt = req.htlc.amount_msat;
    let onion_amt = some_or_continue!(
        req.onion.forward_msat,
        "missing forward_msat in onion, continue"
    );

    let payment_data = some_or_continue!(
        req.onion.payload.get(TLV_PAYMENT_SECRET),
        "htlc is a forward, continue"
    );

    // Check that the htlc belongs to a jit-channel request.
    let mut cln_client = ok_or_continue!(p.state().rpc().await);

    let lsp_data = ok_or_continue!(
        cln_client
            .call_typed(&ListdatastoreRequest {
                key: Some(vec![
                    "lsps".to_string(),
                    "invoice".to_string(),
                    hex::encode(&req.htlc.payment_hash),
                ]),
            })
            .await
            .context("failed to fetch datastore record")
    );

    // If we don't know about this payment it's not an LSP payment, continue.
    some_or_continue!(lsp_data.datastore.first());

    let extra_fee_msat = req
        .htlc
        .extra_tlvs
        .as_ref()
        .map(|tlvs| tlvs.get_u64(65537))
        .transpose()?
        .flatten()
        .unwrap_or_default();

    debug!(
        "incoming jit-channel htlc with htlc_amt={}, onion_amt={} and extra_fee={}",
        htlc_amt.msat(),
        onion_amt.msat(),
        extra_fee_msat
    );

    if htlc_amt.msat() + extra_fee_msat != onion_amt.msat() {
        warn!(
            "amounts don't match (htlc_amt + extra_fee) = {} != onion_amt = {}",
            (htlc_amt.msat() + extra_fee_msat),
            onion_amt.msat()
        );
        // FIXME: If we are strict, we should reject the htlc here.
    }

    let inv_res = ok_or_continue!(
        cln_client
            .call_typed(&ListinvoicesRequest {
                index: None,
                invstring: None,
                label: None,
                limit: None,
                offer_id: None,
                payment_hash: Some(hex::encode(&req.htlc.payment_hash)),
                start: None,
            })
            .await
            .context("failed to get invoice")
    );

    let invoice = some_or_continue!(
        inv_res.invoices.first(),
        "no invoice found for jit-channel-opening with payment_hash={}",
        hex::encode(&req.htlc.payment_hash)
    );

    let total_amt = invoice.amount_msat.unwrap_or(htlc_amt).msat();

    let mut payload = req.onion.payload.clone();
    payload.set_tu64(TLV_FORWARD_AMT, htlc_amt.msat());

    let mut ps = Vec::new();
    ps.extend_from_slice(&payment_data[0..32]);
    ps.extend(encode_tu64(total_amt));
    payload.insert(TLV_PAYMENT_SECRET, ps);
    let payload_bytes = ok_or_continue!(
        payload
            .to_bytes()
            .context("failed to encode payload as bytes")
    );

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

/// Allows a `zero_conf` channel from an LSP if one of its buys has an
/// approval left.
///
/// The open_channel message doesn't say which buy the channel is for, so
/// any approval left will do. The approval isn't spent here but once the
/// channel is open, in `on_channel_opened`: an open that fails after this
/// hook leaves the approval to the LSP's retry.
async fn on_openchannel(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let req: OpenChannelRequest = ok_or_continue!(
        serde_json::from_value(v).context("failed to deserialize open_channel request JSON")
    );

    // Fixme: Check that channel parameters are as negotiated.

    let mut cln_client = ok_or_continue!(p.state().rpc().await);

    let _lock = p.state().approvals.lock().await;
    let approvals =
        ok_or_continue!(live_approvals(&mut cln_client, &req.openchannel.id, unix_now()).await);

    if approvals.iter().any(|a| a.record.funding_txid.is_none()) {
        info!(
            "Allowing zero-conf channel from LSP {}",
            &req.openchannel.id
        );
        // Fixme: Check that we actually use client-trusts-LSP mode - can be
        // found in the ds record.
        Ok(serde_json::json!({
            "result": "continue",
            "mindepth": 0,
        }))
    } else {
        // Not a requested JIT-channel opening, continue.
        Ok(serde_json::json!({"result": "continue"}))
    }
}

/// Spends an approval of the LSP once its channel is open.
///
/// lightningd saves the channel and sends this notification before it sends
/// `funding_signed`, so the LSP can't open again before the notification is
/// on its way. The `openchannel` hook for that next open runs as a task of
/// its own, though, and may still take the approvals lock first.
async fn on_channel_opened(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<(), anyhow::Error> {
    #[derive(Deserialize)]
    struct ChannelOpened {
        id: String,
        funding_txid: String,
    }
    #[derive(Deserialize)]
    struct Notification {
        channel_opened: ChannelOpened,
    }
    let opened = serde_json::from_value::<Notification>(v)
        .context("failed to deserialize channel_opened notification JSON")?
        .channel_opened;

    // Queue up for the lock before anything else: the lock is fair, so the
    // `openchannel` hook for the LSP's next open, which can only arrive
    // after our `funding_signed`, waits for this notification.
    let _lock = p.state().approvals.lock().await;

    let mut cln_client = p.state().rpc().await?;

    let approvals = live_approvals(&mut cln_client, &opened.id, unix_now()).await?;
    // We can't tell which buy the channel is for: spend the approval that
    // expires first.
    if let Some(mut approval) = approvals
        .into_iter()
        .find(|a| a.record.funding_txid.is_none())
    {
        info!(
            "Channel {} from LSP {} is open, spending the zero-conf approval for {}",
            opened.funding_txid, opened.id, approval.record.jit_channel_scid
        );
        approval.record.funding_txid = Some(opened.funding_txid);
        save_approval(&mut cln_client, &approval).await?;
    }
    Ok(())
}

/// Gives back the approvals spent on channels that never got going.
///
/// If the connection to the LSP drops before it gets our `funding_signed`,
/// the channel is saved on our side but the LSP will never fund it, and
/// opens a new one for the payer's retry (bLIP-52). On reconnect such a
/// channel is still waiting for `channel_ready`, or already gone.
async fn on_peer_connected(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let lsp_id = some_or_continue!(
        v["peer"]["id"].as_str(),
        "peer_connected without peer id, continue"
    );

    let mut cln_client = ok_or_continue!(p.state().rpc().await);

    let _lock = p.state().approvals.lock().await;
    ok_or_continue!(settle_spent_approvals(&mut cln_client, lsp_id, true).await);
    continue_ok()
}

/// Deletes the LSP's approvals spent on a channel that got going: they
/// can't come back. That includes approvals given back from a channel that
/// got going after all. If the LSP has `reconnected`, gives back the other
/// spent approvals, see `on_peer_connected`. Call it with the approvals
/// lock held.
async fn settle_spent_approvals(
    cln_client: &mut ClnRpc,
    lsp_id: &str,
    reconnected: bool,
) -> Result<(), anyhow::Error> {
    let spent: Vec<Approval> = live_approvals(cln_client, lsp_id, unix_now())
        .await?
        .into_iter()
        .filter(|a| a.record.funding_txid.is_some() || !a.record.given_back_from.is_empty())
        .collect();
    if spent.is_empty() {
        return Ok(());
    }

    let channels = cln_client
        .call_typed(&ListpeerchannelsRequest {
            id: Some(PublicKey::from_str(lsp_id)?),
            channel_id: None,
            short_channel_id: None,
        })
        .await
        .context("failed to list channels of LSP")?
        .channels;

    let state_of = |txid: &str| {
        channels
            .iter()
            .find(|c| c.funding_txid.as_deref() == Some(txid))
            .map(|c| c.state)
    };
    for mut approval in spent {
        match settle(&approval.record, state_of, reconnected) {
            Settle::Delete => {
                debug!(
                    "A channel from LSP {} got going, deleting the zero-conf approval for {}",
                    lsp_id, approval.record.jit_channel_scid
                );
                if let Err(e) = cln_client
                    .call_typed(&DeldatastoreRequest {
                        key: approval.key,
                        generation: None,
                    })
                    .await
                {
                    warn!("Failed to delete spent zero-conf approval: {:#}", e);
                }
            }
            Settle::GiveBack => {
                info!(
                    "Channel {:?} from LSP {} never got going, returning the zero-conf approval for {}",
                    approval.record.funding_txid, lsp_id, approval.record.jit_channel_scid
                );
                let txid = approval.record.funding_txid.take();
                approval.record.given_back_from.extend(txid);
                if let Err(e) = save_approval(cln_client, &approval).await {
                    warn!("Failed to return zero-conf approval: {:#}", e);
                }
            }
            Settle::Keep => {}
        }
    }
    Ok(())
}

/// What `settle_spent_approvals` does with an approval.
#[derive(Debug, PartialEq)]
enum Settle {
    Keep,
    Delete,
    GiveBack,
}

/// Decides what to do with an approval, from the state of the LSP's
/// channels by funding txid: delete it if a channel it was spent on, or
/// given back from, got going; give it back if it is spent and the LSP has
/// `reconnected`; keep it otherwise.
fn settle(
    record: &DatastoreRecord,
    state_of: impl Fn(&str) -> Option<ChannelState>,
    reconnected: bool,
) -> Settle {
    let got_going = record
        .funding_txid
        .iter()
        .chain(&record.given_back_from)
        .any(|txid| !never_got_going(state_of(txid)));
    if got_going {
        Settle::Delete
    } else if reconnected && record.funding_txid.is_some() {
        Settle::GiveBack
    } else {
        Settle::Keep
    }
}

/// Whether the channel an approval was spent on never got going, from its
/// state: still waiting for `channel_ready`, or gone.
fn never_got_going(state: Option<ChannelState>) -> bool {
    state.is_none_or(|s| s == ChannelState::CHANNELD_AWAITING_LOCKIN)
}

/// Datastore key under which the zero-conf approvals for the buys from an
/// LSP are kept, one per `jit_channel_scid`.
fn approvals_key(lsp_id: &str) -> Vec<String> {
    vec!["lsps".to_string(), "client".to_string(), lsp_id.to_string()]
}

fn unix_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or_default()
}

/// A zero-conf approval for one buy, and its datastore key.
#[derive(Debug, Clone, PartialEq)]
struct Approval {
    key: Vec<String>,
    record: DatastoreRecord,
}

/// Splits the datastore entries under an LSP's approvals key into its live
/// approvals, soonest expiry first, and the keys to delete:
/// approvals that expired, and entries we can't read, such as the single
/// record per LSP that older versions kept.
fn sort_approvals(
    entries: Vec<ListdatastoreDatastore>,
    now: u64,
) -> (Vec<Approval>, Vec<Vec<String>>) {
    let mut live = Vec::new();
    let mut stale = Vec::new();
    for entry in entries {
        let record = entry
            .string
            .as_deref()
            .and_then(|s| serde_json::from_str::<DatastoreRecord>(s).ok());
        match record {
            Some(record) if record.expires_at > now => live.push(Approval {
                key: entry.key,
                record,
            }),
            _ => stale.push(entry.key),
        }
    }
    live.sort_by(|a, b| (a.record.expires_at, &a.key).cmp(&(b.record.expires_at, &b.key)));
    (live, stale)
}

/// Returns the live zero-conf approvals for the buys from `lsp_id`, see
/// `sort_approvals`, and deletes the stale ones.
async fn live_approvals(
    cln_client: &mut ClnRpc,
    lsp_id: &str,
    now: u64,
) -> Result<Vec<Approval>, anyhow::Error> {
    let res = cln_client
        .call_typed(&ListdatastoreRequest {
            key: Some(approvals_key(lsp_id)),
        })
        .await
        .context("failed to list zero-conf approvals")?;
    let (live, stale) = sort_approvals(res.datastore, now);
    for key in stale {
        debug!("Deleting stale zero-conf approval {:?}", key);
        if let Err(e) = cln_client
            .call_typed(&DeldatastoreRequest {
                key,
                generation: None,
            })
            .await
        {
            warn!("Failed to delete stale zero-conf approval: {:#}", e);
        }
    }
    Ok(live)
}

async fn save_approval(cln_client: &mut ClnRpc, approval: &Approval) -> Result<(), anyhow::Error> {
    cln_client
        .call_typed(&DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::CREATE_OR_REPLACE),
            string: Some(serde_json::to_string(&approval.record)?),
            key: approval.key.clone(),
        })
        .await
        .context("failed to save zero-conf approval")?;
    Ok(())
}

async fn on_lsps_listprotocols(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    #[derive(Deserialize)]
    struct Request {
        lsp_id: String,
    }
    let mut cln_client = p.state().rpc().await?;

    let req: Request = serde_json::from_value(v).context("Failed to parse request JSON")?;
    let lsp_id = PublicKey::from_str(&req.lsp_id).context("lsp_id is not a valid public key")?;
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

    let client = p.state().client();
    match client.list_protocols(&lsp_id).await?.as_result() {
        Ok(i) => {
            debug!("Received lsps0.list_protocols response: {:?}", i);
            Ok(serde_json::to_value(i)?)
        }
        Err(e) => Ok(serde_json::to_value(e)?),
    }
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
            });
        }
        Some(p) => p,
    };

    let connected = peer.connected;
    let has_lsp_feature = {
        let feature_bits = hex::decode(&peer.features).map_err(|e| {
            anyhow!(
                "Invalid feature bits hex for peer {peer_id}, {}: {e}",
                peer.features
            )
        })?;
        is_feature_bit_set_reversed(&feature_bits, LSP_FEATURE_BIT)
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

pub fn payment_hash(preimage: &[u8]) -> sha256::Hash {
    sha256::Hash::hash(preimage)
}

fn continue_ok() -> Result<serde_json::Value, anyhow::Error> {
    Ok(serde_json::json!({"result": "continue"}))
}

#[macro_export]
macro_rules! some_or_continue {
    ($expr:expr) => {
        match $expr {
            Some(v) => v,
            None => return continue_ok(),
        }
    };
    ($expr:expr, $($log:tt)+) => {
        match $expr {
            Some(v) => v,
            None => {
                debug!($($log)+);
                return continue_ok();
            },
        }
    };
}

#[macro_export]
macro_rules! ok_or_continue {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                debug!("{:#}", e);
                return continue_ok();
            }
        }
    };
    ($expr:expr, $($log:tt)+) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                debug!("{}: {:#}",format_args!($($log)+), e);
                return continue_ok();
            }
        }
    };
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

/// The zero-conf approval for one buy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DatastoreRecord {
    jit_channel_scid: ShortChannelId,
    client_trusts_lsp: bool,
    /// When the invoice of the buy expires, in seconds since the epoch.
    expires_at: u64,
    /// The funding txid of the channel the approval was spent on, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    funding_txid: Option<String>,
    /// The funding txids of the channels the approval was given back from,
    /// see `on_peer_connected`. If one of them gets going after all, the
    /// approval was spent on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    given_back_from: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use lsps_types::{lsps0::Ppm, lsps2::Promise};

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn params(min_payment_size: u64, max_payment_size: u64, promise: &str) -> OpeningFeeParams {
        OpeningFeeParams {
            min_fee_msat: Msat::from_msat(1_000),
            proportional: Ppm::from_ppm(1_000),
            valid_until: (now() + Duration::hours(1)).into(),
            min_lifetime: 144,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat::from_msat(min_payment_size),
            max_payment_size_msat: Msat::from_msat(max_payment_size),
            promise: Promise::try_from(promise).unwrap(),
        }
    }

    #[test]
    fn select_skips_params_with_min_above_max() {
        let menu = vec![params(2_000, 1_000, "inverted"), params(1_000, 2_000, "ok")];
        let selected = select_opening_fee_params(&menu, now()).unwrap();
        assert_eq!(selected.promise.as_str(), "ok");
    }

    #[test]
    fn select_accepts_min_equal_max() {
        let menu = vec![params(1_000, 1_000, "equal")];
        let selected = select_opening_fee_params(&menu, now()).unwrap();
        assert_eq!(selected.promise.as_str(), "equal");
    }

    #[test]
    fn select_fails_if_all_params_have_min_above_max() {
        let menu = vec![params(2_000, 1_000, "a"), params(5_000, 4_999, "b")];
        assert!(select_opening_fee_params(&menu, now()).is_none());
    }

    #[test]
    fn select_skips_params_expiring_within_a_minute() {
        let mut soon = params(1_000, 2_000, "soon");
        soon.valid_until = (now() + Duration::seconds(60)).into();
        let menu = vec![soon, params(1_000, 2_000, "later")];
        let selected = select_opening_fee_params(&menu, now()).unwrap();
        assert_eq!(selected.promise.as_str(), "later");
    }

    fn entry(key: &str, string: Option<&str>) -> ListdatastoreDatastore {
        ListdatastoreDatastore {
            generation: Some(0),
            hex: None,
            string: string.map(str::to_string),
            key: key.split('/').map(str::to_string).collect(),
        }
    }

    fn record(scid: &str, expires_at: u64, funding_txid: Option<&str>) -> String {
        serde_json::to_string(&DatastoreRecord {
            jit_channel_scid: ShortChannelId::from_str(scid).unwrap(),
            client_trusts_lsp: false,
            expires_at,
            funding_txid: funding_txid.map(str::to_string),
            given_back_from: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn sort_approvals_orders_live_ones_by_expiry() {
        let entries = vec![
            entry("lsps/client/lsp/1x2x0", Some(&record("1x2x0", 300, None))),
            entry(
                "lsps/client/lsp/1x1x0",
                Some(&record("1x1x0", 200, Some("ab"))),
            ),
        ];
        let (live, stale) = sort_approvals(entries, 100);
        assert!(stale.is_empty());
        let scids: Vec<String> = live
            .iter()
            .map(|a| a.record.jit_channel_scid.to_string())
            .collect();
        assert_eq!(scids, ["1x1x0", "1x2x0"]);
        assert_eq!(live[0].record.funding_txid.as_deref(), Some("ab"));
    }

    #[test]
    fn sort_approvals_drops_expired_and_unreadable_entries() {
        let entries = vec![
            entry("lsps/client/lsp/1x1x0", Some(&record("1x1x0", 100, None))),
            // The single record per LSP of older versions, without expiry.
            entry(
                "lsps/client/lsp",
                Some(r#"{"jit_channel_scid":"1x1x0","client_trusts_lsp":false}"#),
            ),
            entry("lsps/client/lsp/1x2x0", None),
            entry("lsps/client/lsp/1x3x0", Some(&record("1x3x0", 101, None))),
        ];
        let (live, stale) = sort_approvals(entries, 100);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].record.jit_channel_scid.to_string(), "1x3x0");
        assert_eq!(
            stale,
            [
                vec!["lsps", "client", "lsp", "1x1x0"],
                vec!["lsps", "client", "lsp"],
                vec!["lsps", "client", "lsp", "1x2x0"],
            ]
        );
    }

    #[test]
    fn spent_approvals_come_back_only_from_channels_that_never_got_going() {
        assert!(never_got_going(None));
        assert!(never_got_going(Some(
            ChannelState::CHANNELD_AWAITING_LOCKIN
        )));
        assert!(!never_got_going(Some(ChannelState::CHANNELD_NORMAL)));
        assert!(!never_got_going(Some(ChannelState::ONCHAIN)));
    }

    #[test]
    fn settle_deletes_approvals_whose_channel_got_going() {
        let approval = |funding_txid: Option<&str>, given_back_from: &[&str]| DatastoreRecord {
            jit_channel_scid: ShortChannelId::from_str("1x1x0").unwrap(),
            client_trusts_lsp: false,
            expires_at: 100,
            funding_txid: funding_txid.map(str::to_string),
            given_back_from: given_back_from.iter().map(|s| s.to_string()).collect(),
        };
        // "going" got going, "waiting" waits for channel_ready, others are
        // gone.
        let state_of = |txid: &str| match txid {
            "going" => Some(ChannelState::CHANNELD_NORMAL),
            "waiting" => Some(ChannelState::CHANNELD_AWAITING_LOCKIN),
            _ => None,
        };
        let cases = [
            (approval(Some("going"), &[]), Settle::Delete, Settle::Delete),
            (
                approval(Some("waiting"), &[]),
                Settle::Keep,
                Settle::GiveBack,
            ),
            (approval(Some("gone"), &[]), Settle::Keep, Settle::GiveBack),
            // Given back from a channel that got going after all.
            (approval(None, &["going"]), Settle::Delete, Settle::Delete),
            (approval(None, &["waiting"]), Settle::Keep, Settle::Keep),
            // Spent again after it was given back.
            (
                approval(Some("waiting"), &["going"]),
                Settle::Delete,
                Settle::Delete,
            ),
            (
                approval(Some("going"), &["gone"]),
                Settle::Delete,
                Settle::Delete,
            ),
            (
                approval(Some("gone"), &["waiting"]),
                Settle::Keep,
                Settle::GiveBack,
            ),
        ];
        for (record, paid, reconnected) in cases {
            assert_eq!(settle(&record, state_of, false), paid, "{record:?}");
            assert_eq!(settle(&record, state_of, true), reconnected, "{record:?}");
        }
    }

    #[test]
    fn select_takes_the_first_usable_params() {
        let menu = vec![
            params(1_000, 2_000, "first"),
            params(1_000, 2_000, "second"),
        ];
        let selected = select_opening_fee_params(&menu, now()).unwrap();
        assert_eq!(selected.promise.as_str(), "first");
    }
}
