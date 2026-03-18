use anyhow::bail;
use bitcoin::hashes::Hash;
use chrono::Utc;
use cln_lsps::{
    cln_adapters::{
        hooks::service_custommsg_hook,
        rpc::{ClnActionExecutor, ClnBlockheight, ClnDatastore, ClnPolicyProvider, ClnRecoveryProvider, ClnRpcClient},
        sender::ClnSender, state::ServiceState,
        types::HtlcAcceptedRequest,
    },
    core::{
        lsps2::{
            actor::HtlcResponse,
            event_sink::NoopEventSink,
            manager::{PaymentHash, SessionConfig, SessionManager},
            provider::{DatastoreProvider, RecoveryProvider},
            session::PaymentPart,
            service::Lsps2ServiceHandler,
        },
        server::LspsService,
        tlv::{TlvStream, TLV_FORWARD_AMT},
    },
    proto::{
        lsps0::{Msat, ShortChannelId},
        lsps2::{failure_codes::UNKNOWN_NEXT_PEER, SessionOutcome},
    },
};
use cln_plugin::{options, Plugin};
use log::{debug, error, trace, warn};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const OPTION_ENABLED: options::FlagConfigOption = options::ConfigOption::new_flag(
    "experimental-lsps2-service",
    "Enables lsps2 for the LSP service",
);

pub const OPTION_PROMISE_SECRET: options::StringConfigOption =
    options::ConfigOption::new_str_no_default(
        "experimental-lsps2-promise-secret",
        "A 64-character hex string that is the secret for promises",
    );

pub const OPTION_COLLECT_TIMEOUT: options::DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "experimental-lsps2-collect-timeout",
        90,
        "Timeout in seconds for collecting MPP parts (default: 90)",
    );

#[derive(Clone)]
struct State {
    lsps_service: Arc<LspsService>,
    sender: ClnSender,
    lsps2_enabled: bool,
    datastore: Arc<ClnDatastore>,
    recovery: Arc<ClnRecoveryProvider>,
    session_manager: Arc<SessionManager<ClnDatastore, ClnActionExecutor>>,
}

impl State {
    pub fn new(rpc_path: PathBuf, promise_secret: &[u8; 32], collect_timeout_secs: u64) -> Self {
        let rpc = ClnRpcClient::new(rpc_path.clone());
        let sender = ClnSender::new(rpc_path);
        let datastore = Arc::new(ClnDatastore::new(rpc.clone()));
        let blockheight = Arc::new(ClnBlockheight::new(rpc.clone()));
        let policy = Arc::new(ClnPolicyProvider::new(rpc.clone()));
        let executor = Arc::new(ClnActionExecutor::new(rpc.clone()));
        let recovery = Arc::new(ClnRecoveryProvider::new(rpc));
        let lsps2_handler = Arc::new(Lsps2ServiceHandler::new(datastore.clone(), blockheight, policy, promise_secret));
        let lsps_service = Arc::new(LspsService::builder().with_protocol(lsps2_handler).build());
        let session_manager = Arc::new(SessionManager::new(
            datastore.clone(),
            executor,
            SessionConfig {
                collect_timeout_secs,
                ..SessionConfig::default()
            },
            Arc::new(NoopEventSink),
        ));
        Self {
            lsps_service,
            sender,
            lsps2_enabled: true,
            datastore,
            recovery,
            session_manager,
        }
    }
}

impl ServiceState for State {
    fn service(&self) -> Arc<LspsService> {
        self.lsps_service.clone()
    }

    fn sender(&self) -> cln_lsps::cln_adapters::sender::ClnSender {
        self.sender.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_ENABLED)
        .option(OPTION_PROMISE_SECRET)
        .option(OPTION_COLLECT_TIMEOUT)
        // FIXME: Temporarily disabled lsp feature to please test cases, this is
        // ok as the feature is optional per spec.
        // We need to ensure that `connectd` only starts after all plugins have
        // been initialized.
        // .featurebits(
        //     cln_plugin::FeatureBitsKind::Node,
        //     util::feature_bit_to_hex(LSP_FEATURE_BIT),
        // )
        // .featurebits(
        //     cln_plugin::FeatureBitsKind::Init,
        //     util::feature_bit_to_hex(LSP_FEATURE_BIT),
        // )
        .hook("custommsg", service_custommsg_hook)
        .hook("htlc_accepted", on_htlc_accepted)
        .subscribe("forward_event", on_forward_event)
        .subscribe("block_added", on_block_added)
        .configure()
        .await?
    {
        let rpc_path =
            Path::new(&plugin.configuration().lightning_dir).join(&plugin.configuration().rpc_file);

        if plugin.option(&OPTION_ENABLED)? {
            log::debug!("lsps2-service enabled");
            if let Some(secret_hex) = plugin.option(&OPTION_PROMISE_SECRET)? {
                let secret_hex = secret_hex.trim().to_lowercase();

                let decoded_bytes = match hex::decode(&secret_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return plugin
                            .disable(&format!(
                                "Invalid hex string for promise secret: {}",
                                secret_hex
                            ))
                            .await;
                    }
                };

                let secret: [u8; 32] = match decoded_bytes.try_into() {
                    Ok(array) => array,
                    Err(vec) => {
                        return plugin
                            .disable(&format!(
                                "Promise secret must be exactly 32 bytes, got {}",
                                vec.len()
                            ))
                            .await;
                    }
                };

                let collect_timeout_secs = plugin.option(&OPTION_COLLECT_TIMEOUT)? as u64;
                let state = State::new(rpc_path, &secret, collect_timeout_secs);

                // Recover in-flight sessions before processing replayed HTLCs
                let recovery: Arc<dyn RecoveryProvider> = state.recovery.clone();
                if let Err(e) = state.session_manager.recover(recovery).await {
                    warn!("session recovery failed: {e}");
                }

                let plugin = plugin.start(state).await?;
                plugin.join().await
            } else {
                bail!("lsps2 enabled but no promise-secret set.");
            }
        } else {
            return plugin
                .disable(&format!("`{}` not enabled", &OPTION_ENABLED.name))
                .await;
        }
    } else {
        Ok(())
    }
}

async fn on_htlc_accepted(
    p: Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    Ok(handle_htlc_safe(&p, v).await)
}

async fn handle_htlc_safe(p: &Plugin<State>, v: serde_json::Value) -> serde_json::Value {
    match handle_htlc_inner(p, v).await {
        Ok(response) => response,
        Err(e) => {
            error!("HTLC hook error (continuing): {:#}", e);
            json_continue()
        }
    }
}

async fn handle_htlc_inner(
    p: &Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    if !p.state().lsps2_enabled {
        return Ok(json_continue());
    }

    let req: HtlcAcceptedRequest = serde_json::from_value(v)?;

    let short_channel_id: ShortChannelId = match req.onion.short_channel_id {
        Some(scid) => scid.into(),
        None => {
            trace!("We are the destination of the HTLC, continue.");
            return Ok(json_continue());
        }
    };

    // Decide path: look up buy request to check for MPP.
    let ds_rec = match p.state().datastore.get_buy_request(&short_channel_id).await {
        Ok(rec) => rec,
        Err(_) => {
            trace!("SCID not ours, continue.");
            return Ok(json_continue());
        }
    };

    if Utc::now() >= ds_rec.opening_fee_params.valid_until {
        let _ = p
            .state()
            .datastore
            .finalize_session(&short_channel_id, SessionOutcome::Timeout)
            .await;
        return Ok(json_fail(UNKNOWN_NEXT_PEER));
    }

    handle_session_htlc(p, &req, short_channel_id).await
}

async fn handle_session_htlc(
    p: &Plugin<State>,
    req: &HtlcAcceptedRequest,
    scid: ShortChannelId,
) -> Result<serde_json::Value, anyhow::Error> {
    let payment_hash =
        PaymentHash::from_byte_array(req.htlc.payment_hash.as_slice().try_into()?);
    let part = PaymentPart {
        htlc_id: req.htlc.id,
        amount_msat: Msat::from_msat(req.htlc.amount_msat.msat()),
        cltv_expiry: req.htlc.cltv_expiry,
    };
    match p
        .state()
        .session_manager
        .on_part(payment_hash, scid, part)
        .await
    {
        Ok(resp) => session_response_to_json(
            resp,
            &req.onion.payload,
            req.htlc.amount_msat.msat(),
            &req.htlc.extra_tlvs,
        ),
        Err(e) => {
            debug!("session manager error: {e:#}");
            Ok(json_continue())
        }
    }
}

fn session_response_to_json(
    resp: HtlcResponse,
    payload: &TlvStream,
    _htlc_amount_msat: u64,
    extra_tlvs: &Option<TlvStream>,
) -> Result<serde_json::Value, anyhow::Error> {
    match resp {
        HtlcResponse::Forward {
            channel_id,
            fee_msat,
            forward_msat,
        } => {
            let mut payload = payload.clone();
            payload.set_tu64(TLV_FORWARD_AMT, forward_msat);

            let mut extra_tlvs = extra_tlvs.clone().unwrap_or_default();
            extra_tlvs.set_u64(65537, fee_msat);

            let forward_to = hex::decode(&channel_id)?;

            Ok(json_continue_forward(
                payload.to_bytes()?,
                forward_to,
                extra_tlvs.to_bytes()?,
            ))
        }
        HtlcResponse::Fail { failure_code } => Ok(json_fail(failure_code)),
        HtlcResponse::Continue => Ok(json_continue()),
    }
}

async fn on_forward_event(
    p: Plugin<State>,
    v: serde_json::Value,
) -> Result<(), anyhow::Error> {
    let event = match v.get("forward_event") {
        Some(e) => e,
        None => return Ok(()),
    };

    let status = event.get("status").and_then(|s| s.as_str());

    let payment_hash = match status {
        Some("settled") | Some("failed") | Some("local_failed") => {
            let hash_hex = match event.get("payment_hash").and_then(|s| s.as_str()) {
                Some(h) => h,
                None => return Ok(()),
            };
            let bytes: [u8; 32] = hex::decode(hash_hex)?
                .try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("bad payment_hash len {}", v.len()))?;
            PaymentHash::from_byte_array(bytes)
        }
        _ => return Ok(()),
    };

    let updated_index = event.get("updated_index").and_then(|v| v.as_u64());

    match status {
        Some("settled") => {
            let preimage = event
                .get("preimage")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            if let Err(e) = p
                .state()
                .session_manager
                .on_payment_settled(payment_hash, preimage, updated_index)
                .await
            {
                debug!("on_payment_settled error: {e:#}");
            }
        }
        Some("failed") | Some("local_failed") => {
            if let Err(e) = p
                .state()
                .session_manager
                .on_payment_failed(payment_hash, updated_index)
                .await
            {
                debug!("on_payment_failed error: {e:#}");
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

async fn on_block_added(
    p: Plugin<State>,
    v: serde_json::Value,
) -> Result<(), anyhow::Error> {
    let height = match v
        .get("block_added")
        .and_then(|b| b.get("height"))
        .and_then(|h| h.as_u64())
    {
        Some(h) => h as u32,
        None => return Ok(()),
    };

    p.state().session_manager.on_new_block(height).await;
    Ok(())
}

fn json_continue() -> serde_json::Value {
    serde_json::json!({"result": "continue"})
}

fn json_continue_forward(
    payload: Vec<u8>,
    forward_to: Vec<u8>,
    extra_tlvs: Vec<u8>,
) -> serde_json::Value {
    serde_json::json!({
        "result": "continue",
        "payload": hex::encode(payload),
        "forward_to": hex::encode(forward_to),
        "extra_tlvs": hex::encode(extra_tlvs)
    })
}

fn json_fail(failure_code: &str) -> serde_json::Value {
    serde_json::json!({
        "result": "fail",
        "failure_message": failure_code
    })
}

