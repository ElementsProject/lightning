use anyhow::bail;
use bitcoin::hashes::Hash;
use cln_lsps::{
    cln_adapters::{
        hooks::service_custommsg_hook, rpc::ClnApiRpc, sender::ClnSender, state::ServiceState,
        types::HtlcAcceptedRequest,
    },
    core::{
        lsps2::{
            htlc::{Htlc, HtlcAcceptedHookHandler, HtlcDecision, Onion, RejectReason},
            service::Lsps2ServiceHandler,
        },
        server::LspsService,
    },
    proto::lsps0::Msat,
};
use cln_plugin::{options, Plugin};
use log::{debug, error, trace};
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

#[derive(Clone)]
struct State {
    lsps_service: Arc<LspsService>,
    sender: ClnSender,
    lsps2_enabled: bool,
}

impl State {
    pub fn new(rpc_path: PathBuf, promise_secret: &[u8; 32]) -> Self {
        let api = Arc::new(ClnApiRpc::new(rpc_path.clone()));
        let sender = ClnSender::new(rpc_path);
        let lsps2_handler = Arc::new(Lsps2ServiceHandler::new(api, promise_secret));
        let lsps_service = Arc::new(LspsService::builder().with_protocol(lsps2_handler).build());
        Self {
            lsps_service,
            sender,
            lsps2_enabled: true,
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

                let state = State::new(rpc_path, &secret);
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

    let short_channel_id = match req.onion.short_channel_id {
        Some(scid) => scid,
        None => {
            trace!("We are the destination of the HTLC, continue.");
            return Ok(json_continue());
        }
    };

    let rpc_path = Path::new(&p.configuration().lightning_dir).join(&p.configuration().rpc_file);
    let api = ClnApiRpc::new(rpc_path);
    // Fixme: Use real htlc_minimum_amount.
    let handler = HtlcAcceptedHookHandler::new(api, 1000);

    let onion = Onion {
        short_channel_id,
        payload: req.onion.payload,
    };

    let htlc = Htlc {
        amount_msat: Msat::from_msat(req.htlc.amount_msat.msat()),
        extra_tlvs: req.htlc.extra_tlvs.unwrap_or_default(),
    };

    debug!("Handle potential jit-session HTLC.");
    let response = match handler.handle(&htlc, &onion).await {
        Ok(dec) => {
            log_decision(&dec);
            decision_to_response(dec)?
        }
        Err(e) => {
            // Fixme: Should we log **BROKEN** here?
            debug!("Htlc handler failed (continuing): {:#}", e);
            return Ok(json_continue());
        }
    };

    Ok(serde_json::to_value(&response)?)
}

fn decision_to_response(decision: HtlcDecision) -> Result<serde_json::Value, anyhow::Error> {
    Ok(match decision {
        HtlcDecision::NotOurs => json_continue(),

        HtlcDecision::Forward {
            mut payload,
            forward_to,
            mut extra_tlvs,
        } => json_continue_forward(
            payload.to_bytes()?,
            forward_to.as_byte_array().to_vec(),
            extra_tlvs.to_bytes()?,
        ),

        // Fixme: once we implement MPP-Support we need to remove this.
        HtlcDecision::Reject {
            reason: RejectReason::MppNotSupported,
        } => json_continue(),
        HtlcDecision::Reject { reason } => json_fail(reason.failure_code()),
    })
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

fn log_decision(decision: &HtlcDecision) {
    match decision {
        HtlcDecision::NotOurs => {
            trace!("SCID not ours, continue");
        }
        HtlcDecision::Forward { forward_to, .. } => {
            debug!(
                "Forwarding via JIT channel {}",
                hex::encode(forward_to.as_byte_array())
            );
        }
        HtlcDecision::Reject { reason } => {
            debug!("Rejecting HTLC: {:?}", reason);
        }
    }
}
