use anyhow::bail;
use cln_lsps::{
    cln_adapters::{hooks::service_custommsg_hook, sender::ClnSender, state::ServiceState},
    core::{
        lsps2::handler::{ClnApiRpc, HtlcAcceptedHookHandler, Lsps2ServiceHandler},
        server::LspsService,
    },
    lsps2::{
        self,
        cln::{HtlcAcceptedRequest, HtlcAcceptedResponse},
    },
};
use cln_plugin::Plugin;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
        .option(lsps2::OPTION_ENABLED)
        .option(lsps2::OPTION_PROMISE_SECRET)
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

        if plugin.option(&lsps2::OPTION_ENABLED)? {
            log::debug!("lsps2-service enabled");
            if let Some(secret_hex) = plugin.option(&lsps2::OPTION_PROMISE_SECRET)? {
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
                .disable(&format!("`{}` not enabled", &lsps2::OPTION_ENABLED.name))
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
    if !p.state().lsps2_enabled {
        // just continue.
        // Fixme: Add forward and extra tlvs from incoming.
        let res = serde_json::to_value(&HtlcAcceptedResponse::continue_(None, None, None))?;
        return Ok(res);
    }

    let req: HtlcAcceptedRequest = serde_json::from_value(v)?;
    let rpc_path = Path::new(&p.configuration().lightning_dir).join(&p.configuration().rpc_file);
    let api = ClnApiRpc::new(rpc_path);
    // Fixme: Use real htlc_minimum_amount.
    let handler = HtlcAcceptedHookHandler::new(api, 1000);
    let res = handler.handle(req).await?;
    let res_val = serde_json::to_value(&res)?;
    Ok(res_val)
}
