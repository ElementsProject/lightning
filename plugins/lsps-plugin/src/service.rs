use anyhow::anyhow;
use async_trait::async_trait;
use cln_lsps::jsonrpc::server::JsonRpcResponseWriter;
use cln_lsps::jsonrpc::TransportError;
use cln_lsps::jsonrpc::{server::JsonRpcServer, JsonRpcRequest};
use cln_lsps::lsps0::handler::Lsps0ListProtocolsHandler;
use cln_lsps::lsps0::model::Lsps0listProtocolsRequest;
use cln_lsps::lsps0::transport::{self, CustomMsg};
use cln_lsps::lsps2::model::{Lsps2BuyRequest, Lsps2GetInfoRequest};
use cln_lsps::util::wrap_payload_with_peer_id;
use cln_lsps::{lsps0, lsps2, util, LSP_FEATURE_BIT};
use cln_plugin::options::ConfigOption;
use cln_plugin::{options, Plugin};
use cln_rpc::notifications::CustomMsgNotification;
use cln_rpc::primitives::PublicKey;
use log::debug;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// An option to enable this service.
const OPTION_ENABLED: options::FlagConfigOption = ConfigOption::new_flag(
    "dev-lsps-service-enabled",
    "Enables an LSPS service on the node.",
);

#[derive(Clone)]
struct State {
    lsps_service: JsonRpcServer,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_ENABLED)
        .option(lsps2::OPTION_ENABLED)
        .option(lsps2::OPTION_PROMISE_SECRET)
        .featurebits(
            cln_plugin::FeatureBitsKind::Node,
            util::feature_bit_to_hex(LSP_FEATURE_BIT),
        )
        .featurebits(
            cln_plugin::FeatureBitsKind::Init,
            util::feature_bit_to_hex(LSP_FEATURE_BIT),
        )
        .hook("custommsg", on_custommsg)
        .configure()
        .await?
    {
        let rpc_path =
            Path::new(&plugin.configuration().lightning_dir).join(&plugin.configuration().rpc_file);

        if !plugin.option(&OPTION_ENABLED)? {
            return plugin
                .disable(&format!("`{}` not enabled", OPTION_ENABLED.name))
                .await;
        }

        let mut lsps_builder = JsonRpcServer::builder().with_handler(
            Lsps0listProtocolsRequest::METHOD.to_string(),
            Arc::new(Lsps0ListProtocolsHandler {
                lsps2_enabled: plugin.option(&lsps2::OPTION_ENABLED)?,
            }),
        );

        if plugin.option(&lsps2::OPTION_ENABLED)? {
            log::debug!("lsps2 enabled");
            let secret_hex = plugin.option(&lsps2::OPTION_PROMISE_SECRET)?;
            if let Some(secret_hex) = secret_hex {
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

                let cln_api_rpc = lsps2::handler::ClnApiRpc::new(rpc_path);
                let getinfo_handler =
                    lsps2::handler::Lsps2GetInfoHandler::new(cln_api_rpc.clone(), secret);
                let buy_handler = lsps2::handler::Lsps2BuyHandler::new(cln_api_rpc, secret);
                lsps_builder = lsps_builder
                    .with_handler(
                        Lsps2GetInfoRequest::METHOD.to_string(),
                        Arc::new(getinfo_handler),
                    )
                    .with_handler(Lsps2BuyRequest::METHOD.to_string(), Arc::new(buy_handler));
            }
        }

        let lsps_service = lsps_builder.build();

        let state = State { lsps_service };
        let plugin = plugin.start(state).await?;
        plugin.join().await
    } else {
        Ok(())
    }
}

async fn on_custommsg(
    p: Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    // All of this could be done async if needed.
    let continue_response = Ok(serde_json::json!({
      "result": "continue"
    }));
    let msg: CustomMsgNotification =
        serde_json::from_value(v).map_err(|e| anyhow!("invalid custommsg: {e}"))?;

    let req = CustomMsg::from_str(&msg.payload).map_err(|e| anyhow!("invalid payload {e}"))?;
    if req.message_type != lsps0::transport::LSPS0_MESSAGE_TYPE {
        // We don't care if this is not for us!
        return continue_response;
    }

    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);
    let mut writer = LspsResponseWriter {
        peer_id: msg.peer_id,
        rpc_path: rpc_path.try_into()?,
    };

    // The payload inside CustomMsg is the actual JSON-RPC
    // request/notification, we wrap it to attach the peer_id as well.
    let payload = wrap_payload_with_peer_id(&req.payload, msg.peer_id);

    let service = p.state().lsps_service.clone();
    match service.handle_message(&payload, &mut writer).await {
        Ok(_) => continue_response,
        Err(e) => {
            debug!("failed to handle lsps message: {}", e);
            continue_response
        }
    }
}

pub struct LspsResponseWriter {
    peer_id: PublicKey,
    rpc_path: PathBuf,
}

#[async_trait]
impl JsonRpcResponseWriter for LspsResponseWriter {
    async fn write(&mut self, payload: &[u8]) -> cln_lsps::jsonrpc::Result<()> {
        let mut client = cln_rpc::ClnRpc::new(&self.rpc_path).await.map_err(|e| {
            cln_lsps::jsonrpc::Error::Transport(TransportError::Other(e.to_string()))
        })?;
        transport::send_custommsg(&mut client, payload.to_vec(), self.peer_id).await
    }
}
