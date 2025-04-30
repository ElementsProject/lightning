use anyhow::anyhow;
use async_trait::async_trait;
use cln_lsps::jsonrpc::server::{JsonRpcResponseWriter, RequestHandler};
use cln_lsps::jsonrpc::{server::JsonRpcServer, JsonRpcRequest};
use cln_lsps::jsonrpc::{JsonRpcResponse, RequestObject, RpcError, TransportError};
use cln_lsps::lsps0;
use cln_lsps::lsps0::model::{Lsps0listProtocolsRequest, Lsps0listProtocolsResponse};
use cln_lsps::lsps0::transport::{self, CustomMsg};
use cln_plugin::options::ConfigOption;
use cln_plugin::{options, Plugin};
use cln_rpc::notifications::CustomMsgNotification;
use cln_rpc::primitives::PublicKey;
use log::debug;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// An option to enable this service. It defaults to `false` as we don't want a
/// node to be an LSP per default.
/// If a user want's to run an LSP service on their node this has to explicitly
/// set to true. We keep this as a dev option for now until it actually does
/// something.
const OPTION_ENABLED: options::DefaultBooleanConfigOption = ConfigOption::new_bool_with_default(
    "dev-lsps-service",
    false,
    "Enables an LSPS service on the node.",
);

#[derive(Clone)]
struct State {
    lsps_service: JsonRpcServer,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let lsps_service = JsonRpcServer::builder()
        .with_handler(
            Lsps0listProtocolsRequest::METHOD.to_string(),
            Arc::new(Lsps0ListProtocolsHandler),
        )
        .build();
    let state = State { lsps_service };

    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_ENABLED)
        .hook("custommsg", on_custommsg)
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

    let service = p.state().lsps_service.clone();
    match service.handle_message(&req.payload, &mut writer).await {
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

pub struct Lsps0ListProtocolsHandler;

#[async_trait]
impl RequestHandler for Lsps0ListProtocolsHandler {
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
        let req: RequestObject<Lsps0listProtocolsRequest> =
            serde_json::from_slice(payload).unwrap();
        if let Some(id) = req.id {
            let res = Lsps0listProtocolsResponse { protocols: vec![] }.into_response(id);
            let res_vec = serde_json::to_vec(&res).unwrap();
            return Ok(res_vec);
        }
        Ok(vec![])
    }
}
