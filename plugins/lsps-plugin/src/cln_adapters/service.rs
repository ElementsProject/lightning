use crate::{
    core::{router::RequestContext, server::LspsService},
    proto::lsps0::{decode_frame, encode_frame},
};
use anyhow::Result;
use bitcoin::secp256k1::PublicKey;
use cln_plugin::Plugin;
use cln_rpc::model::requests::SendcustommsgRequest;
use serde::Deserialize;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub trait ServiceStore {
    fn service(&self) -> Arc<LspsService>;
}

#[derive(Debug, Clone, Deserialize)]
struct CustomMsg {
    peer_id: PublicKey,
    payload: String,
}

fn rpc_path<S>(p: &Plugin<S>) -> PathBuf
where
    S: Clone + Sync + Send + 'static,
{
    let dir = p.configuration().lightning_dir;
    Path::new(&dir).join(&p.configuration().rpc_file)
}

async fn send_custommsg<P>(rpc_path: P, peer: &PublicKey, msg: &str) -> Result<()>
where
    P: AsRef<Path>,
{
    let mut client = cln_rpc::ClnRpc::new(rpc_path).await?;
    let _ = client
        .call_typed(&SendcustommsgRequest {
            msg: msg.to_owned(),
            node_id: peer.to_owned(),
        })
        .await?;
    Ok(())
}

pub async fn on_custommsg_service<S>(plugin: Plugin<S>, v: Value) -> Result<Value>
where
    S: Clone + Sync + Send + 'static + ServiceStore,
{
    let msg: CustomMsg = serde_json::from_value(v)?;
    let req = match decode_lsps0_frame_hex(&msg.payload) {
        Some(d) => d,
        None => {
            return Ok(serde_json::json!({
              "result": "continue"
            }))
        }
    };
    let service = plugin.state().service();
    let rpc_path = rpc_path(&plugin);
    let ctx = RequestContext {
        peer_id: msg.peer_id,
    };
    let res = service.handle(&ctx, &req).await;
    if let Some(payload) = res {
        let payload = encode_lsps0_frame_hex(&payload);
        if let Err(e) = send_custommsg(&rpc_path, &msg.peer_id, &payload).await {
            log::error!("Failed to send LSPS response to {}: {}", &msg.peer_id, e);
        };
    }

    Ok(serde_json::json!({
      "result": "continue"
    }))
}

fn decode_lsps0_frame_hex(hex_str: &str) -> Option<Vec<u8>> {
    let frame = match hex::decode(hex_str) {
        Ok(f) => f,
        Err(e) => {
            log::error!(
                "Failed to decode hex string payload from custom message: {}",
                e
            );
            return None;
        }
    };
    decode_frame(&frame).ok().map(|d| d.to_owned())
}

fn encode_lsps0_frame_hex(payload: &[u8]) -> String {
    let frame = encode_frame(payload);
    hex::encode(&frame)
}
