use crate::{
    cln_adapters::state::{ClientState, ServiceState},
    core::{router::RequestContext, transport::MessageSender as _},
    proto::lsps0,
};
use anyhow::Result;
use bitcoin::secp256k1::PublicKey;
use cln_plugin::Plugin;
use serde::Deserialize;
use serde_json::Value;

pub async fn client_custommsg_hook<S>(plugin: Plugin<S>, v: Value) -> Result<Value>
where
    S: Clone + Sync + Send + 'static + ClientState,
{
    let Some(hook) = CustomMsgHook::parse(v) else {
        return Ok(serde_json::json!({
          "result": "continue"
        }));
    };

    if let Some(id) = extract_message_id(&hook.payload) {
        plugin.state().pending().complete(&id, hook.payload).await;
    }

    return Ok(serde_json::json!({
      "result": "continue"
    }));
}

pub async fn service_custommsg_hook<S>(plugin: Plugin<S>, v: Value) -> Result<Value>
where
    S: Clone + Sync + Send + 'static + ServiceState,
{
    let Some(hook) = CustomMsgHook::parse(v) else {
        return Ok(serde_json::json!({
          "result": "continue"
        }));
    };
    let service = plugin.state().service();
    let ctx = RequestContext {
        peer_id: hook.peer_id,
    };
    let res = service.handle(&ctx, &hook.payload).await;
    if let Some(payload) = res {
        let sender = plugin.state().sender().clone();
        if let Err(e) = sender.send(&hook.peer_id, &payload).await {
            log::error!("Failed to send LSPS response to {}: {}", &hook.peer_id, e);
        };
    }

    Ok(serde_json::json!({
      "result": "continue"
    }))
}

#[derive(Debug, Deserialize)]
struct CustomMsgHookRaw {
    peer_id: PublicKey,
    payload: String,
}

/// Parsed and validated hook data
pub struct CustomMsgHook {
    pub peer_id: PublicKey,
    pub payload: Vec<u8>,
}

impl CustomMsgHook {
    /// Parse and validate everything upfront
    pub fn parse(v: Value) -> Option<Self> {
        let raw: CustomMsgHookRaw = serde_json::from_value(v).ok()?;
        let peer_id = raw.peer_id;
        let payload = decode_lsps0_frame_hex(&raw.payload)?;
        Some(Self { peer_id, payload })
    }
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
    lsps0::decode_frame(&frame).ok().map(|d| d.to_owned())
}

fn extract_message_id(payload: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct IdOnly {
        id: Option<String>,
    }

    let parsed: IdOnly = serde_json::from_slice(payload).ok()?;
    parsed.id
}
