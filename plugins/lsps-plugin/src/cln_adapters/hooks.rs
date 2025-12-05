use crate::cln_adapters::{
    state::ClientState,
    utils::{decode_lsps0_frame_hex, extract_message_id},
};
use cln_plugin::Plugin;
use serde_json::Value;

/// Client hook - thin wrapper
pub async fn client_custommsg_hook<S>(plugin: Plugin<S>, v: Value) -> Result<Value, anyhow::Error>
where
    S: Clone + Sync + Send + 'static + ClientState,
{
    let payload_hex = v["payload"].as_str().unwrap();

    // LSPS0 Bolt8 transport frame needs to be decoded.
    let payload = match decode_lsps0_frame_hex(payload_hex) {
        Some(p) => p,
        None => {
            return Ok(serde_json::json!({
              "result": "continue"
            }))
        }
    };

    if let Some(id) = extract_message_id(&payload) {
        plugin.state().pending().complete(&id, payload).await;
    }

    return Ok(serde_json::json!({
      "result": "continue"
    }));
}
