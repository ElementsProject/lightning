use anyhow::Error;
use cln_plugin::{Builder, Plugin};
use serde_json::json;
use tokio::sync::broadcast;

#[derive(Clone)]
struct State {
    tx: broadcast::Sender<bool>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (tx, _) = broadcast::channel(4);
    let state = State { tx };

    if let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .hook("htlc_accepted", htlc_accepted_handler)
        .rpcmethod("release", "Release all HTLCs we currently hold", release)
        .rpcmethod("fail", "Fail all HTLCs we currently hold", fail)
        .start(state)
        .await?
    {
        plugin.join().await?;
        Ok(())
    } else {
        Ok(())
    }
}

/// Release all waiting HTLCs
async fn release(p: Plugin<State>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    p.state().tx.send(true).unwrap();
    Ok(json!("Released!"))
}

/// Fail all waiting HTLCs
async fn fail(p: Plugin<State>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    p.state().tx.send(false).unwrap();
    Ok(json!("Failed!"))
}

async fn htlc_accepted_handler(
    p: Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    log::info!("Holding on to incoming HTLC {:?}", v);
    // Wait for `release` to be called.
    if p.state().tx.subscribe().recv().await.unwrap() {
        Ok(json!({"result": "continue"}))
    } else {
        Ok(json!({"result": "fail"}))
    }
}
