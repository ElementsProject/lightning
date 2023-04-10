use anyhow::Error;
use cln_plugin::{Builder, Plugin};
use serde_json::json;
use tokio::sync::broadcast;

#[derive(Clone)]
struct State {
    tx: broadcast::Sender<()>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (tx, _) = broadcast::channel(4);
    let state = State { tx };

    if let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .hook("htlc_accepted", htlc_accepted_handler)
        .rpcmethod("release", "Release all HTLCs we currently hold", release)
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
    p.state().tx.send(()).unwrap();
    Ok(json!("Released!"))
}

async fn htlc_accepted_handler(
    p: Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    log::info!("Holding on to incoming HTLC {:?}", v);
    // Wait for `release` to be called.
    p.state().tx.subscribe().recv().await.unwrap();

    Ok(json!({"result": "continue"}))
}
