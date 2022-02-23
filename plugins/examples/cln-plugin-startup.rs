//! This is a test plugin used to verify that we can compile and run
//! plugins using the Rust API against c-lightning.
#[macro_use]
extern crate serde_json;
use cln_plugin::{options, Builder, Error, Plugin};
use std::pin::Pin;
use tokio;
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let plugin = Builder::new((), tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "test-option",
            options::Value::Integer(42),
            "a test-option with default 42",
        ))
        .rpcmethod("testmethod", "This is a test", Box::new(testmethod))
        .subscribe("connect", Box::new(connect_handler))
        .hook("peer_connected", Box::new(peer_connected_handler))
        .start()
        .await?;
    plugin.join().await
}

fn testmethod(_p: Plugin<()>, _v: &serde_json::Value) -> Result<serde_json::Value, Error> {
    Ok(json!("Hello"))
}

fn connect_handler(_p: Plugin<()>, v: &serde_json::Value) -> Result<(), Error> {
    log::info!("Got a connect notification: {}", v);
    Ok(())
}

fn peer_connected_handler(_p: Plugin<()>, v: &serde_json::Value) -> Result<serde_json::Value, Error> {
    log::info!("Got a connect hook call: {}", v);
    Ok(json!({"result": "continue"}))
}
