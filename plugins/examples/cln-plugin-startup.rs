//! This is a test plugin used to verify that we can compile and run
//! plugins using the Rust API against Core Lightning.
#[macro_use]
extern crate serde_json;
use cln_plugin::{messages, options, Builder, Error, Plugin};
use tokio;

const TEST_NOTIF_TAG: &str = "test_custom_notification";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let state = ();

    if let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "test-option",
            options::Value::Integer(42),
            "a test-option with default 42",
        ))
        .option(options::ConfigOption::new(
            "opt-option",
            options::Value::OptInteger,
            "An optional option",
        ))
        .rpcmethod("testmethod", "This is a test", testmethod)
        .rpcmethod(
            "testoptions",
            "Retrieve options from this plugin",
            testoptions,
        )
        .rpcmethod(
            "test-custom-notification",
            "send a test_custom_notification event",
            test_send_custom_notification,
        )
        .subscribe("connect", connect_handler)
        .subscribe("test_custom_notification", test_receive_custom_notification)
        .hook("peer_connected", peer_connected_handler)
        .notification(messages::NotificationTopic::new(TEST_NOTIF_TAG))
        .start(state)
        .await?
    {
        plugin.join().await
    } else {
        Ok(())
    }
}

async fn testoptions(p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    Ok(json!({
        "opt-option": format!("{:?}", p.option("opt-option").unwrap())
    }))
}

async fn testmethod(_p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    Ok(json!("Hello"))
}

async fn test_send_custom_notification(
    p: Plugin<()>,
    _v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let custom_notification = json!({
        "test": "test",
    });
    p.send_custom_notification(TEST_NOTIF_TAG.to_string(), custom_notification)
        .await?;
    Ok(json!("Notification sent"))
}

async fn test_receive_custom_notification(
    _p: Plugin<()>,
    v: serde_json::Value,
) -> Result<(), Error> {
    log::info!("Received a test_custom_notification: {}", v);
    Ok(())
}

async fn connect_handler(_p: Plugin<()>, v: serde_json::Value) -> Result<(), Error> {
    log::info!("Got a connect notification: {}", v);
    Ok(())
}

async fn peer_connected_handler(
    _p: Plugin<()>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    log::info!("Got a connect hook call: {}", v);
    Ok(json!({"result": "continue"}))
}
