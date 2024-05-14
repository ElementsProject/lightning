//! This is a test plugin used to verify that we can compile and run
//! plugins using the Rust API against Core Lightning.
#[macro_use]
extern crate serde_json;
use cln_plugin::options::{
    self, BooleanConfigOption, DefaultIntegerConfigOption, IntegerConfigOption,
};
use cln_plugin::{messages, Builder, Error, Plugin};
use tokio;

const TEST_NOTIF_TAG: &str = "test_custom_notification";

const TEST_OPTION: DefaultIntegerConfigOption = DefaultIntegerConfigOption::new_i64_with_default(
    "test-option",
    42,
    "a test-option with default 42",
);

const TEST_OPTION_NO_DEFAULT: IntegerConfigOption =
    IntegerConfigOption::new_i64_no_default("opt-option", "An option without a default");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let state = ();

    let test_dynamic_option: BooleanConfigOption = BooleanConfigOption::new_bool_no_default(
        "test-dynamic-option",
        "A option that can be changed dynamically",
    )
    .dynamic();

    if let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(TEST_OPTION)
        .option(TEST_OPTION_NO_DEFAULT)
        .option(test_dynamic_option)
        .setconfig_callback(setconfig_callback)
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

async fn setconfig_callback(
    plugin: Plugin<()>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let name = args.get("config").unwrap().as_str().unwrap();
    let value = args.get("val").unwrap();

    let opt_value = options::Value::String(value.to_string());

    plugin.set_option_str(name, opt_value)?;
    log::info!(
        "cln-plugin-startup: Got dynamic option change: {} {}",
        name,
        plugin.option_str(name).unwrap().unwrap().as_str().unwrap()
    );
    Ok(json!({}))
}

async fn testoptions(p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    let test_option = p.option(&TEST_OPTION)?;
    let test_option_no_default = p.option(&TEST_OPTION_NO_DEFAULT)?;

    Ok(json!({
        "test-option": test_option,
        "opt-option" : test_option_no_default
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
