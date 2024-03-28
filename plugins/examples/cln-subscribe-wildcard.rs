/// This plug-in subscribes to the wildcard-notifications
/// and creates a corresponding log-entry

use anyhow::Result;
use cln_plugin::{Builder, Plugin};

#[tokio::main]
async fn main() -> Result<()> {
    let state = ();

    let configured = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .subscribe("*", handle_wildcard_notification)
        .start(state)
        .await?;

    match configured {
	Some(p) => p.join().await?,
	None => return Ok(()) // cln was started with --help
    };

    Ok(())
}

async fn handle_wildcard_notification(_plugin: Plugin<()>, value : serde_json::Value) -> Result<()> {
    let notification_type : String = value
	.as_object()
	.unwrap()
	.keys()
	.next()
	.unwrap()
	.into();

    log::info!("Received notification {}", notification_type);
    Ok(())
}
