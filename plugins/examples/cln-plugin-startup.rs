//! This is a test plugin used to verify that we can compile and run
//! plugins using the Rust API against c-lightning.

use cln_plugin::{options, Builder};
use tokio;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let (plugin, stdin) = Builder::new((), tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "test-option",
            options::Value::Integer(42),
            "a test-option with default 42",
        ))
        .build();

    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        log::info!("Hello world");
    });
    plugin.run(stdin).await
}
