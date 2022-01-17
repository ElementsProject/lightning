//! This is a test plugin used to verify that we can compile and run
//! plugins using the Rust API against c-lightning.

use cln_plugin::Builder;
use tokio;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let (plugin, stdin) = Builder::new((), tokio::io::stdin(), tokio::io::stdout()).build();
    plugin.run(stdin).await;
    Ok(())
}
