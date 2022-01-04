use anyhow::Context;
use cln_rpc::{requests::Getinfo, ClnRpc, Request};
use log::info;
use std::env::args;
use std::path::Path;
use tokio;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Hello world");
    let rpc_path = args().nth(1).context("missing argument: socket path")?;
    let p = Path::new(&rpc_path);

    let mut rpc = ClnRpc::new(p).await?;
    let response = rpc.call(Request::Getinfo(Getinfo {})).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
