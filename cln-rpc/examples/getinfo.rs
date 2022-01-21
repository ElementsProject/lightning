use anyhow::Context;
use cln_rpc::{model::GetinfoRequest, ClnRpc, Request};
use log::info;
use std::env::args;
use std::path::Path;
use tokio;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let rpc_path = args().nth(1).context("missing argument: socket path")?;
    let p = Path::new(&rpc_path);

    let mut rpc = ClnRpc::new(p).await?;
    let response = rpc.call(Request::Getinfo(GetinfoRequest {})).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
