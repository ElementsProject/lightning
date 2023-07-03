use anyhow::{anyhow, Context};
use cln_rpc::{model::requests::GetinfoRequest, ClnRpc, Request};
use std::env::args;
use std::path::Path;
use tokio;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // initialize the log inside the library
    env_logger::init();

    let rpc_path = args().nth(1).context("missing argument: socket path")?;
    let p = Path::new(&rpc_path);

    let mut rpc = ClnRpc::new(p).await?;
    let response = rpc
        .call(Request::Getinfo(GetinfoRequest {}))
        .await
        .map_err(|e| anyhow!("Error calling getinfo: {:?}", e))?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
