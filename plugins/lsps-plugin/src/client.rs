use cln_lsps::jsonrpc::client::JsonRpcClient;
use cln_lsps::lsps0::{
    self,
    transport::{Bolt8Transport, CustomMessageHookManager, WithCustomMessageHookManager},
};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone)]
struct State {
    hook_manager: CustomMessageHookManager,
}

impl WithCustomMessageHookManager for State {
    fn get_custommsg_hook_manager(&self) -> &CustomMessageHookManager {
        &self.hook_manager
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let hook_manager = CustomMessageHookManager::new();
    let state = State { hook_manager };

    if let Some(plugin) = cln_plugin::Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .hook("custommsg", CustomMessageHookManager::on_custommsg::<State>)
        .rpcmethod(
            "lsps-listprotocols",
            "list protocols supported by lsp",
            on_lsps_listprotocols,
        )
        .start(state)
        .await?
    {
        plugin.join().await
    } else {
        Ok(())
    }
}

async fn on_lsps_listprotocols(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    #[derive(Deserialize)]
    struct Request {
        peer: String,
    }
    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);

    let req: Request = serde_json::from_value(v).unwrap();

    let client = JsonRpcClient::new(Bolt8Transport::new(
        &req.peer,
        rpc_path,
        p.state().hook_manager.clone(),
        None,
    )?);
    let res: lsps0::model::Lsps0listProtocolsResponse = client
        .call_typed(lsps0::model::Lsps0listProtocolsRequest {})
        .await?;
    Ok(serde_json::to_value(res)?)
}
