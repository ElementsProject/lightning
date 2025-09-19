use anyhow::Context;
use cln_lsps::jsonrpc::client::JsonRpcClient;
use cln_lsps::lsps0::{
    self,
    transport::{Bolt8Transport, CustomMessageHookManager, WithCustomMessageHookManager},
};
use cln_plugin::options;
use log::debug;
use serde::Deserialize;
use std::path::Path;

/// An option to enable this service.
const OPTION_ENABLED: options::FlagConfigOption = options::ConfigOption::new_flag(
    "dev-lsps-client-enabled",
    "Enables an LSPS client on the node.",
);

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
        .option(OPTION_ENABLED)
        .rpcmethod(
            "lsps-listprotocols",
            "list protocols supported by lsp",
            on_lsps_listprotocols,
        )
        .configure()
        .await?
    {
        if !plugin.option(&OPTION_ENABLED)? {
            return plugin
                .disable(&format!("`{}` not enabled", OPTION_ENABLED.name))
                .await;
        }

        let plugin = plugin.start(state).await?;
        plugin.join().await
    } else {
        Ok(())
    }
}

/// RPC Method handler for `lsps-listprotocols`.
async fn on_lsps_listprotocols(
    p: cln_plugin::Plugin<State>,
    v: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    #[derive(Deserialize)]
    struct Request {
        lsp_id: String,
    }
    let dir = p.configuration().lightning_dir;
    let rpc_path = Path::new(&dir).join(&p.configuration().rpc_file);

    let req: Request = serde_json::from_value(v).context("Failed to parse request JSON")?;

    // Create the transport first and handle potential errors
    let transport = Bolt8Transport::new(
        &req.lsp_id,
        rpc_path,
        p.state().hook_manager.clone(),
        None, // Use default timeout
    )
    .context("Failed to create Bolt8Transport")?;

    // Now create the client using the transport
    let client = JsonRpcClient::new(transport);

    let request = lsps0::model::Lsps0listProtocolsRequest {};
    let res: lsps0::model::Lsps0listProtocolsResponse = client
        .call_typed(request)
        .await
        .context("lsps0.list_protocols call failed")?;

    debug!("Received lsps0.list_protocols response: {:?}", res);
    Ok(serde_json::to_value(res)?)
}
