use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Result};
use cln_plugin::Builder;
use log::{debug, warn};
use parking_lot::Mutex;

mod hooks;
mod tasks;
use holdinvoice::hold::{
    hold_invoice, hold_invoice_cancel, hold_invoice_lookup, hold_invoice_settle,
};
use holdinvoice::model::PluginState;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    debug!("Starting holdinvoice plugin");
    std::env::set_var("CLN_PLUGIN_LOG", "debug");

    let state = PluginState {
        blockheight: Arc::new(Mutex::new(u32::default())),
        holdinvoices: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
    };

    let confplugin = if let Some(p) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .rpcmethod(
            "holdinvoice",
            "create a new invoice and hold it",
            hold_invoice,
        )
        .rpcmethod(
            "holdinvoicesettle",
            "settle htlcs to corresponding holdinvoice",
            hold_invoice_settle,
        )
        .rpcmethod(
            "holdinvoicecancel",
            "cancel htlcs to corresponding holdinvoice",
            hold_invoice_cancel,
        )
        .rpcmethod(
            "holdinvoicelookup",
            "lookup hold status of holdinvoice",
            hold_invoice_lookup,
        )
        .hook("htlc_accepted", hooks::htlc_handler)
        .subscribe("block_added", hooks::block_added)
        .configure()
        .await?
    {
        p
    } else {
        return Ok(());
    };

    if let Ok(plugin) = confplugin.start(state).await {
        let cleanupclone = plugin.clone();
        tokio::spawn(async move {
            match tasks::autoclean_holdinvoice_db(cleanupclone).await {
                Ok(()) => (),
                Err(e) => warn!(
                    "Error in autoclean_holdinvoice_db thread: {}",
                    e.to_string()
                ),
            };
        });
        plugin.join().await
    } else {
        Err(anyhow!("Error starting the plugin!"))
    }
}
