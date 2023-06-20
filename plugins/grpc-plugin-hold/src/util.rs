use std::path::{Path, PathBuf};

use anyhow::anyhow;
use cln_plugin::{Error, Plugin};
use cln_rpc::{
    model::{ListinvoicesRequest, ListinvoicesResponse},
    ClnRpc, Request, Response,
};

use crate::PluginState;

pub async fn listinvoices(
    rpc_path: &PathBuf,
    label: Option<String>,
    payment_hash: Option<String>,
) -> Result<ListinvoicesResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let invoice_request = rpc
        .call(Request::ListInvoices(ListinvoicesRequest {
            label,
            invstring: None,
            payment_hash,
            offer_id: None,
        }))
        .await
        .map_err(|e| anyhow!("Error calling listinvoices: {:?}", e))?;
    match invoice_request {
        Response::ListInvoices(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in listinvoices: {:?}", e)),
    }
}

pub fn make_rpc_path(plugin: &Plugin<PluginState>) -> PathBuf {
    Path::new(&plugin.configuration().lightning_dir).join(plugin.configuration().rpc_file)
}

pub async fn cleanup_htlc_state(
    plugin: Plugin<PluginState>,
    pay_hash: &str,
    scid: &str,
    htlc_id: u64,
) {
    let mut hold_invoices = plugin.state().holdinvoices.lock().await;
    if let Some(h_inv) = hold_invoices.get_mut(pay_hash) {
        h_inv
            .htlc_data
            .remove(&(scid.to_string() + &htlc_id.to_string()));
        if h_inv.htlc_data.is_empty() {
            hold_invoices.remove(pay_hash);
        }
    }
}
