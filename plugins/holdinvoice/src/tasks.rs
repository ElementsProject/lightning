use std::time::Duration;

use anyhow::Error;

use cln_plugin::Plugin;
use log::info;
use tokio::time::{self, Instant};

use holdinvoice::model::PluginState;
use holdinvoice::util::{
    del_datastore_htlc_expiry, del_datastore_state, listdatastore_all, listinvoices, make_rpc_path,
};

pub async fn autoclean_holdinvoice_db(plugin: Plugin<PluginState>) -> Result<(), Error> {
    time::sleep(Duration::from_secs(60)).await;
    info!("Starting autoclean_holdinvoice_db");

    let rpc_path = make_rpc_path(plugin.clone());
    loop {
        let now = Instant::now();
        let mut count = 0;
        {
            let node_invoices = listinvoices(&rpc_path, None, None).await?.invoices;

            let payment_hashes: Vec<String> = node_invoices
                .iter()
                .map(|invoice| invoice.payment_hash.to_string())
                .collect();

            let datastore = listdatastore_all(&rpc_path).await?.datastore;
            for data in datastore {
                if !payment_hashes.contains(&data.key[1]) {
                    let _res = del_datastore_htlc_expiry(&rpc_path, data.key[1].clone()).await;
                    let _res2 = del_datastore_state(&rpc_path, data.key[1].clone()).await;
                    count += 1;
                }
            }
        }
        info!(
            "cleaned up {} holdinvoice database entries in {}ms",
            count,
            now.elapsed().as_millis()
        );
        time::sleep(Duration::from_secs(3_600)).await;
    }
}
