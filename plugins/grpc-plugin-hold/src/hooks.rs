use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Error};
use cln_grpc_hold::{
    datastore_htlc_expiry, datastore_update_state, listdatastore_state, Holdstate,
};
use cln_plugin::Plugin;
use cln_rpc::primitives::Amount;
use log::{debug, info, warn};
use serde_json::json;
use tokio::time;

use crate::{
    util::{cleanup_htlc_state, listinvoices, make_rpc_path},
    HoldHtlc, HoldInvoice, PluginState,
};

pub(crate) async fn htlc_handler(
    plugin: Plugin<PluginState>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    if let Some(htlc) = v.get("htlc") {
        if let Some(pay_hash) = htlc
            .get("payment_hash")
            .and_then(|pay_hash| pay_hash.as_str())
        {
            debug!("payment_hash: `{}`. htlc_hook started!", pay_hash);
            let rpc_path = make_rpc_path(&plugin);

            let is_new_invoice;
            let cltv_expiry;

            let amount_msat;

            let invoice;
            let scid;
            let htlc_id;
            let hold_state;

            {
                let mut states = plugin.state().holdinvoices.lock().await;
                let generation;
                match states.get_mut(&pay_hash.to_string()) {
                    Some(h) => {
                        is_new_invoice = false;
                        debug!(
                            "payment_hash: `{}`. Htlc is for a known hold-invoice! Processing...",
                            pay_hash
                        );

                        hold_state = h.hold_state;
                        invoice = h.invoice.clone();
                        generation = h.generation;
                    }
                    None => {
                        is_new_invoice = true;
                        debug!(
                            "payment_hash: `{}`. Htlc for fresh invoice arrived. Checking if it's a hold-invoice...",
                            pay_hash
                        );

                        match listdatastore_state(&rpc_path, pay_hash.to_string()).await {
                            Ok(dbstate) => {
                                debug!(
                                    "payment_hash: `{}`. Htlc is indeed for a hold-invoice! Processing...",
                                    pay_hash
                                );
                                hold_state = Holdstate::from_str(&dbstate.string.unwrap())?;
                                generation = if let Some(g) = dbstate.generation {
                                    g
                                } else {
                                    0
                                };

                                invoice = listinvoices(&rpc_path, None, Some(pay_hash.to_string()))
                                    .await?
                                    .invoices
                                    .first()
                                    .ok_or(anyhow!(
                                        "payment_hash: `{}`. Hold-invoice not found!",
                                        pay_hash
                                    ))?
                                    .clone();
                            }
                            Err(_e) => {
                                debug!(
                                    "payment_hash: `{}`. Not a hold-invoice! Continue...",
                                    pay_hash
                                );
                                return Ok(json!({"result": "continue"}));
                            }
                        };
                    }
                }

                htlc_id = match htlc.get("id") {
                    Some(ce) => ce.as_u64().unwrap(),
                    None => {
                        warn!(
                            "payment_hash: `{}`. htlc id not found! Rejecting htlc...",
                            pay_hash
                        );
                        return Ok(json!({"result": "fail"}));
                    }
                };

                scid = match htlc.get("short_channel_id") {
                    Some(ce) => ce.as_str().unwrap(),
                    None => {
                        warn!(
                            "payment_hash: `{}`. short_channel_id not found! Rejecting htlc...",
                            pay_hash
                        );
                        return Ok(json!({"result": "fail"}));
                    }
                };

                cltv_expiry = match htlc.get("cltv_expiry") {
                    Some(ce) => ce.as_u64().unwrap() as u32,
                    None => {
                        warn!(
                            "payment_hash: `{}`. cltv_expiry not found! Rejecting htlc...",
                            pay_hash
                        );
                        return Ok(json!({"result": "fail"}));
                    }
                };

                amount_msat = match htlc.get("amount_msat") {
                    Some(ce) => ce.as_u64().unwrap(),
                    None => {
                        warn!(
                            "payment_hash: `{}` scid: `{}` htlc_id: {}: amount_msat not found! Rejecting htlc...",
                            pay_hash, scid, htlc_id
                        );
                        return Ok(json!({"result": "fail"}));
                    }
                };

                if is_new_invoice {
                    datastore_htlc_expiry(&rpc_path, pay_hash.to_string(), cltv_expiry.to_string())
                        .await?;

                    let mut htlc_data = HashMap::new();
                    htlc_data.insert(
                        scid.to_string() + &htlc_id.to_string(),
                        HoldHtlc {
                            amount_msat,
                            cltv_expiry,
                        },
                    );
                    states.insert(
                        pay_hash.to_string(),
                        HoldInvoice {
                            hold_state,
                            generation,
                            htlc_data,
                            invoice: invoice.clone(),
                        },
                    );
                } else {
                    let holdinvoice = states.get_mut(&pay_hash.to_string()).unwrap();
                    if cltv_expiry
                        < holdinvoice
                            .htlc_data
                            .values()
                            .map(|htlc| htlc.cltv_expiry)
                            .min()
                            .unwrap()
                    {
                        datastore_htlc_expiry(
                            &rpc_path,
                            pay_hash.to_string(),
                            cltv_expiry.to_string(),
                        )
                        .await?;
                    }
                    holdinvoice.htlc_data.insert(
                        scid.to_string() + &htlc_id.to_string(),
                        HoldHtlc {
                            amount_msat,
                            cltv_expiry,
                        },
                    );
                }
            }

            if let Holdstate::Canceled = hold_state {
                info!(
                        "payment_hash: `{}`. Htlc arrived after hold-cancellation was requested. Rejecting htlc...",
                        pay_hash
                    );

                cleanup_htlc_state(plugin.clone(), pay_hash, scid, htlc_id).await;

                return Ok(json!({"result": "fail"}));
            }

            info!(
                "payment_hash: `{}` scid: `{}` htlc_id: `{}`. Holding {}msat",
                pay_hash,
                scid.to_string(),
                htlc_id,
                amount_msat
            );

            loop {
                {
                    let hold_invoice = plugin.state().holdinvoices.lock().await.clone();
                    match hold_invoice.get(&pay_hash.to_string()) {
                        Some(hold_invoice_data) => {
                            let holdstate = hold_invoice_data.hold_state;
                            let generation = hold_invoice_data.generation;
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            if invoice.expires_at <= now + 60 {
                                warn!(
                                    "payment_hash: `{}` scid: `{}` htlc: `{}`. Hold-invoice expired! State=CANCELED",
                                    pay_hash, scid, htlc_id
                                );
                                match datastore_update_state(
                                    &rpc_path,
                                    pay_hash.to_string(),
                                    Holdstate::Canceled.to_string(),
                                    generation,
                                )
                                .await
                                {
                                    Ok(_o) => (),
                                    Err(_e) => {
                                        time::sleep(Duration::from_secs(2)).await;
                                        continue;
                                    }
                                };

                                cleanup_htlc_state(plugin.clone(), pay_hash, scid, htlc_id).await;

                                return Ok(json!({"result": "fail"}));
                            }

                            if cltv_expiry <= plugin.state().blockheight.lock().clone() + 6 {
                                warn!(
                                    "payment_hash: `{}` scid: `{}` htlc: `{}`. HTLC timed out. Rejecting htlc...",
                                    pay_hash, scid, htlc_id
                                );
                                let cur_amt: u64 = hold_invoice_data
                                    .htlc_data
                                    .values()
                                    .map(|htlc| htlc.amount_msat)
                                    .sum();
                                if Amount::msat(&invoice.amount_msat.unwrap())
                                    > cur_amt - amount_msat
                                    && holdstate == Holdstate::Accepted
                                {
                                    match datastore_update_state(
                                        &rpc_path,
                                        pay_hash.to_string(),
                                        Holdstate::Open.to_string(),
                                        generation,
                                    )
                                    .await
                                    {
                                        Ok(_o) => (),
                                        Err(_e) => {
                                            time::sleep(Duration::from_secs(2)).await;
                                            continue;
                                        }
                                    };
                                    info!(
                                        "payment_hash: `{}` scid: `{}` htlc: `{}`. No longer enough msats for the hold-invoice. State=OPEN",
                                        pay_hash, scid, htlc_id
                                    );
                                }

                                cleanup_htlc_state(plugin.clone(), pay_hash, scid, htlc_id).await;

                                return Ok(json!({"result": "fail"}));
                            }

                            match holdstate {
                                Holdstate::Open => {
                                    if Amount::msat(&invoice.amount_msat.unwrap())
                                        <= hold_invoice_data
                                            .htlc_data
                                            .values()
                                            .map(|htlc| htlc.amount_msat)
                                            .sum()
                                        && holdstate.is_valid_transition(&Holdstate::Accepted)
                                    {
                                        match datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Holdstate::Accepted.to_string(),
                                            generation,
                                        )
                                        .await
                                        {
                                            Ok(_o) => (),
                                            Err(_e) => {
                                                time::sleep(Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        };
                                        info!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. Got enough msats for the hold-invoice. State=ACCEPTED",
                                            pay_hash, scid, htlc_id
                                        );
                                    } else {
                                        debug!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. Not enough msats for the hold-invoice yet.",
                                            pay_hash, scid, htlc_id
                                        );
                                    }
                                }
                                Holdstate::Accepted => {
                                    if Amount::msat(&invoice.amount_msat.unwrap())
                                        > hold_invoice_data
                                            .htlc_data
                                            .values()
                                            .map(|htlc| htlc.amount_msat)
                                            .sum()
                                        && holdstate.is_valid_transition(&Holdstate::Open)
                                    {
                                        match datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Holdstate::Open.to_string(),
                                            generation,
                                        )
                                        .await
                                        {
                                            Ok(_o) => (),
                                            Err(_e) => {
                                                time::sleep(Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        };
                                        info!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. No longer enough msats for the hold-invoice. State=OPEN",
                                            pay_hash, scid, htlc_id
                                        );
                                    } else {
                                        debug!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. Holding accepted hold-invoice.",
                                            pay_hash, scid, htlc_id
                                        );
                                    }
                                }
                                Holdstate::Settled => {
                                    info!(
                                        "payment_hash: `{}` scid: `{}` htlc: `{}`. Settling htlc for hold-invoice. State=SETTLED",
                                        pay_hash, scid, htlc_id
                                    );

                                    cleanup_htlc_state(plugin.clone(), pay_hash, scid, htlc_id)
                                        .await;

                                    return Ok(json!({"result": "continue"}));
                                }
                                Holdstate::Canceled => {
                                    info!(
                                        "payment_hash: `{}` scid: `{}` htlc: `{}`. Rejecting htlc for canceled hold-invoice.  State=CANCELED",
                                        pay_hash, scid, htlc_id
                                    );

                                    cleanup_htlc_state(plugin.clone(), pay_hash, scid, htlc_id)
                                        .await;

                                    return Ok(json!({"result": "fail"}));
                                }
                            }
                        }
                        None => {
                            warn!("payment_hash: `{}` scid: `{}` htlc: `{}`. DROPPED INVOICE from internal state!", pay_hash, scid, htlc_id);
                            return Err(anyhow!(
                                "Invoice dropped from internal state unexpectedly: {}",
                                pay_hash
                            ));
                        }
                    }
                }
                time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
    warn!("htlc_accepted hook could not find htlc object");
    Ok(json!({"result": "continue"}))
}

pub async fn block_added(plugin: Plugin<PluginState>, v: serde_json::Value) -> Result<(), Error> {
    match v.get("block") {
        Some(block) => match block.get("height") {
            Some(h) => *plugin.state().blockheight.lock() = h.as_u64().unwrap() as u32,
            None => return Err(anyhow!("could not find height for block")),
        },
        None => return Err(anyhow!("could not read block notification")),
    };
    Ok(())
}
