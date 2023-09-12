use std::{str::FromStr, time::Duration};

use anyhow::{anyhow, Error};
use cln_plugin::Plugin;
use cln_rpc::{
    model::{requests::InvoiceRequest, responses::ListinvoicesInvoicesStatus},
    primitives::{Amount, AmountOrAny},
    ClnRpc, Request, Response,
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{time, time::Instant};

use crate::{
    model::PluginState,
    util::{
        datastore_new_state, datastore_update_state_forced, listdatastore_htlc_expiry,
        listdatastore_state, listinvoices, listpeerchannels, make_rpc_path,
        CANCEL_HOLD_BEFORE_HTLC_EXPIRY_BLOCKS, CANCEL_HOLD_BEFORE_INVOICE_EXPIRY_SECONDS,
    },
    Holdstate,
};

pub async fn hold_invoice(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let rpc_path = make_rpc_path(plugin.clone());
    let mut rpc = ClnRpc::new(&rpc_path).await?;

    let valid_arg_keys = vec![
        "amount_msat",
        "label",
        "description",
        "expiry",
        "fallbacks",
        "preimage",
        "cltv",
        "deschashonly",
    ];

    let mut new_args = serde_json::Value::Object(Default::default());
    match args {
        serde_json::Value::Array(a) => {
            for (idx, arg) in a.iter().enumerate() {
                if idx < valid_arg_keys.len() {
                    new_args[valid_arg_keys[idx]] = arg.clone();
                }
            }
        }
        serde_json::Value::Object(o) => {
            for (k, v) in o.iter() {
                if !valid_arg_keys.contains(&k.as_str()) {
                    return Ok(invalid_argument_error(k));
                }
                new_args[k] = v.clone();
            }
        }
        _ => return Ok(invalid_input_error(&args.to_string())),
    };

    let inv_req = match build_invoice_request(&new_args) {
        Ok(i) => i,
        Err(e) => return Ok(e),
    };

    let invoice_request = match rpc.call(Request::Invoice(inv_req)).await {
        Ok(resp) => resp,
        Err(e) => match e.code {
            Some(_) => return Ok(json!(e)),
            None => return Err(anyhow!("Unexpected response in invoice: {}", e.to_string())),
        },
    };
    let result = match invoice_request {
        Response::Invoice(info) => info,
        e => return Err(anyhow!("Unexpected result in invoice: {:?}", e)),
    };
    datastore_new_state(
        &rpc_path,
        result.payment_hash.to_string(),
        Holdstate::Open.to_string(),
    )
    .await?;
    Ok(json!(result))
}

pub async fn hold_invoice_settle(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let rpc_path = make_rpc_path(plugin.clone());

    let pay_hash = match parse_payment_hash(args) {
        Ok(ph) => ph,
        Err(e) => return Ok(e),
    };

    let data = match listdatastore_state(&rpc_path, pay_hash.clone()).await {
        Ok(d) => d,
        Err(_) => return Ok(payment_hash_missing_error(&pay_hash)),
    };

    let holdstate = Holdstate::from_str(&data.string.unwrap())?;

    if holdstate.is_valid_transition(&Holdstate::Settled) {
        let result = datastore_update_state_forced(
            &rpc_path,
            pay_hash.clone(),
            Holdstate::Settled.to_string(),
        )
        .await;
        match result {
            Ok(_r) => {
                let mut holdinvoices = plugin.state().holdinvoices.lock().await;
                if let Some(invoice) = holdinvoices.get_mut(&pay_hash.to_string()) {
                    for (_, htlc) in invoice.htlc_data.iter_mut() {
                        *htlc.loop_mutex.lock().await = true;
                    }
                } else {
                    warn!(
                        "payment_hash: '{}' DROPPED INVOICE from internal state!",
                        pay_hash
                    );
                    return Err(anyhow!(
                        "Invoice dropped from internal state unexpectedly: {}",
                        pay_hash
                    ));
                }

                Ok(json!(HoldStateResponse {
                    state: Holdstate::Settled.to_string(),
                }))
            }
            Err(e) => Err(anyhow!(
                "Unexpected result {} to method call datastore_update_state_forced",
                e.to_string()
            )),
        }
    } else {
        Ok(wrong_hold_state(holdstate))
    }
}

pub async fn hold_invoice_cancel(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let rpc_path = make_rpc_path(plugin.clone());

    let pay_hash = match parse_payment_hash(args) {
        Ok(ph) => ph,
        Err(e) => return Ok(e),
    };

    let data = match listdatastore_state(&rpc_path, pay_hash.clone()).await {
        Ok(d) => d,
        Err(_) => return Ok(payment_hash_missing_error(&pay_hash)),
    };

    let holdstate = Holdstate::from_str(&data.string.unwrap())?;

    if holdstate.is_valid_transition(&Holdstate::Canceled) {
        let result = datastore_update_state_forced(
            &rpc_path,
            pay_hash.clone(),
            Holdstate::Canceled.to_string(),
        )
        .await;
        match result {
            Ok(_r) => {
                let mut holdinvoices = plugin.state().holdinvoices.lock().await;
                if let Some(invoice) = holdinvoices.get_mut(&pay_hash.to_string()) {
                    for (_, htlc) in invoice.htlc_data.iter_mut() {
                        *htlc.loop_mutex.lock().await = true;
                    }
                }

                Ok(json!(HoldStateResponse {
                    state: Holdstate::Canceled.to_string(),
                }))
            }
            Err(e) => Err(anyhow!(
                "Unexpected result {} to method call datastore_update_state_forced",
                e.to_string()
            )),
        }
    } else {
        Ok(wrong_hold_state(holdstate))
    }
}

pub async fn hold_invoice_lookup(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let rpc_path = make_rpc_path(plugin.clone());

    let pay_hash = match parse_payment_hash(args) {
        Ok(ph) => ph,
        Err(e) => return Ok(e),
    };

    let data = match listdatastore_state(&rpc_path, pay_hash.clone()).await {
        Ok(d) => d,
        Err(_) => return Ok(payment_hash_missing_error(&pay_hash)),
    };

    let holdstate = Holdstate::from_str(&data.string.unwrap())?;

    let mut htlc_expiry = None;
    match holdstate {
        Holdstate::Open => {
            let invoices = listinvoices(&rpc_path, None, Some(pay_hash.clone()))
                .await?
                .invoices;
            if let Some(inv) = invoices.first() {
                if inv.status == ListinvoicesInvoicesStatus::EXPIRED {
                    datastore_update_state_forced(
                        &rpc_path,
                        pay_hash.clone(),
                        Holdstate::Canceled.to_string(),
                    )
                    .await?;
                    return Ok(json!(HoldLookupResponse {
                        state: Holdstate::Canceled.to_string(),
                        htlc_expiry
                    }));
                }
            }
        }
        Holdstate::Accepted => {
            htlc_expiry = Some(listdatastore_htlc_expiry(&rpc_path, pay_hash.clone()).await?)
        }
        Holdstate::Canceled => {
            let now = Instant::now();
            loop {
                let mut all_cancelled = true;
                let channels = match listpeerchannels(&rpc_path).await?.channels {
                    Some(c) => c,
                    None => break,
                };

                for chan in channels {
                    if let Some(htlcs) = chan.htlcs {
                        for htlc in htlcs {
                            if let Some(ph) = htlc.payment_hash {
                                if ph.to_string() == pay_hash {
                                    all_cancelled = false;
                                }
                            }
                        }
                    }
                }

                if all_cancelled {
                    break;
                }

                if now.elapsed().as_secs() > 20 {
                    return Err(anyhow!(
                        "holdinvoicelookup: Timed out before cancellation of all \
                        related htlcs was finished"
                    ));
                }

                time::sleep(Duration::from_secs(2)).await
            }
        }
        Holdstate::Settled => {
            let now = Instant::now();
            loop {
                let invoices = listinvoices(&rpc_path, None, Some(pay_hash.clone()))
                    .await?
                    .invoices;

                if let Some(inv) = invoices.first() {
                    match inv.status {
                        ListinvoicesInvoicesStatus::PAID => {
                            break;
                        }
                        ListinvoicesInvoicesStatus::EXPIRED => {
                            return Err(anyhow!(
                                "holdinvoicelookup: Invoice expired while trying to settle!"
                            ));
                        }
                        _ => (),
                    }
                }

                if now.elapsed().as_secs() > 20 {
                    return Err(anyhow!(
                        "holdinvoicelookup: Timed out before settlement could be confirmed",
                    ));
                }

                time::sleep(Duration::from_secs(2)).await
            }
        }
    }
    Ok(json!(HoldLookupResponse {
        state: holdstate.to_string(),
        htlc_expiry
    }))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HoldLookupResponse {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    htlc_expiry: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HoldStateResponse {
    state: String,
}

fn missing_parameter_error(param: &str) -> serde_json::Value {
    json!({
        "code": -32602,
        "message": format!("missing required parameter: {}", param)
    })
}

fn invalid_argument_error(arg: &str) -> serde_json::Value {
    json!({
        "code": -1,
        "message": format!("Invalid argument: '{}'", arg)
    })
}

fn invalid_input_error(input: &str) -> serde_json::Value {
    json!({
        "code": -1,
        "message": format!("Invalid input: '{}'", input)
    })
}

fn invalid_hash_error(name: &str, token: &str) -> serde_json::Value {
    json!({
        "code": -32602,
        "message": format!("{}: should be a 32 byte hex value: \
        invalid token '{}'", name, token)
    })
}

fn payment_hash_missing_error(pay_hash: &str) -> serde_json::Value {
    json!({
        "code": -32602,
        "message": format!("payment_hash '{}' not found", pay_hash)
    })
}

fn invalid_integer_error(name: &str, integer: &str) -> serde_json::Value {
    json!({
        "code": -32602,
        "message": format!("{}: should be an unsigned 64 bit integer: \
        invalid token '{}'", name,integer)
    })
}

fn too_many_params_error(actual: usize, expected: usize) -> serde_json::Value {
    json!({
       "code": -32602,
       "message": format!("too many parameters: got {}, expected {}", actual, expected)
    })
}

fn wrong_hold_state(holdstate: Holdstate) -> serde_json::Value {
    json!({
        "code": -32602,
        "message": format!("Holdinvoice is in wrong state: '{}'", holdstate)
    })
}

fn parse_payment_hash(args: serde_json::Value) -> Result<String, serde_json::Value> {
    if let serde_json::Value::Array(i) = args {
        if i.is_empty() {
            Err(missing_parameter_error("payment_hash"))
        } else if i.len() != 1 {
            Err(too_many_params_error(i.len(), 1))
        } else if let serde_json::Value::String(s) = i.first().unwrap() {
            if s.len() != 64 {
                Err(invalid_hash_error("payment_hash", s))
            } else {
                Ok(s.clone())
            }
        } else {
            Err(invalid_hash_error(
                "payment_hash",
                &i.first().unwrap().to_string(),
            ))
        }
    } else if let serde_json::Value::Object(o) = args {
        let valid_arg_keys = vec!["payment_hash"];
        for (k, _v) in o.iter() {
            if !valid_arg_keys.contains(&k.as_str()) {
                return Err(invalid_argument_error(k));
            }
        }
        if let Some(pay_hash) = o.get("payment_hash") {
            if let serde_json::Value::String(s) = pay_hash {
                if s.len() != 64 {
                    Err(invalid_hash_error("payment_hash", s))
                } else {
                    Ok(s.clone())
                }
            } else {
                Err(invalid_hash_error("payment_hash", &pay_hash.to_string()))
            }
        } else {
            Err(missing_parameter_error("payment_hash"))
        }
    } else {
        Err(invalid_input_error(&args.to_string()))
    }
}

fn build_invoice_request(args: &serde_json::Value) -> Result<InvoiceRequest, serde_json::Value> {
    let amount_msat = if let Some(amt) = args.get("amount_msat") {
        AmountOrAny::Amount(Amount::from_msat(if let Some(amt_u64) = amt.as_u64() {
            amt_u64
        } else {
            return Err(invalid_integer_error(
                "amount_msat|msatoshi",
                &amt.to_string(),
            ));
        }))
    } else {
        return Err(missing_parameter_error("amount_msat|msatoshi"));
    };

    let label = if let Some(lbl) = args.get("label") {
        match lbl {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.as_str().to_string(),
            e => return Err(invalid_input_error(&e.to_string())),
        }
    } else {
        return Err(missing_parameter_error("label"));
    };

    let description = if let Some(desc) = args.get("description") {
        match desc {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.as_str().to_string(),
            e => return Err(invalid_input_error(&e.to_string())),
        }
    } else {
        return Err(missing_parameter_error("description"));
    };

    let expiry = if let Some(exp) = args.get("expiry") {
        Some(if let Some(exp_u64) = exp.as_u64() {
            if exp_u64 <= CANCEL_HOLD_BEFORE_INVOICE_EXPIRY_SECONDS {
                return Err(json!({
                    "code": -32602,
                    "message": format!("expiry: needs to be greater than '{}' requested: '{}'",
                    CANCEL_HOLD_BEFORE_INVOICE_EXPIRY_SECONDS, exp_u64)
                }));
            } else {
                exp_u64
            }
        } else {
            return Err(invalid_integer_error("expiry", &exp.to_string()));
        })
    } else {
        None
    };

    let fallbacks = if let Some(fbcks) = args.get("fallbacks") {
        Some(if let Some(fbcks_arr) = fbcks.as_array() {
            fbcks_arr
                .iter()
                .filter_map(|value| value.as_str().map(|s| s.to_string()))
                .collect()
        } else {
            return Err(json!({
                "code": -32602,
                "message": format!("fallbacks: should be an array: \
                invalid token '{}'", fbcks.to_string())
            }));
        })
    } else {
        None
    };

    let preimage = if let Some(preimg) = args.get("preimage") {
        Some(if let Some(preimg_str) = preimg.as_str() {
            if preimg_str.len() != 64 {
                return Err(invalid_hash_error("preimage", &preimg.to_string()));
            } else {
                preimg_str.to_string()
            }
        } else {
            return Err(invalid_hash_error("preimage", &preimg.to_string()));
        })
    } else {
        None
    };

    let cltv = if let Some(c) = args.get("cltv") {
        Some(if let Some(c_u64) = c.as_u64() {
            if c_u64 as u32 <= CANCEL_HOLD_BEFORE_HTLC_EXPIRY_BLOCKS {
                return Err(json!({
                    "code": -32602,
                    "message": format!("cltv: needs to be greater than '{}' requested: '{}'",
                    CANCEL_HOLD_BEFORE_HTLC_EXPIRY_BLOCKS, c_u64)
                }));
            } else {
                c_u64 as u32
            }
        } else {
            return Err(json!({
                "code": -32602,
                "message": format!("cltv: should be an integer: \
                invalid token '{}'", c.to_string())
            }));
        })
    } else {
        None
    };

    let deschashonly = if let Some(dhash) = args.get("deschashonly") {
        Some(if let Some(dhash_bool) = dhash.as_bool() {
            dhash_bool
        } else {
            return Err(json!({
                "code": -32602,
                "message": format!("deschashonly: should be 'true' or 'false': \
                invalid token '{}'", dhash.to_string())
            }));
        })
    } else {
        None
    };

    Ok(InvoiceRequest {
        amount_msat,
        label,
        description,
        expiry,
        fallbacks,
        preimage,
        cltv,
        deschashonly,
    })
}
