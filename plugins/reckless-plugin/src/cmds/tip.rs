use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::{model::requests::XpayRequest, notifications::LogLevel, primitives::Amount};
use serde_json::json;

use crate::{
    structs::{PluginState, RecklessLogger, RecklessTopic, RpcResponse, RpcResult, TipArgs},
    util::{parse_target, read_metadata, search_sources},
};

pub async fn handle_tip(
    plugin: Plugin<PluginState>,
    args: TipArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut result = RpcResult::new();
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Tip, verbose);

    let (plugin_name, git_ref) = match parse_target(&args.target) {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };
    if git_ref.is_some() {
        let line = "git refs are not supported here";
        logger.log(line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    }

    let plugin_dir = plugin.state().reckless_dir.join(&plugin_name);

    let offer = match read_metadata(&plugin_name, &plugin_dir).await {
        Ok(p) => {
            if let Some(off) = &p.manifest().offer {
                Some(off.clone())
            } else {
                let line =
                    format!("installed version of {plugin_name} has no offer, checking sources...");
                logger.log(&line, LogLevel::INFO).await?;
                get_offer_from_sources(&plugin, &plugin_name, &mut logger).await?
            }
        }
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            let line = format!("{plugin_name} not installed, searching in sources...");
            logger.log(&line, LogLevel::INFO).await?;

            get_offer_from_sources(&plugin, &plugin_name, &mut logger).await?
        }
    };

    let Some(offer) = offer else {
        return Err(anyhow!(
            "no offer found in reckless manifest for {plugin_name}"
        ));
    };

    let line = format!(
        "Sending {}msat to {plugin_name} author...",
        args.amount_msat
    );
    logger.log(&line, LogLevel::INFO).await?;

    let mut rpc = plugin.state().rpc.lock().await;
    let xpay = match rpc
        .call_typed(&XpayRequest {
            amount_msat: Some(Amount::from_msat(args.amount_msat)),
            dev_use_shadow: None,
            label: None,
            localinvreqid: None,
            maxdelay: None,
            maxfee: None,
            partial_msat: None,
            payer_note: args.payer_note,
            retry_for: None,
            layers: None,
            invstring: offer.clone(),
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            let line = format!(
                "Error sending {}msat to {plugin_name} author: {e}",
                args.amount_msat
            );
            logger.log(&line, LogLevel::UNUSUAL).await?;
            return Err(anyhow!(line));
        }
    };

    let line = format!(
        "Successfully sent {}msat to {plugin_name} author!",
        args.amount_msat
    );
    logger.log(&line, LogLevel::INFO).await?;

    result.push(xpay)?;

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

async fn get_offer_from_sources(
    plugin: &Plugin<PluginState>,
    plugin_name: &str,
    logger: &mut RecklessLogger<'_>,
) -> Result<Option<String>, anyhow::Error> {
    let search_results = match search_sources(plugin, Some(plugin_name.to_owned()), logger).await {
        Ok(o) => o,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };
    let Some(rlp) = search_results.get(plugin_name) else {
        return Err(anyhow!("{plugin_name} not found installed or in sources"));
    };

    Ok(rlp.manifest().offer.clone())
}
