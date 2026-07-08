use std::collections::HashMap;

use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;
use tokio::fs;

use crate::{
    structs::{
        ListavailableResponse, ListavailableResult, ListinstalledResponse, ListinstalledResult,
        Metadata, PluginState, RecklessLogger, RecklessTopic,
    },
    util::{read_metadata, search_sources},
};

pub async fn handle_list_available(
    plugin: Plugin<PluginState>,
    target: Option<String>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);
    let mut listavailable_results = Vec::new();

    let reckless_plugins = match search_sources(&plugin, target, &mut logger).await {
        Ok(o) => o,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };

    for (_plugin_name, plugin) in reckless_plugins {
        listavailable_results.push(ListavailableResult::from(plugin));
    }

    let response = ListavailableResponse::new(listavailable_results, logger);

    Ok(json!(response))
}

pub async fn handle_list_installed(
    plugin: Plugin<PluginState>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);
    let mut listinstalled_results = Vec::new();

    let installed = match list_installed(plugin.clone()).await {
        Ok(i) => i,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(anyhow!(e.to_string()));
        }
    };

    for (plugin_name, metadata) in installed {
        let li_res = ListinstalledResult::new(metadata, plugin_name);
        listinstalled_results.push(li_res);
    }

    let response = ListinstalledResponse::new(listinstalled_results, logger);

    Ok(json!(response))
}

pub async fn list_installed(
    plugin: Plugin<PluginState>,
) -> Result<HashMap<String, Metadata>, anyhow::Error> {
    let mut result: HashMap<String, Metadata> = HashMap::new();
    let mut entries = fs::read_dir(&plugin.state().reckless_dir).await?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if file_type.is_file() {
            continue;
        }
        let plugin_name = entry.file_name().to_string_lossy().to_string();
        if let Ok(rl_plugin) = read_metadata(&plugin_name, &entry.path()).await {
            result.insert(plugin_name, rl_plugin.metadata().clone());
        }
    }

    Ok(result)
}
