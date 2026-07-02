use std::collections::HashMap;

use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::{Map, Value, json};
use tokio::fs;

use crate::{
    structs::{Metadata, PluginState, RecklessLogger, RecklessTopic, RpcResponse, RpcResult},
    util::{read_metadata, search_sources},
};

pub async fn handle_list_available(
    plugin: Plugin<PluginState>,
    target: Option<String>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);
    let mut result = RpcResult::new();

    let reckless_plugins = match search_sources(&plugin, target, &mut logger).await {
        Ok(o) => o,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };

    for (plugin_name, plugin) in reckless_plugins {
        let mut entry = Map::new();
        let Ok(Value::Object(plugin_json)) = serde_json::to_value(&plugin) else {
            let line = format!("failed to serialize plugin {plugin_name}");
            logger.log(&line, LogLevel::BROKEN).await?;
            return Err(anyhow!(line));
        };
        let la_fields: Vec<(String, Value)> = ["plugin_name", "installer", "manifest", "origin"]
            .iter()
            .filter_map(|key| {
                plugin_json
                    .get(*key)
                    .map(|v| ((*key).to_string(), v.clone()))
            })
            .collect();
        entry.extend(la_fields);
        result.push(entry)?;
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn handle_list_installed(
    plugin: Plugin<PluginState>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);
    let mut result = RpcResult::new();

    let installed = match list_installed(plugin.clone()).await {
        Ok(i) => i,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(anyhow!(e.to_string()));
        }
    };

    for (plugin_name, metadata) in installed {
        let mut entry = Map::new();
        entry.insert("plugin_name".to_owned(), json!(plugin_name));
        let Ok(Value::Object(plugin_json)) = serde_json::to_value(&metadata) else {
            return Err(anyhow!(
                "failed to serialize {plugin_name}'s metadata: {metadata:?}",
            ));
        };
        entry.extend(plugin_json);
        result.push(entry)?;
    }

    let response = RpcResponse::new(result, logger);

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
