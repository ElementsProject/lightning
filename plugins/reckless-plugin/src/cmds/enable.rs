use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;

use crate::{
    structs::{
        EnableArgs, PluginState, RecklessLogger, RecklessPlugin, RecklessTopic, RpcResponse,
        RpcResult, TargetResponse,
    },
    util::{
        add_plugin_to_config, cln_list_plugins, cln_start_plugin, cln_stop_plugin,
        get_plugin_manifest, parse_options, parse_target, read_metadata, remove_plugin_from_config,
    },
};

pub async fn handle_enable(
    plugin: Plugin<PluginState>,
    enable_args: EnableArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Enable, verbose);
    let mut result = RpcResult::new();

    let (plugin_name, git_ref) = match parse_target(&enable_args.target) {
        Ok((n, g)) => (n, g),
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

    let rl_plugin = match read_metadata(&plugin_name, &plugin_dir).await {
        Ok(p) => p,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };

    match enable_plugin(plugin.clone(), &rl_plugin, enable_args.options, &mut logger).await {
        Ok(()) => result.push(TargetResponse { plugin_name })?,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn enable_plugin(
    plugin: Plugin<PluginState>,
    rl_plugin: &RecklessPlugin,
    options: Vec<(String, Option<String>)>,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let entry_file = rl_plugin.manifest().entry_filename_str()?;
    let entry_path = rl_plugin.get_entrypath()?;

    let plugin_manifest = get_plugin_manifest(&entry_path, logger).await?;
    logger
        .log(&format!("{plugin_manifest:#?}"), LogLevel::TRACE)
        .await?;

    let parsed_options = parse_options(&plugin_manifest, &options)?;

    if let Some(req_opts) = rl_plugin.manifest().required_options.as_ref() {
        for option in req_opts {
            if !parsed_options.iter().any(|(o, _)| o == option) {
                return Err(anyhow!("option `{option}` is required"));
            }
        }
    }

    let running_plugins = cln_list_plugins(plugin.clone(), logger).await?;
    if running_plugins.contains(&entry_file) {
        let line = format!("Plugin {} is already running", rl_plugin.name());
        logger.log(&line, LogLevel::INFO).await?;
    } else if !running_plugins.contains(&entry_file) && plugin_manifest.is_dynamic() {
        cln_start_plugin(
            plugin.clone(),
            rl_plugin.name(),
            &entry_path,
            options,
            logger,
        )
        .await?;
    } else if !plugin_manifest.is_dynamic() {
        let line = format!(
            "{} is not dynamic and will be started the next time the node starts",
            rl_plugin.name()
        );
        logger.log(&line, LogLevel::INFO).await?;
    }

    match add_plugin_to_config(plugin.clone(), entry_path, parsed_options, plugin_manifest).await {
        Ok(()) => {
            let line = format!("{} enabled", rl_plugin.name());
            logger.log(&line, LogLevel::INFO).await?;
        }
        Err(e) => {
            return Err(anyhow!("{} failed to enable: {e}", rl_plugin.name()));
        }
    }

    Ok(())
}

pub async fn handle_disable(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Enable, verbose);
    let mut result = RpcResult::new();

    let (plugin_name, git_ref) = match parse_target(&target) {
        Ok((pn, g)) => (pn, g),
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

    let rl_plugin = match read_metadata(&plugin_name, &plugin_dir).await {
        Ok(p) => p,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };

    match disable_plugin(plugin.clone(), &rl_plugin, &mut logger).await {
        Ok(_) => result.push(TargetResponse { plugin_name })?,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn disable_plugin(
    plugin: Plugin<PluginState>,
    rl_plugin: &RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
) -> Result<Vec<(String, Option<String>)>, anyhow::Error> {
    let entry_file = rl_plugin.manifest().entry_filename_str()?;
    let entry_path = rl_plugin.get_entrypath()?;

    let manifest = get_plugin_manifest(&entry_path, logger).await?;
    logger
        .log(&format!("{manifest:#?}"), LogLevel::TRACE)
        .await?;

    let running_plugins = cln_list_plugins(plugin.clone(), logger).await?;
    if running_plugins.contains(&entry_file) {
        cln_stop_plugin(plugin.clone(), rl_plugin.name(), &entry_path, logger).await?;
    } else {
        let line = format!("{} already stopped", rl_plugin.name());
        logger.log(&line, LogLevel::INFO).await?;
    }

    let old_options = remove_plugin_from_config(plugin.clone(), entry_path, manifest).await?;
    let line = format!("{} disabled", rl_plugin.name());
    logger.log(&line, LogLevel::INFO).await?;

    Ok(old_options)
}
