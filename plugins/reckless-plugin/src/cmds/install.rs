use std::{collections::HashMap, path::PathBuf};

use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;
use tokio::{fs, process::Command};

use crate::{
    cmds::enable::{disable_plugin, enable_plugin},
    installers::{
        install_custom_plugin, install_go_plugin, install_nodejs_plugin, install_poetry_plugin,
        install_python_plugin, install_rust_plugin, install_uv_legacy_plugin, install_uv_plugin,
        install_uv_shebang_plugin,
    },
    structs::{
        CommonResult, InstallArgs, InstallResponse, InstallResult, Installer, PluginState,
        RecklessLogger, RecklessPlugin, RecklessTopic, UninstallResponse,
    },
    util::{
        copy_dir_all, parse_install_target, parse_target, read_metadata, run_logged_command,
        search_sources, write_metadata,
    },
};

pub async fn handle_install(
    plugin: Plugin<PluginState>,
    install_args: InstallArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Install, verbose);

    let mut search_results: HashMap<String, RecklessPlugin> = HashMap::new();

    let (plugin_name, git_ref) = match parse_install_target(
        &mut logger,
        &install_args.target,
        &mut search_results,
        &plugin.state().reckless_dir,
    )
    .await
    {
        Ok((pn, g)) => (pn, g),
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };

    if search_results.is_empty() {
        search_results = match search_sources(&plugin, Some(plugin_name.clone()), &mut logger).await
        {
            Ok(o) => o,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
                return Err(e);
            }
        };
    }
    let Some(rl_plugin) = search_results.get_mut(&plugin_name) else {
        let line = format!("{plugin_name} not found in any known sources");
        logger.log(&line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    };

    pre_install_checks(rl_plugin, &plugin_name, git_ref.as_ref(), &mut logger).await?;

    let install_result = install(
        rl_plugin,
        git_ref.clone(),
        install_args.developer,
        &mut logger,
    )
    .await;

    match install_result {
        Ok(entrypoint) => {
            let line = format!(
                "{plugin_name} installed, entrypoint: {}",
                entrypoint.display()
            );
            logger.log(&line, LogLevel::DEBUG).await?;
        }
        Err(e) => {
            let line = format!("{plugin_name} install failed: {e}, uninstalling...");
            logger.log(&line, LogLevel::UNUSUAL).await?;
            if let Some(deps) = &rl_plugin.manifest().dependencies {
                let line = format!(
                    "Make sure you have the following system dependencies installed: {}",
                    deps.join(", ")
                );
                logger.log(&line, LogLevel::UNUSUAL).await?;
            }
            if let Err(e) = uninstall(plugin.clone(), plugin_name.clone(), &mut logger).await {
                let line = format!("{plugin_name} uninstall failed: {e}");
                logger.log(&line, LogLevel::BROKEN).await?;
                return Err(e);
            }
            return Err(e);
        }
    }

    let mut install_result = InstallResult {
        plugin_name: plugin_name.clone(),
        enabled: false,
        installed_commit: rl_plugin
            .metadata()
            .installed_commit()
            .map(std::borrow::ToOwned::to_owned),
    };

    match enable_plugin(plugin.clone(), rl_plugin, install_args.options, &mut logger).await {
        Ok(()) => install_result.enabled = true,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            let line =
                format!("{plugin_name} failed to start, it may require options, read the logs!");
            logger.log(&line, LogLevel::UNUSUAL).await?;
        }
    }

    let response = InstallResponse::new(install_result, logger);

    Ok(json!(response))
}

async fn install(
    rl_plugin: &mut RecklessPlugin,
    git_ref: Option<String>,
    developer: bool,
    logger: &mut RecklessLogger<'_>,
) -> Result<PathBuf, anyhow::Error> {
    if !rl_plugin.origin_plugin_path().exists() {
        return Err(anyhow!(
            "origin path does not exist: {}",
            rl_plugin.origin_repo_path().display()
        ));
    }

    fs::create_dir_all(rl_plugin.path()).await?;

    if !rl_plugin.is_local_path() {
        let mut command = Command::new("git");
        command
            .args(["pull", "--ff-only"])
            .current_dir(rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["submodule", "sync", "--recursive"])
            .current_dir(rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["submodule", "update", "--init", "--recursive"])
            .current_dir(rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["checkout", git_ref.as_deref().unwrap_or("HEAD")])
            .current_dir(rl_plugin.origin_plugin_path());
        run_logged_command(command, logger).await?;

        fs::create_dir_all(rl_plugin.source_path()).await?;
        copy_dir_all(
            rl_plugin.origin_plugin_path(),
            rl_plugin.source_path(),
            logger,
        )
        .await?;
    }

    let entrypoint = match rl_plugin.installer() {
        Installer::PythonUv => install_uv_plugin(rl_plugin, logger).await?,
        Installer::PythonUvShebang => install_uv_shebang_plugin(rl_plugin, logger).await?,
        Installer::PythonUvLegacy => install_uv_legacy_plugin(rl_plugin, logger).await?,
        Installer::PoetryVenv => install_poetry_plugin(rl_plugin, logger).await?,
        Installer::PyprojectViaPip | Installer::Python => {
            install_python_plugin(rl_plugin, logger).await?
        }
        Installer::Nodejs => install_nodejs_plugin(rl_plugin, logger).await?,
        Installer::Rust => install_rust_plugin(rl_plugin, logger, developer).await?,
        Installer::Go => install_go_plugin(rl_plugin, logger).await?,
        Installer::Custom => install_custom_plugin(rl_plugin, logger).await?,
    };

    if rl_plugin.is_local_path() {
        rl_plugin.metadata_mut().new_install(None, None);
    } else {
        let mut command = Command::new("git");
        command
            .args(["rev-parse", "HEAD"])
            .current_dir(rl_plugin.origin_plugin_path());
        let commit_hash = run_logged_command(command, logger).await?;

        let installed_ref = if let Some(gr) = &git_ref {
            gr.clone()
        } else {
            commit_hash
        };

        rl_plugin
            .metadata_mut()
            .new_install(Some(installed_ref), git_ref);
    }

    write_metadata(rl_plugin).await?;

    let line = format!("plugin installed: {}", entrypoint.display());
    logger.log(&line, LogLevel::INFO).await?;

    Ok(entrypoint)
}

async fn pre_install_checks(
    rl_plugin: &RecklessPlugin,
    plugin_name: &str,
    git_ref: Option<&String>,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    if rl_plugin.path().exists() {
        let line = format!("{plugin_name} is already installed");
        logger.log(&line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    }

    if let Some(installable) = rl_plugin.manifest().installable {
        if !installable {
            let line =
                format!("{plugin_name} is not reckless-installable according to their manifest");
            logger.log(&line, LogLevel::UNUSUAL).await?;
            return Err(anyhow!(line));
        }
    }

    if rl_plugin.is_local_path() && git_ref.is_some() {
        let line = "git refs are not supported for local paths";
        logger.log(line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    }

    Ok(())
}

pub async fn handle_uninstall(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Uninstall, verbose);

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

    let common_result = match uninstall(plugin.clone(), plugin_name.clone(), &mut logger).await {
        Ok(()) => CommonResult { plugin_name },
        Err(e) => {
            let line = format!("{plugin_name} NOT uninstalled: {e}");
            logger.log(&line, LogLevel::BROKEN).await?;
            return Err(anyhow!(line));
        }
    };

    let response = UninstallResponse::new(common_result, logger);

    Ok(json!(response))
}

async fn uninstall(
    plugin: Plugin<PluginState>,
    plugin_name: String,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let plugin_dir = plugin.state().reckless_dir.join(&plugin_name);

    match read_metadata(&plugin_name, &plugin_dir).await {
        Ok(rl_plugin) => {
            if let Err(e) = disable_plugin(plugin.clone(), &rl_plugin, logger).await {
                let line =
                    format!("{plugin_name} NOT disabled: {e}, remove plugin from config manually!");
                logger.log(&line, LogLevel::BROKEN).await?;
            }
        }
        Err(e) => {
            let line = format!(
                "could not read metadata for {plugin_name}: {e}, you must stop and remove it \
                from the configs yourself"
            );
            logger.log(&line, LogLevel::BROKEN).await?;
        }
    }

    match fs::remove_dir_all(&plugin_dir).await {
        Ok(()) => {
            let line = format!("{plugin_name} uninstalled");
            logger.log(&line, LogLevel::INFO).await?;
        }
        Err(e) => {
            return Err(e.into());
        }
    }

    Ok(())
}
