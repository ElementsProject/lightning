use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;
use tokio::process::Command;

use crate::{
    cmds::{
        enable::{disable_plugin, enable_plugin},
        list::list_installed,
    },
    installers::{
        install_custom_plugin, install_go_plugin, install_nodejs_plugin, install_poetry_plugin,
        install_python_plugin, install_rust_plugin, install_uv_legacy_plugin, install_uv_plugin,
        install_uv_shebang_plugin,
    },
    structs::{
        InstallResult, Installer, PluginState, RecklessLogger, RecklessPlugin, RecklessTopic,
        UpdateArgs, UpdateResponse,
    },
    util::{
        copy_dir_all, parse_target, read_metadata, run_logged_command, search_sources,
        write_metadata,
    },
};

#[allow(clippy::too_many_lines)]
pub async fn handle_update(
    plugin: Plugin<PluginState>,
    install_args: UpdateArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Install, verbose);
    let mut update_results = Vec::new();

    let mut ignore_pinned = false;

    let targets = gather_update_targets(
        plugin.clone(),
        &install_args,
        &mut ignore_pinned,
        &mut logger,
    )
    .await?;

    for target in targets {
        let (plugin_name, git_ref) = match parse_target(&target) {
            Ok(o) => o,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
                return Err(e);
            }
        };
        let mut search_results =
            match search_sources(&plugin, Some(plugin_name.clone()), &mut logger).await {
                Ok(o) => o,
                Err(e) => {
                    logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                    continue;
                }
            };
        let Some(new_rl_plugin) = search_results.get_mut(&plugin_name) else {
            let line = format!("{plugin_name} not found in any known sources");
            logger.log(&line, LogLevel::UNUSUAL).await?;
            continue;
        };

        let plugin_dir = plugin.state().reckless_dir.join(&plugin_name);

        let old_rl_plugin = match read_metadata(&plugin_name, &plugin_dir).await {
            Ok(o) => o,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                continue;
            }
        };

        if let Err(e) = check_upgradeable(&old_rl_plugin, new_rl_plugin, ignore_pinned) {
            let line = format!("{plugin_name} is not upgradeable: {e}");
            logger.log(&line, LogLevel::UNUSUAL).await?;
            continue;
        }

        let old_options = match disable_plugin(plugin.clone(), &old_rl_plugin, &mut logger).await {
            Ok(o) => o,
            Err(e) => {
                let line = format!(
                    "Disabling {} before update failed. \
                    It might be in an inconsistent state: {e}",
                    old_rl_plugin.name()
                );
                logger.log(&line, LogLevel::BROKEN).await?;
                continue;
            }
        };

        let update_result = update(
            git_ref.clone(),
            old_rl_plugin,
            new_rl_plugin,
            &mut logger,
            install_args.developer,
        )
        .await;

        let mut install_result = InstallResult {
            plugin_name: plugin_name.clone(),
            enabled: false,
            installed_commit: new_rl_plugin
                .metadata()
                .installed_commit()
                .map(std::borrow::ToOwned::to_owned),
        };

        match update_result {
            Ok(()) => {
                match enable_plugin(plugin.clone(), new_rl_plugin, old_options, &mut logger).await {
                    Ok(()) => {
                        install_result.enabled = true;
                    }
                    Err(e) => {
                        let line =
                            format!("Enabling {} after update failed: {e}", new_rl_plugin.name());
                        logger.log(&line, LogLevel::BROKEN).await?;
                    }
                }
                update_results.push(install_result);
            }
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                if let Some(deps) = &new_rl_plugin.manifest().dependencies {
                    let line = format!(
                        "Make sure you have the following system dependencies installed: {}",
                        deps.join(", ")
                    );
                    logger.log(&line, LogLevel::UNUSUAL).await?;
                }
            }
        }
    }

    if update_results.is_empty() {
        let line = "No updates succeeded";
        logger.log(line, LogLevel::BROKEN).await?;
        return Err(anyhow!(line));
    }

    let response = UpdateResponse::new(update_results, logger);

    Ok(json!(response))
}

fn check_upgradeable(
    old_rl_plugin: &RecklessPlugin,
    new_rl_plugin: &RecklessPlugin,
    ignore_pinned: bool,
) -> Result<(), anyhow::Error> {
    if old_rl_plugin.metadata().requested_commit().is_some() && !ignore_pinned {
        return Err(anyhow!("version-pinned plugin: {}", old_rl_plugin.name()));
    }

    if !new_rl_plugin.origin_plugin_path().exists() {
        return Err(anyhow!(
            "repo does not exist: {}",
            new_rl_plugin.origin_repo_path().display()
        ));
    }

    if let Some(installable) = new_rl_plugin.manifest().installable {
        if !installable {
            return Err(anyhow!(
                "{} is not reckless-installable according to their manifest",
                new_rl_plugin.name()
            ));
        }
    }
    Ok(())
}

async fn gather_update_targets(
    plugin: Plugin<PluginState>,
    install_args: &UpdateArgs,
    ignore_pinned: &mut bool,
    logger: &mut RecklessLogger<'_>,
) -> Result<Vec<String>, anyhow::Error> {
    if let Some(target) = &install_args.target {
        *ignore_pinned = true;
        Ok(vec![target.clone()])
    } else {
        let listinstalled = match list_installed(plugin).await {
            Ok(o) => o,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(e);
            }
        };
        let mut targets = Vec::new();
        for (name, _) in listinstalled {
            targets.push(name);
        }
        Ok(targets)
    }
}

async fn update(
    git_ref: Option<String>,
    old_rl_plugin: RecklessPlugin,
    new_rl_plugin: &mut RecklessPlugin,
    logger: &mut RecklessLogger<'_>,
    developer: bool,
) -> Result<(), anyhow::Error> {
    if !new_rl_plugin.is_local_path() {
        let mut command = Command::new("git");
        command
            .args(["pull", "--ff-only"])
            .current_dir(new_rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["submodule", "sync", "--recursive"])
            .current_dir(new_rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["submodule", "update", "--init", "--recursive"])
            .current_dir(new_rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["checkout", git_ref.as_ref().unwrap_or(&"HEAD".to_owned())])
            .current_dir(new_rl_plugin.origin_plugin_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["rev-parse", "HEAD"])
            .current_dir(new_rl_plugin.origin_plugin_path());
        let commit_hash = run_logged_command(command, logger).await?;

        let ref_to_be_installed = if let Some(gr) = &git_ref {
            gr.clone()
        } else {
            commit_hash
        };

        if let Some(installed_commit) = old_rl_plugin.metadata().installed_commit() {
            if installed_commit == ref_to_be_installed {
                let line = format!(
                    "{} is already on the latest version: {ref_to_be_installed}",
                    old_rl_plugin.name()
                );
                logger.log(&line, LogLevel::INFO).await?;
                return Ok(());
            }
        } else {
            let line = format!(
                "{} should have a git ref for the current install",
                old_rl_plugin.name()
            );
            logger.log(&line, LogLevel::UNUSUAL).await?;
        }

        let line = format!(
            "updating {} from {} to {ref_to_be_installed}",
            old_rl_plugin.name(),
            old_rl_plugin.metadata().installed_commit().unwrap()
        );
        logger.log(&line, LogLevel::INFO).await?;

        copy_dir_all(
            new_rl_plugin.origin_plugin_path(),
            new_rl_plugin.source_path(),
            logger,
        )
        .await?;
    }

    let entrypoint = match new_rl_plugin.installer() {
        Installer::PythonUv => install_uv_plugin(new_rl_plugin, logger).await?,
        Installer::PythonUvShebang => install_uv_shebang_plugin(new_rl_plugin, logger).await?,
        Installer::PythonUvLegacy => install_uv_legacy_plugin(new_rl_plugin, logger).await?,
        Installer::PoetryVenv => install_poetry_plugin(new_rl_plugin, logger).await?,
        Installer::PyprojectViaPip | Installer::Python => {
            install_python_plugin(new_rl_plugin, logger).await?
        }
        Installer::Nodejs => install_nodejs_plugin(new_rl_plugin, logger).await?,
        Installer::Rust => install_rust_plugin(new_rl_plugin, logger, developer).await?,
        Installer::Go => install_go_plugin(new_rl_plugin, logger).await?,
        Installer::Custom => install_custom_plugin(new_rl_plugin, logger).await?,
    };

    if new_rl_plugin.is_local_path() {
        new_rl_plugin.metadata_mut().new_install(None, None);
    } else {
        let mut command = Command::new("git");
        command
            .args(["rev-parse", "HEAD"])
            .current_dir(new_rl_plugin.origin_plugin_path());
        let commit_hash = run_logged_command(command, logger).await?;

        let installed_ref = if let Some(gr) = &git_ref {
            gr.clone()
        } else {
            commit_hash
        };

        new_rl_plugin
            .metadata_mut()
            .new_install(Some(installed_ref), git_ref);
    }

    write_metadata(new_rl_plugin).await?;

    let line = format!("plugin updated: {}", entrypoint.display());
    logger.log(&line, LogLevel::INFO).await?;

    Ok(())
}
