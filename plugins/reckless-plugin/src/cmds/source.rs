use std::str::FromStr;

use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use url::Url;

use crate::{
    structs::{PluginOrigin, PluginState, RecklessLogger, RecklessTopic, SourcesResponse},
    util::{init_plugin_repo, read_sources_file, repo_path_from_url},
};

pub async fn handle_source_list(
    plugin: Plugin<PluginState>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);

    let (sources, _source_file) = match read_sources_file(&plugin).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    let response = SourcesResponse::new(sources, logger);

    Ok(json!(response))
}

pub async fn handle_source_add(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Source, verbose);

    let (mut sources, source_file) = match read_sources_file(&plugin).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    let mut file_handle = match OpenOptions::new().append(true).open(source_file).await {
        Ok(f) => f,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(anyhow!(e));
        }
    };

    let add_source = PluginOrigin::new(&target)?;

    for source in &sources {
        if source == &add_source {
            let line = format!("source {target} already exists");
            logger.log(&line, LogLevel::UNUSUAL).await?;
            return Err(anyhow!(line));
        }
    }

    if let PluginOrigin::Url(url_str) = &add_source {
        let url = Url::from_str(url_str)?;
        init_plugin_repo(&plugin, url, &mut logger).await?;
    }

    if let Err(e) = file_handle
        .write_all(format!("{add_source}\n").as_bytes())
        .await
    {
        logger.log(&e.to_string(), LogLevel::BROKEN).await?;
        return Err(anyhow!(e));
    }

    sources.push(add_source);

    let response = SourcesResponse::new(sources, logger);

    Ok(json!(response))
}

pub async fn handle_source_remove(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Source, verbose);

    let (mut sources, source_file) = match read_sources_file(&plugin).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    let del_source = PluginOrigin::new(&target)?;

    match remove_source(&plugin, &del_source, &mut logger).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    }

    let Ok(mut file_handle) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&source_file)
        .await
    else {
        let line = format!("failed to open sources file: {}", source_file.display());
        logger.log(&line, LogLevel::BROKEN).await?;
        return Err(anyhow!(line));
    };

    let mut remove_index = None;

    for (i, source) in sources.iter().enumerate() {
        if source == &del_source {
            remove_index = Some(i);
        } else if let Err(e) = file_handle
            .write_all(format!("{source}\n").as_bytes())
            .await
        {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(anyhow!(e));
        }
    }

    if let Some(i) = remove_index {
        sources.remove(i);
    } else {
        return Err(anyhow!("source {target} not found"));
    }

    let response = SourcesResponse::new(sources, logger);

    Ok(json!(response))
}

async fn remove_source(
    plugin: &Plugin<PluginState>,
    target: &PluginOrigin,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    match target {
        PluginOrigin::LocalPath(_path) => {}
        PluginOrigin::Url(url_str) => {
            let url = Url::from_str(url_str)?;
            let repo_dir = plugin.state().reckless_dir.join(repo_path_from_url(&url)?);
            if !repo_dir.exists() {
                let line = format!("source directory never existed: {}", repo_dir.display());
                logger.log(&line, LogLevel::INFO).await?;
                return Ok(());
            }
            match fs::remove_dir_all(&repo_dir).await {
                Ok(()) => {
                    let line = format!("source directory removed: {}", repo_dir.display());
                    logger.log(&line, LogLevel::INFO).await?;
                }
                Err(e) => {
                    let line = format!(
                        "failed to remove source directory: {}: {}",
                        repo_dir.display(),
                        e
                    );
                    return Err(anyhow!(line));
                }
            }

            let owner_dir = repo_dir
                .parent()
                .ok_or_else(|| anyhow!("source repo has no owner directory"))?;

            match fs::read_dir(&owner_dir).await {
                Ok(mut entries) => {
                    if entries.next_entry().await?.is_none() {
                        let line = format!(
                            "also removing empty repository owner directory: {}",
                            owner_dir.display()
                        );
                        logger.log(&line, LogLevel::INFO).await?;
                        fs::remove_dir_all(owner_dir).await?;
                    }
                }
                Err(e) => {
                    let line = format!(
                        "could not read repository owner directory: {} {e}",
                        owner_dir.display()
                    );
                    logger.log(&line, LogLevel::UNUSUAL).await?;
                }
            }
        }
    }

    Ok(())
}
