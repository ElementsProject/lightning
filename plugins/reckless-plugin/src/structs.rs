use std::{
    collections::HashSet,
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Error, anyhow};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use cln_plugin::{Plugin, options};
use cln_rpc::{ClnRpc, notifications::LogLevel};
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use tokio::sync::Mutex;
use url::Url;

use crate::{RECKLESS_NOTIFICATION, util::validate_path};

#[derive(Clone)]
pub struct PluginState {
    pub reckless_dir: PathBuf,
    pub cln_conf: PathBuf,
    pub cln_global_conf: Option<PathBuf>,
    pub cln_setconfig: PathBuf,
    pub reckless_conf: PathBuf,
    pub github_redir: Option<String>,
    pub rpc: Arc<Mutex<ClnRpc>>,
}
impl PluginState {
    pub fn get_cln_configs(&self) -> Vec<&Path> {
        if let Some(cln_global) = self.cln_global_conf.as_ref() {
            return vec![cln_global, &self.cln_conf, &self.cln_setconfig];
        }

        vec![&self.cln_conf, &self.cln_setconfig]
    }
}

pub struct RecklessLogger<'a> {
    plugin: &'a Plugin<PluginState>,
    log: Vec<String>,
    topic: RecklessTopic,
    verbose: bool,
}
impl<'a> RecklessLogger<'a> {
    pub fn new(plugin: &'a Plugin<PluginState>, topic: RecklessTopic, verbose: bool) -> Self {
        Self {
            plugin,
            log: Vec::new(),
            topic,
            verbose,
        }
    }
    pub async fn log(&mut self, line: &str, log_level: LogLevel) -> Result<(), anyhow::Error> {
        if !self.verbose
            && (log_level == LogLevel::IO
                || log_level == LogLevel::TRACE
                || log_level == LogLevel::DEBUG)
        {
            return Ok(());
        }
        for line in line.split('\n') {
            match log_level {
                LogLevel::IO => {
                    self.log.push(format!("IO: {line}"));
                    log::trace!("{line}");
                }
                LogLevel::TRACE => {
                    self.log.push(format!("TRACE: {line}"));
                    log::trace!("{line}");
                }
                LogLevel::DEBUG => {
                    self.log.push(format!("DEBUG: {line}"));
                    log::debug!("{line}");
                }
                LogLevel::INFO => {
                    self.log.push(format!("INFO: {line}"));
                    log::info!("{line}");
                }
                LogLevel::UNUSUAL => {
                    self.log.push(format!("WARNING: {line}"));
                    log::warn!("{line}");
                }
                LogLevel::BROKEN => {
                    self.log.push(format!("ERROR: {line}"));
                    log::error!("{line}");
                }
            }

            if let RecklessTopic::Install = self.topic {
                self.plugin
                    .send_custom_notification(
                        RECKLESS_NOTIFICATION.to_owned(),
                        json!({"level": log_level, "log": line}),
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

#[derive(Parser, Debug, Deserialize, PartialEq)]
#[command(name = "reckless", no_binary_name = true, disable_help_flag = true)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecklessArgs {
    #[arg(short = 'v', long, default_value_t = false, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<RecklessCmd>,
}

#[derive(Subcommand, Debug, Deserialize, PartialEq)]
pub enum RecklessCmd {
    /// Search for and install a plugin, then test and activate
    Install(InstallArgs),

    /// Deactivate a plugin and remove it from the directory
    Uninstall(TargetArgs),

    /// List plugins available from the sources list
    Listavailable(ListArgs),

    /// Dynamically enable a plugin and update config
    Enable(EnableArgs),

    /// Disable a plugin, remove it from the config, but keep the plugin files
    Disable(TargetArgs),

    /// Manage plugin search sources
    Source(SourceArgs),

    /// Update plugins to latest version
    Update(UpdateArgs),

    /// List reckless-installed plugins
    Listinstalled,

    /// Tip a plugin author
    Tip(TipArgs),
}

/// Shared args for commands that take one or more plugin name targets
#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct TargetArgs {
    pub target: String,
}

#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct ListArgs {
    pub target: Option<String>,
}

/// `reckless source <subcommand>`
#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct SourceArgs {
    #[command(subcommand)]
    pub subcommand: SourceCmd,
}

#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct InstallArgs {
    #[arg(help = "name of plugin to install")]
    pub target: String,

    #[arg(long, help = "build plugins in debug mode and keep build files")]
    pub developer: bool,

    #[arg(value_parser = parse_key_val)]
    pub options: Vec<(String, Option<String>)>,
}

#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct UpdateArgs {
    #[arg(help = "name of plugin to update, leave empty to update all installed plugins")]
    pub target: Option<String>,

    #[arg(long, help = "build plugins in debug mode and keep build files")]
    pub developer: bool,

    #[arg(value_parser = parse_key_val)]
    pub options: Vec<(String, Option<String>)>,
}

#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct EnableArgs {
    #[arg(help = "name of plugin to install")]
    pub target: String,

    #[arg(value_parser = parse_key_val)]
    pub options: Vec<(String, Option<String>)>,
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_key_val(s: &str) -> Result<(String, Option<String>), String> {
    if let Some((k, v)) = s.split_once('=') {
        Ok((k.to_owned(), Some(v.to_owned())))
    } else {
        Ok((s.to_owned(), None))
    }
}

#[derive(Args, Debug, Deserialize, PartialEq)]
pub struct TipArgs {
    #[arg(help = "plugin name which author to tip")]
    pub target: String,

    #[arg(help = "tip amount in msat")]
    pub amount_msat: u64,

    #[arg(help = "tip message")]
    pub payer_note: Option<String>,
}

#[derive(Subcommand, Debug, Deserialize, PartialEq)]
pub enum SourceCmd {
    /// List available plugin sources
    List,

    /// Add a source repository
    Add(TargetArgs),

    /// Remove a plugin source repository
    #[command(aliases = ["rem", "rm"])]
    Remove(TargetArgs),
}

pub fn json_to_argv(value: &serde_json::Value) -> Result<Vec<String>, Error> {
    match value {
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => Ok(s.clone()),
                other => Ok(other.to_string()),
            })
            .collect(),
        serde_json::Value::Object(obj) => {
            fn get_flag<'a>(
                key: &'a str,
                obj: &serde_json::Map<String, serde_json::Value>,
                remaining: &mut std::collections::HashSet<&'a str>,
            ) -> Result<bool, Error> {
                remaining.remove(key);
                match obj.get(key) {
                    None => Ok(false),
                    Some(serde_json::Value::Bool(b)) => Ok(*b),
                    Some(other) => Err(anyhow!("\"{key}\" must be a boolean, got: {other}")),
                }
            }

            let mut argv: Vec<String> = Vec::new();
            let mut remaining: HashSet<&str> = obj.keys().map(String::as_str).collect();

            if get_flag("verbose", obj, &mut remaining)? {
                argv.push("-v".to_owned());
            }

            remaining.remove("command");
            let command = obj
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("object form requires a `command` field"))?;
            argv.push(command.to_owned());

            if let Some(sc) = obj.get("subcommand") {
                if !command.eq_ignore_ascii_case("source") {
                    return Err(anyhow!("`subcommand` only valid if `command` is `source`"));
                }
                remaining.remove("subcommand");
                argv.push(
                    sc.as_str()
                        .ok_or_else(|| anyhow!("`subcommand` must be a string"))?
                        .to_owned(),
                );
            }

            if get_flag("developer", obj, &mut remaining)? {
                argv.push("--developer".to_owned());
            }

            for key in ["target", "amount_msat", "payer_note"] {
                remaining.remove(key);
                match obj.get(key) {
                    Some(serde_json::Value::String(s)) => argv.push(s.clone()),
                    Some(other) => argv.push(other.to_string()),
                    None => {}
                }
            }

            if let Some(serde_json::Value::Array(opts)) = obj.get("options") {
                remaining.remove("options");
                for opt in opts {
                    match opt {
                        serde_json::Value::String(s) => argv.push(s.clone()),
                        _ => return Err(anyhow!("{opt} must be a string")),
                    }
                }
            }

            if !remaining.is_empty() {
                let mut unknown: Vec<&str> = remaining.into_iter().collect();
                unknown.sort_unstable();
                return Err(anyhow!("unknown fields: {}", unknown.join(", ")));
            }

            Ok(argv)
        }
        _ => Err(anyhow!("expected array or object")),
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum Installer {
    PythonUv,
    PythonUvShebang,
    PythonUvLegacy,
    PoetryVenv,
    PyprojectViaPip,
    Python,
    Nodejs,
    Rust,
    Go,
    Custom,
}

#[derive(Debug, Clone, Copy)]
pub enum RecklessTopic {
    Install,
    Search,
    Enable,
    Source,
    Tip,
}

#[derive(Deserialize, Default, Debug)]
pub struct GetManifestResponse {
    pub options: Vec<UntypedConfigOption>,
    pub dynamic: Option<bool>,
}
impl GetManifestResponse {
    pub fn is_dynamic(&self) -> bool {
        self.dynamic.unwrap_or(false)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct UntypedConfigOption {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: options::ValueType,
    // pub default: Option<options::Value>,
    // pub description: String,
    // pub deprecated: Option<bool>,
    // pub dynamic: Option<bool>,
    pub multi: Option<bool>,
}
impl UntypedConfigOption {
    // pub fn is_dynamic(&self) -> bool {
    //     self.dynamic.unwrap_or(false)
    // }
    pub fn is_multi(&self) -> bool {
        self.multi.unwrap_or(false)
    }
    // pub fn is_deprecated(&self) -> bool {
    //     self.deprecated.unwrap_or(false)
    // }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct RecklessManifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<PathBuf>,
    // TODO check for dependencies
    #[serde(skip_serializing_if = "option_vec_is_empty")]
    pub dependencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "option_vec_is_empty")]
    pub install_cmd: Option<Vec<String>>,
    #[serde(skip_serializing_if = "option_vec_is_empty")]
    pub required_options: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installable: Option<bool>,
}
impl RecklessManifest {
    pub fn entry_filename(&self) -> Result<&Path, anyhow::Error> {
        Ok(Path::new(
            self.entrypoint
                .as_ref()
                .ok_or_else(|| anyhow!("no entrypoint found"))?
                .file_name()
                .ok_or_else(|| anyhow!("entrypoint has no filename"))?,
        ))
    }
    pub fn entry_filename_str(&self) -> Result<String, anyhow::Error> {
        Ok(self
            .entry_filename()?
            .to_str()
            .ok_or_else(|| anyhow!("entry filename contains invalid utf-8"))?
            .to_owned())
    }
}

#[allow(clippy::ref_option)]
fn option_vec_is_empty<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_none_or(Vec::is_empty)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum PluginOrigin {
    LocalPath(PathBuf),
    Url(String),
}
impl Display for PluginOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginOrigin::LocalPath(path) => write!(f, "{}", path.display()),
            PluginOrigin::Url(url) => write!(f, "{url}"),
        }
    }
}
impl PluginOrigin {
    pub fn new(original_source: &str) -> Result<Self, anyhow::Error> {
        match Url::parse(original_source) {
            Ok(url) => {
                if matches!(url.scheme(), "http" | "https") {
                    Ok(PluginOrigin::Url(original_source.to_owned()))
                } else {
                    Err(anyhow!(
                        "only http/https are supported for remote git \
                        repositories: {original_source}"
                    ))
                }
            }
            _ => Ok(PluginOrigin::LocalPath(validate_path(original_source)?)),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecklessPlugin {
    plugin_name: String,
    /// URL or path where we got the plugin from, e.g.
    /// <https://github.com/lightningd/plugins>
    origin: PluginOrigin,
    /// path that to the overall repo
    /// e.g. lightningd/plugins
    origin_repo_path: PathBuf,
    /// we might need to traverse deeper into a repo to find the plugin path
    /// e.g. lightningd/plugins/summary
    origin_plugin_path: PathBuf,
    /// always ``reckless_dir/<plugin_name>``
    path: PathBuf,
    /// if origin is a remote git repo it is ``reckless_dir/<plugin_name>/source/<plugin_name>``
    /// if it's from a local path it is just that
    source_path: PathBuf,
    metadata: Metadata,
    installer: Installer,
    manifest: RecklessManifest,
}
impl PartialEq for RecklessPlugin {
    fn eq(&self, other: &Self) -> bool {
        self.plugin_name == other.plugin_name
            && self.origin == other.origin
            && self.origin_plugin_path == other.origin_plugin_path
            && self.origin_repo_path == other.origin_repo_path
            && self.path == other.path
    }
}
impl RecklessPlugin {
    pub fn new(
        origin: PluginOrigin,
        origin_plugin_path: PathBuf,
        origin_repo_path: PathBuf,
        name: String,
        reckless_dir: &Path,
        installer: Installer,
        manifest: RecklessManifest,
    ) -> Self {
        let source_path = match origin {
            PluginOrigin::LocalPath(_) => origin_plugin_path.clone(),
            PluginOrigin::Url(_) => reckless_dir.join(&name).join("source").join(&name),
        };
        RecklessPlugin {
            path: reckless_dir.join(&name),
            plugin_name: name,
            metadata: Metadata::new(origin.clone()),
            origin,
            origin_plugin_path,
            origin_repo_path,
            source_path,
            installer,
            manifest,
        }
    }
    pub fn name(&self) -> &str {
        &self.plugin_name
    }
    pub fn origin(&self) -> &PluginOrigin {
        &self.origin
    }
    pub fn origin_plugin_path(&self) -> &PathBuf {
        &self.origin_plugin_path
    }
    pub fn origin_repo_path(&self) -> &PathBuf {
        &self.origin_repo_path
    }
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
    pub fn source_path(&self) -> &PathBuf {
        &self.source_path
    }
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }
    pub fn is_local_path(&self) -> bool {
        matches!(self.origin, PluginOrigin::LocalPath(_))
    }
    pub fn installer(&self) -> &Installer {
        &self.installer
    }
    pub fn manifest(&self) -> &RecklessManifest {
        &self.manifest
    }
    pub fn get_entrypath(&self) -> Result<PathBuf, anyhow::Error> {
        Ok(self.path().join(self.manifest().entry_filename()?))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Metadata {
    installation_date: String,
    installation_time: u64,
    original_source: PluginOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_commit: Option<String>,
}
impl Metadata {
    pub fn new(original_source: PluginOrigin) -> Metadata {
        Metadata {
            installation_date: Utc::now().date_naive().to_string(),
            installation_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            original_source,
            requested_commit: None,
            installed_commit: None,
        }
    }
    pub fn new_install(
        &mut self,
        installed_commit: Option<String>,
        requested_commit: Option<String>,
    ) {
        self.installation_date = Utc::now().date_naive().to_string();
        self.installation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.requested_commit = requested_commit;
        self.installed_commit = installed_commit;
    }
    pub fn requested_commit(&self) -> Option<&str> {
        self.requested_commit.as_deref()
    }
    pub fn installed_commit(&self) -> Option<&str> {
        self.installed_commit.as_deref()
    }
}

#[derive(Debug)]
pub struct RpcResult {
    result: Vec<Map<String, serde_json::Value>>,
}
impl RpcResult {
    pub fn new() -> RpcResult {
        RpcResult { result: Vec::new() }
    }
    pub fn push<T: Serialize>(&mut self, value: T) -> serde_json::Result<()> {
        match serde_json::to_value(value)? {
            serde_json::Value::Object(obj) => {
                self.result.push(obj);
                Ok(())
            }
            _ => Err(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expected JSON object",
            ))),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.result.is_empty()
    }
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    result: Vec<Map<String, serde_json::Value>>,
    log: Vec<String>,
}
impl RpcResponse {
    pub fn new(result: RpcResult, logger: RecklessLogger) -> RpcResponse {
        RpcResponse {
            result: result.result,
            log: logger.log,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InstallResponse {
    pub plugin_name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_commit: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TargetResponse {
    pub plugin_name: String,
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde_json::json;

    use crate::structs::{
        EnableArgs, InstallArgs, RecklessArgs, RecklessCmd, SourceArgs, SourceCmd, TargetArgs,
        TipArgs, json_to_argv,
    };

    #[test]
    fn test_object_input() {
        let enable = json!({
            "command": "enable",
            "target": "plugin_name",
            "verbose": true
        });
        let argv = json_to_argv(&enable).unwrap();
        let rl_args = RecklessArgs::try_parse_from(argv).unwrap();
        assert_eq!(
            rl_args,
            RecklessArgs {
                verbose: true,
                command: Some(RecklessCmd::Enable(EnableArgs {
                    target: "plugin_name".to_owned(),
                    options: vec![]
                }))
            }
        );

        let enable_opts = json!({
            "command": "enable",
            "target": "plugin_name",
            "options": ["test-option=value"]
        });
        let argv = json_to_argv(&enable_opts).unwrap();
        let rl_args = RecklessArgs::try_parse_from(argv).unwrap();
        assert_eq!(
            rl_args,
            RecklessArgs {
                verbose: false,
                command: Some(RecklessCmd::Enable(EnableArgs {
                    target: "plugin_name".to_owned(),
                    options: vec![("test-option".to_owned(), Some("value".to_owned()))]
                }))
            }
        );

        let install = json!({
            "command": "install",
            "target": "plugin_name",
            "options": ["test-option=value"],
            "verbose": true,
            "developer": true
        });
        let argv = json_to_argv(&install).unwrap();
        let rl_args = RecklessArgs::try_parse_from(argv).unwrap();
        assert_eq!(
            rl_args,
            RecklessArgs {
                verbose: true,
                command: Some(RecklessCmd::Install(InstallArgs {
                    target: "plugin_name".to_owned(),
                    developer: true,
                    options: vec![("test-option".to_owned(), Some("value".to_owned()))]
                }))
            }
        );

        let source = json!({
            "command": "source",
            "subcommand": "add",
            "target": "plugin_name",
            "verbose": true
        });
        let argv = json_to_argv(&source).unwrap();
        let rl_args = RecklessArgs::try_parse_from(argv).unwrap();
        assert_eq!(
            rl_args,
            RecklessArgs {
                verbose: true,
                command: Some(RecklessCmd::Source(SourceArgs {
                    subcommand: SourceCmd::Add(TargetArgs {
                        target: "plugin_name".to_owned()
                    })
                }))
            }
        );

        let tip = json!({
            "command": "tip",
            "target": "offer1",
            "amount_msat": 1000,
            "payer_note": "test note",
            "verbose": true
        });
        let argv = json_to_argv(&tip).unwrap();
        let rl_args = RecklessArgs::try_parse_from(argv).unwrap();
        assert_eq!(
            rl_args,
            RecklessArgs {
                verbose: true,
                command: Some(RecklessCmd::Tip(TipArgs {
                    target: "offer1".to_owned(),
                    amount_msat: 1000,
                    payer_note: Some("test note".to_owned())
                }))
            }
        );
    }

    #[test]
    fn test_object_invalid() {
        let typo = json!({
            "commnd": "enable",
            "target": "plugin_name",
            "verbose": true
        });
        assert!(json_to_argv(&typo).is_err());

        let extra = json!({
            "command": "enable",
            "target": "plugin_name",
            "verbose": true,
            "invalid": "none",
        });
        assert!(json_to_argv(&extra).is_err());
    }
}
