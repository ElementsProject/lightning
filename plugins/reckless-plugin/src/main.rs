use std::{path::PathBuf, str::FromStr, sync::Arc};

use clap::{CommandFactory, Parser};
use cln_plugin::{
    Builder, Plugin, RpcMethodBuilder,
    messages::NotificationTopic,
    options::{ConfigOption, StringConfigOption},
};
use cln_rpc::{ClnRpc, model::requests::ListconfigsRequest};
use serde_json::json;
use tokio::sync::Mutex;

use crate::structs::{RecklessArgs, RecklessCmd, SourceCmd};
use crate::{
    cmds::{
        enable::{handle_disable, handle_enable},
        install::{handle_install, handle_uninstall},
        list::{handle_list_available, handle_list_installed},
        source::{handle_source_add, handle_source_list, handle_source_remove},
        tip::handle_tip,
        update::handle_update,
    },
    structs::PluginState,
};

mod cmds;
mod installers;
mod structs;
mod util;

const RECKLESS_DIR: StringConfigOption = ConfigOption::new_str_no_default(
    "reckless-dir",
    "directory where reckless config, git repos and metadata are stored, default to <lightning-dir>/reckless",
);
const RECKLESS_NOTIFICATION: &str = "reckless";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    unsafe {
        std::env::set_var(
            "CLN_PLUGIN_LOG",
            "cln_plugin=info,cln_rpc=info,cln_reckless=trace,warn",
        );
    };

    log_panics::init();

    let github_redir = std::env::var("REDIR_GITHUB").ok();

    let Some(conf_plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("reckless", reckless)
                .description("manage CLN plugins: install, uninstall, and configuration"),
        )
        .notification(NotificationTopic::new(RECKLESS_NOTIFICATION))
        .option(RECKLESS_DIR)
        .dynamic()
        .configure()
        .await?
    else {
        return Ok(());
    };

    let mut lightning_dir = PathBuf::from_str(&conf_plugin.configuration().lightning_dir)?;
    let mut rpc = match ClnRpc::new(lightning_dir.join(conf_plugin.configuration().rpc_file)).await
    {
        Ok(o) => o,
        Err(e) => {
            return conf_plugin
                .disable(&format!("could not establish RPC connection to CLN: {e}"))
                .await;
        }
    };

    let configs_resp = match rpc
        .call_typed(&ListconfigsRequest {
            config: Some("conf".to_owned()),
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            return conf_plugin
                .disable(&format!("could not get listconfigs: {e}"))
                .await;
        }
    };
    let custom_cln_config = configs_resp
        .configs
        .and_then(|c| c.conf)
        .map(|cc| PathBuf::from(cc.value_str));

    let (cln_global_conf, cln_conf, cln_setconfig) = if let Some(custom_config) = custom_cln_config
    {
        let Some(conf_dir) = custom_config.parent() else {
            return conf_plugin
                .disable("`--conf` has no parent directory")
                .await;
        };
        let Some(conf_name) = custom_config.file_name().and_then(|f| f.to_str()) else {
            return conf_plugin.disable("`--conf` has no valid file name").await;
        };
        let setconfig = conf_dir.join(format!("{conf_name}.setconfig"));
        (None, custom_config, setconfig)
    } else {
        let Some(global_dir) = lightning_dir.parent() else {
            return conf_plugin
                .disable("`lightning-dir` has no parent directory")
                .await;
        };
        let global_config = Some(global_dir.join("config"));
        let network_config = lightning_dir.join("config");
        let setconfig_config = lightning_dir.join("config.setconfig");

        (global_config, network_config, setconfig_config)
    };

    lightning_dir.pop();

    let reckless_dir = conf_plugin
        .option(&RECKLESS_DIR)?
        .map_or_else(|| lightning_dir.join("reckless"), PathBuf::from);

    let reckless_conf = reckless_dir.join(format!(
        "{}-reckless.conf",
        conf_plugin.configuration().network
    ));

    let state = PluginState {
        reckless_dir,
        cln_conf,
        cln_global_conf,
        cln_setconfig,
        reckless_conf,
        github_redir,
        rpc: Arc::new(Mutex::new(rpc)),
    };
    let plugin = conf_plugin.start(state).await?;

    plugin.join().await
}

async fn reckless(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let gather_args = structs::json_to_argv(&args)?;

    let parsed = match RecklessArgs::try_parse_from(gather_args) {
        Ok(p) => p,
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(
                serde_json::json!({ "format-hint": "simple","result": e.render().to_string() }),
            );
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "{}",
                e.render().to_string().replace('\n', " ")
            ));
        }
    };

    match parsed.command {
        Some(RecklessCmd::Install(args)) => {
            handle_install(plugin.clone(), args, parsed.verbose).await
        }
        Some(RecklessCmd::Uninstall(args)) => {
            handle_uninstall(plugin.clone(), args.target, parsed.verbose).await
        }
        Some(RecklessCmd::Listavailable(args)) => {
            handle_list_available(plugin.clone(), args.target, parsed.verbose).await
        }
        Some(RecklessCmd::Enable(args)) => {
            handle_enable(plugin.clone(), args, parsed.verbose).await
        }
        Some(RecklessCmd::Disable(args)) => {
            handle_disable(plugin.clone(), args.target, parsed.verbose).await
        }
        Some(RecklessCmd::Source(args)) => match args.subcommand {
            SourceCmd::List => handle_source_list(plugin.clone(), parsed.verbose).await,
            SourceCmd::Add(t) => handle_source_add(plugin.clone(), t.target, parsed.verbose).await,
            SourceCmd::Remove(t) => {
                handle_source_remove(plugin.clone(), t.target, parsed.verbose).await
            }
        },
        Some(RecklessCmd::Update(args)) => {
            handle_update(plugin.clone(), args, parsed.verbose).await
        }
        Some(RecklessCmd::Listinstalled) => {
            handle_list_installed(plugin.clone(), parsed.verbose).await
        }
        Some(RecklessCmd::Tip(args)) => handle_tip(plugin.clone(), args, parsed.verbose).await,
        None => Ok(json!({
            "format-hint": "simple",
            "result": RecklessArgs::command().render_help().to_string()
        })),
    }
}
