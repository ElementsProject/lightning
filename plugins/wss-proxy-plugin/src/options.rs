use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use cln_plugin::ConfiguredPlugin;
use cln_rpc::{model::requests::ListconfigsRequest, ClnRpc};

pub const OPT_WSS_BIND_ADDR: &str = "wss-bind-addr";
pub const OPT_WSS_CERTS_DIR: &str = "wss-certs";

#[derive(Debug, Clone)]
pub struct WssproxyOptions {
    pub wss_addresses: Vec<SocketAddr>,
    pub wss_domains: Vec<String>,
    pub ws_address: SocketAddr,
    pub certs_dir: PathBuf,
}

pub async fn parse_options(
    plugin: &ConfiguredPlugin<(), tokio::io::Stdin, tokio::io::Stdout>,
) -> Result<WssproxyOptions, anyhow::Error> {
    let wss_address_val = plugin
        .option_str(OPT_WSS_BIND_ADDR)?
        .ok_or_else(|| anyhow!("`{}` option is not configured", OPT_WSS_BIND_ADDR))?;
    let wss_address_str = wss_address_val
        .as_str_arr()
        .ok_or_else(|| anyhow!("{} is not a string array!", OPT_WSS_BIND_ADDR))?;

    let mut wss_domains = Vec::new();
    let mut wss_addresses = Vec::new();
    for addr in wss_address_str.iter() {
        wss_domains.push(
            addr.rsplit_once(':')
                .ok_or_else(|| anyhow!("WSS host missing port. Current Value: {}.", addr))?
                .0
                .to_owned(),
        );
        wss_addresses.extend(addr.to_socket_addrs().map_err(|_| {
            anyhow!(
                "WSS host should be a valid IP or resolvable domain. Current Value: {}.",
                addr
            )
        })?);
    }

    if wss_addresses.is_empty() {
        return Err(anyhow!(
            "WSS host is missing a valid IP or resolvable domain."
        ));
    }

    for socket_addr in wss_addresses.iter() {
        if !validate_port(socket_addr.port()) {
            return Err(anyhow!(
                "WSS port should be a valid available port between 1024 and 65535. \
                Current Value: {}.",
                socket_addr.port()
            ));
        }
    }

    let certs_dir_val = plugin
        .option_str(OPT_WSS_CERTS_DIR)?
        .ok_or_else(|| anyhow!("{} is not set!", OPT_WSS_CERTS_DIR))?;
    let certs_dir_str = certs_dir_val
        .as_str()
        .ok_or_else(|| anyhow!("{} is not a string!", OPT_WSS_CERTS_DIR))?;

    let certs_dir = PathBuf::from(certs_dir_str);

    let mut rpc = ClnRpc::new(
        Path::new(&plugin.configuration().lightning_dir).join(plugin.configuration().rpc_file),
    )
    .await?;

    let ws_addr_config = rpc
        .call_typed(&ListconfigsRequest {
            config: Some("bind-addr".to_string()),
        })
        .await?
        .configs
        .ok_or_else(|| anyhow!("Could not get configs object. CLN version too old?"))?
        .bind_addr;

    let mut ws_address: Option<SocketAddr> = None;
    let ws_address_conf = ws_addr_config.ok_or_else(|| anyhow!("`bind-addr` not set!"))?;
    for addr in ws_address_conf.values_str.iter() {
        if let Some(addr_stripped) = addr.strip_prefix("ws:") {
            let ws_address_ips = addr_stripped.to_socket_addrs().map_err(|_| {
                anyhow!(
                    "`bind-addr` with `ws:` IP should be a valid IP or resolvable domain. \
                    Current Value: {}.",
                    addr_stripped
                )
            })?;
            /* Prefer ipv4 here like connectd does */
            for add in ws_address_ips.into_iter() {
                if add.is_ipv6() && ws_address.is_none() {
                    ws_address = Some(add)
                }
                if add.is_ipv4() {
                    ws_address = Some(add);
                    break;
                }
            }
        }
    }

    let ws_address = ws_address.ok_or_else(|| anyhow!("`bind-addr` with `ws:` not set!"))?;
    if !validate_port(ws_address.port()) {
        return Err(anyhow!(
            "`bind-addr` with `ws` port should be a valid available port \
                between 1024 and 65535. Current Value: {}.",
            ws_address.port()
        ));
    }

    log::debug!("Connecting to ws-server via: {}", ws_address);

    Ok(WssproxyOptions {
        wss_addresses,
        wss_domains,
        ws_address,
        certs_dir,
    })
}

fn validate_port(port: u16) -> bool {
    if (1024..=65535).contains(&port) {
        return true;
    }
    false
}
