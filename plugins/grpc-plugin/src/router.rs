use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{PluginState, OPTION_GRPC_IP, OPTION_GRPC_PORT};

use cln_plugin::ConfiguredPlugin;
pub struct GrpcRouterConfig {
    ip: IpAddr,
    port: u16,
}

impl GrpcRouterConfig {
    pub fn from_configured_plugin<I, O>(
        plugin: &ConfiguredPlugin<PluginState, I, O>,
    ) -> anyhow::Result<Option<Self>>
    where
        I: AsyncRead + Send + Unpin + 'static,
        O: AsyncWrite + Send + Unpin + 'static,
    {
        let port = match plugin.option(&OPTION_GRPC_PORT).unwrap() {
            None => return Ok(None),
            Some(port) => u16::try_from(port).with_context(|| {
                format!(
                    "Invalid configuration for {}. The value {} is out-of-bounds.",
                    OPTION_GRPC_PORT.name(),
                    port
                )
            })?,
        };

        let ip = plugin.option(&OPTION_GRPC_IP)?;
        let ip = ip.parse::<IpAddr>().with_context(|| {
            format!(
                "Invalid configuration for {}. '{}' is not a valid ip-address.",
                OPTION_GRPC_IP.name(),
                ip
            )
        })?;

        Ok(Some(GrpcRouterConfig { ip, port }))
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}
