use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{PluginState, OPTION_GRPC_PORT};

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

        Ok(Some(GrpcRouterConfig {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }))
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}
