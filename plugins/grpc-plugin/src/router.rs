use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{PluginState, OPTION_GRPC_HOST, OPTION_GRPC_PORT};

use cln_plugin::ConfiguredPlugin;
pub struct GrpcRouterConfig {
    host: IpAddr,
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
        let port = plugin.option(&OPTION_GRPC_PORT).unwrap();
        let port = u16::try_from(port).with_context(|| {
            format!(
                "Invalid config for {}. The value {} is out-of-bounds.",
                OPTION_GRPC_PORT.name(),
                port
            )
        })?;        

        let host = plugin.option(&OPTION_GRPC_HOST).unwrap();
        let host = host.parse::<IpAddr>().with_context(|| {
            format!(
                "Invalid config for {}. '{}' is not a valid ip-address.",
                OPTION_GRPC_HOST.name(),
                host
            )
        })?;

        Ok(Some(GrpcRouterConfig { host, port }))
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}
