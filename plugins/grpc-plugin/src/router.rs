use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use cln_plugin::ConfiguredPlugin;

use crate::{PluginState, OPTION_GRPC_HOST, OPTION_GRPC_PORT, OPTION_GRPC_SCHEME};

#[derive(Clone, Debug, PartialEq)]
pub enum GrpcRouterScheme {
    HTTP,
    HTTPS,
}

impl FromStr for GrpcRouterScheme {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http" => Ok(GrpcRouterScheme::HTTP),
            "https" => Ok(GrpcRouterScheme::HTTPS),
            _ => anyhow::bail!("Invalid scheme"),
        }
    }
}

pub struct GrpcRouterConfig {
    pub scheme: GrpcRouterScheme,
    pub host: IpAddr,
    pub port: u16,
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

        let scheme = plugin.option(&OPTION_GRPC_SCHEME).unwrap();
        let scheme = scheme.parse::<GrpcRouterScheme>().with_context(|| {
            format!(
                "Invalid config for {}. The config '{}' is invalid. Use either 'http' or 'https'.",
                OPTION_GRPC_SCHEME.name(),
                scheme
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

        if GrpcRouterScheme::HTTP == scheme && !host.is_loopback() {
            anyhow::bail!("Invalid config: Scheme 'http' is only allowed on a loopback address. Try setting {} to 127.0.0.1",
            OPTION_GRPC_HOST.name());
        }

        Ok(Some(GrpcRouterConfig { scheme, host, port }))
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}
