use crate::{
    core::{router::JsonRpcRouterBuilder, server::LspsProtocol},
    proto::{
        jsonrpc::RpcError,
        lsps2::{Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest, Lsps2GetInfoResponse},
    },
    register_handler,
};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use std::sync::Arc;

#[async_trait]
pub trait Lsps2Handler: Send + Sync + 'static {
    async fn handle_get_info(
        &self,
        request: Lsps2GetInfoRequest,
    ) -> std::result::Result<Lsps2GetInfoResponse, RpcError>;

    async fn handle_buy(
        &self,
        peer_id: PublicKey,
        request: Lsps2BuyRequest,
    ) -> Result<Lsps2BuyResponse, RpcError>;
}

impl<H> LspsProtocol for Arc<H>
where
    H: Lsps2Handler + Send + Sync + 'static,
{
    fn register_handler(&self, router: &mut JsonRpcRouterBuilder) {
        register_handler!(router, self, "lsps2.get_info", handle_get_info);
        register_handler!(router, self, "lsps2.buy", handle_buy, with_peer);
    }

    fn protocol(&self) -> u8 {
        2
    }
}
