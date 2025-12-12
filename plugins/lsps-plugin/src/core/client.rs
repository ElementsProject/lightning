use bitcoin::secp256k1::PublicKey;

use crate::{
    core::transport::{self, Transport},
    proto::{
        jsonrpc::{JsonRpcRequest, JsonRpcResponse},
        lsps0::{Lsps0listProtocolsRequest, Lsps0listProtocolsResponse, Msat},
        lsps2::{
            Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest, Lsps2GetInfoResponse,
            OpeningFeeParams,
        },
    },
};

pub struct LspsClient<T: Transport> {
    transport: T,
}

impl<T: Transport> LspsClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

// LSPS0 Implementation
impl<T: Transport> LspsClient<T> {
    pub async fn list_protocols(
        &self,
        peer: &PublicKey,
    ) -> Result<JsonRpcResponse<Lsps0listProtocolsResponse>, transport::Error> {
        self.transport
            .request(peer, &Lsps0listProtocolsRequest {}.into_request())
            .await
    }
}

// LSPS2 Implementation
impl<T: Transport> LspsClient<T> {
    pub async fn get_info(
        &self,
        peer: &PublicKey,
        token: Option<String>,
    ) -> Result<JsonRpcResponse<Lsps2GetInfoResponse>, transport::Error> {
        self.transport
            .request(peer, &Lsps2GetInfoRequest { token }.into_request())
            .await
    }

    pub async fn buy(
        &self,
        peer: &PublicKey,
        opening_fee_params: OpeningFeeParams,
        payment_size_msat: Option<Msat>,
    ) -> Result<JsonRpcResponse<Lsps2BuyResponse>, transport::Error> {
        self.transport
            .request(
                peer,
                &Lsps2BuyRequest {
                    opening_fee_params,
                    payment_size_msat,
                }
                .into_request(),
            )
            .await
    }
}
