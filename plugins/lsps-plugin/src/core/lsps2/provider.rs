use anyhow::Result;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;

use crate::proto::{
    lsps0::{Msat, ShortChannelId},
    lsps2::{
        DatastoreEntry, Lsps2PolicyBuyRequest, Lsps2PolicyBuyResponse, Lsps2PolicyGetInfoRequest,
        Lsps2PolicyGetInfoResponse, OpeningFeeParams, SessionOutcome,
    },
};

pub type Blockheight = u32;

#[async_trait]
pub trait BlockheightProvider: Send + Sync {
    async fn get_blockheight(&self) -> Result<Blockheight>;
}

#[async_trait]
pub trait DatastoreProvider: Send + Sync {
    async fn store_buy_request(
        &self,
        scid: &ShortChannelId,
        peer_id: &PublicKey,
        offer: &OpeningFeeParams,
        expected_payment_size: &Option<Msat>,
        channel_capacity_msat: &Msat,
    ) -> Result<bool>;

    async fn get_buy_request(&self, scid: &ShortChannelId) -> Result<DatastoreEntry>;
    async fn del_buy_request(&self, scid: &ShortChannelId) -> Result<()>;

    async fn finalize_session(&self, scid: &ShortChannelId, outcome: SessionOutcome) -> Result<()>;

    async fn update_session_funding(
        &self,
        scid: &ShortChannelId,
        channel_id: &str,
        funding_psbt: &str,
    ) -> Result<()>;

    async fn update_session_funding_txid(
        &self,
        scid: &ShortChannelId,
        funding_txid: &str,
    ) -> Result<()>;

    async fn update_session_preimage(&self, scid: &ShortChannelId, preimage: &str) -> Result<()>;
}

#[async_trait]
pub trait Lsps2PolicyProvider: Send + Sync {
    async fn get_info(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> Result<Lsps2PolicyGetInfoResponse>;

    async fn buy(&self, request: &Lsps2PolicyBuyRequest) -> Result<Lsps2PolicyBuyResponse>;
}
