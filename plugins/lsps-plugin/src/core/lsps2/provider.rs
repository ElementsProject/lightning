use anyhow::Result;
use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash;
use bitcoin::secp256k1::PublicKey;

use crate::proto::{
    lsps0::{Msat, ShortChannelId},
    lsps2::{
        DatastoreEntry, Lsps2PolicyGetChannelCapacityRequest,
        Lsps2PolicyGetChannelCapacityResponse, Lsps2PolicyGetInfoRequest,
        Lsps2PolicyGetInfoResponse, OpeningFeeParams,
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
    ) -> Result<bool>;

    async fn get_buy_request(&self, scid: &ShortChannelId) -> Result<DatastoreEntry>;
    async fn del_buy_request(&self, scid: &ShortChannelId) -> Result<()>;
}

#[async_trait]
pub trait LightningProvider: Send + Sync {
    async fn fund_jit_channel(&self, peer_id: &PublicKey, amount: &Msat) -> Result<(Hash, String)>;
    async fn is_channel_ready(&self, peer_id: &PublicKey, channel_id: &Hash) -> Result<bool>;
}

#[async_trait]
pub trait Lsps2OfferProvider: Send + Sync {
    async fn get_offer(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> Result<Lsps2PolicyGetInfoResponse>;

    async fn get_channel_capacity(
        &self,
        params: &Lsps2PolicyGetChannelCapacityRequest,
    ) -> Result<Lsps2PolicyGetChannelCapacityResponse>;
}
