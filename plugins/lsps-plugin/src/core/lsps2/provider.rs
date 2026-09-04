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

#[async_trait]
pub trait DatastoreProvider: Send + Sync {
    async fn store_buy_request(
        &self,
        scid: &ShortChannelId,
        peer_id: &PublicKey,
        offer: &OpeningFeeParams,
        expected_payment_size: &Option<Msat>,
        channel_capacity_msat: &Msat,
    ) -> Result<DatastoreEntry>;

    async fn get_buy_request(&self, scid: &ShortChannelId) -> Result<DatastoreEntry>;

    async fn save_session(&self, scid: &ShortChannelId, entry: &DatastoreEntry) -> Result<()>;

    async fn finalize_session(&self, scid: &ShortChannelId, outcome: SessionOutcome) -> Result<()>;

    async fn list_active_sessions(&self) -> Result<Vec<(ShortChannelId, DatastoreEntry)>>;

    async fn list_finalized_sessions(&self) -> Result<Vec<(ShortChannelId, DatastoreEntry)>>;
}

/// Status of forwards on a channel, used during recovery classification.
#[derive(Debug, Clone, PartialEq)]
pub enum ForwardActivity {
    /// No forwards ever happened on this channel.
    NoForwards,
    /// All forwards failed (none settled or offered).
    AllFailed,
    /// Some forwards are in-flight (OFFERED) but none have settled yet.
    Offered,
    /// At least one forward has settled.
    Settled,
}

/// Information about a channel needed for recovery classification.
#[derive(Debug, Clone)]
pub struct ChannelRecoveryInfo {
    pub exists: bool,
    pub withheld: bool,
}

/// Provides recovery-specific queries. Separated from ActionExecutor
/// to keep the normal operation interface clean.
#[async_trait]
pub trait RecoveryProvider: Send + Sync {
    /// Check forward activity on a channel using both in-flight HTLCs
    /// and historical forwards.
    async fn get_forward_activity(&self, channel_id: &str) -> Result<ForwardActivity>;

    /// Get channel recovery info (exists, withheld status).
    async fn get_channel_recovery_info(&self, channel_id: &str) -> Result<ChannelRecoveryInfo>;

    /// Close a channel and unreserve its inputs.
    async fn close_and_unreserve(&self, channel_id: &str, funding_psbt: &str) -> Result<()>;
}

#[async_trait]
pub trait Lsps2PolicyProvider: Send + Sync {
    async fn get_blockheight(&self) -> Result<u32>;

    async fn get_info(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> Result<Lsps2PolicyGetInfoResponse>;

    async fn buy(&self, request: &Lsps2PolicyBuyRequest) -> Result<Lsps2PolicyBuyResponse>;
}
