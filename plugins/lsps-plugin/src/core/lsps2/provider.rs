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

    /// List all active session entries (for recovery scan).
    async fn list_active_sessions(&self) -> Result<Vec<(ShortChannelId, DatastoreEntry)>>;

    /// Update the forwards_updated_index for a session.
    async fn update_session_forwards_index(
        &self,
        scid: &ShortChannelId,
        index: u64,
    ) -> Result<()>;

    /// Reset a session's funding fields back to None (for clean restart).
    async fn reset_session_funding(&self, scid: &ShortChannelId) -> Result<()>;
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

    /// Monitor forward status changes using the wait subsystem.
    /// Returns when a forward on the given channel settles or fails.
    /// `from_index` is the last processed updated_index.
    async fn wait_for_forward_resolution(
        &self,
        channel_id: &str,
        from_index: u64,
    ) -> Result<(ForwardActivity, u64)>;
}

#[async_trait]
pub trait Lsps2PolicyProvider: Send + Sync {
    async fn get_info(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> Result<Lsps2PolicyGetInfoResponse>;

    async fn buy(&self, request: &Lsps2PolicyBuyRequest) -> Result<Lsps2PolicyBuyResponse>;
}
