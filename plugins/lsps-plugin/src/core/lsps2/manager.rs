use super::actor::{ActionExecutor, ActorInboxHandle, HtlcResponse};
use super::provider::DatastoreProvider;
use super::session::{PaymentPart, Session};
use crate::core::lsps2::actor::SessionActor;
use crate::proto::lsps0::ShortChannelId;
pub use bitcoin::hashes::sha256::Hash as PaymentHash;
use log::debug;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("session terminated")]
    SessionTerminated,
    #[error("datastore lookup failed: {0}")]
    DatastoreLookup(#[source] anyhow::Error),
}

pub struct SessionConfig {
    pub max_parts: usize,
    pub collect_timeout_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_parts: 30,            // Core-Lightning default.
            collect_timeout_secs: 90, // Blip52 default.
        }
    }
}

pub struct SessionManager<D, A> {
    sessions: Mutex<HashMap<PaymentHash, ActorInboxHandle>>,
    datastore: Arc<D>,
    executor: Arc<A>,
    config: SessionConfig,
}

impl<D: DatastoreProvider + 'static, A: ActionExecutor + Send + Sync + 'static>
    SessionManager<D, A>
{
    pub fn new(datastore: Arc<D>, executor: Arc<A>, config: SessionConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            datastore,
            executor,
            config,
        }
    }

    pub async fn on_part(
        &self,
        payment_hash: PaymentHash,
        scid: ShortChannelId,
        part: PaymentPart,
    ) -> Result<HtlcResponse, ManagerError> {
        let handle = {
            let mut sessions = self.sessions.lock().await;
            if let Some(handle) = sessions.get(&payment_hash) {
                handle.clone()
            } else {
                let handle = self.create_session(&scid).await?;
                sessions.insert(payment_hash, handle.clone());
                handle
            }
        };

        match handle.add_part(part).await {
            Ok(resp) => Ok(resp),
            Err(_) => {
                self.sessions.lock().await.remove(&payment_hash);
                Err(ManagerError::SessionTerminated)
            }
        }
    }

    pub async fn on_payment_settled(
        &self,
        payment_hash: PaymentHash,
        preimage: Option<String>,
    ) -> Result<(), ManagerError> {
        let handle = {
            let sessions = self.sessions.lock().await;
            match sessions.get(&payment_hash) {
                Some(handle) => handle.clone(),
                None => {
                    debug!("on_payment_settled: no session for {payment_hash}");
                    return Ok(());
                }
            }
        };

        match handle.payment_settled(preimage).await {
            Ok(()) => Ok(()),
            Err(_) => {
                self.sessions.lock().await.remove(&payment_hash);
                Err(ManagerError::SessionTerminated)
            }
        }
    }

    pub async fn on_payment_failed(
        &self,
        payment_hash: PaymentHash,
    ) -> Result<(), ManagerError> {
        let handle = {
            let sessions = self.sessions.lock().await;
            match sessions.get(&payment_hash) {
                Some(handle) => handle.clone(),
                None => {
                    debug!("on_payment_failed: no session for {payment_hash}");
                    return Ok(());
                }
            }
        };

        match handle.payment_failed().await {
            Ok(()) => Ok(()),
            Err(_) => {
                self.sessions.lock().await.remove(&payment_hash);
                Err(ManagerError::SessionTerminated)
            }
        }
    }

    pub async fn on_new_block(&self, height: u32) {
        let handles: Vec<(PaymentHash, ActorInboxHandle)> = {
            let sessions = self.sessions.lock().await;
            sessions.iter().map(|(k, v)| (*k, v.clone())).collect()
        };

        let mut dead = Vec::new();
        for (hash, handle) in handles {
            if handle.new_block(height).await.is_err() {
                dead.push(hash);
            }
        }

        if !dead.is_empty() {
            let mut sessions = self.sessions.lock().await;
            for hash in dead {
                sessions.remove(&hash);
            }
        }
    }

    async fn create_session(
        &self,
        scid: &ShortChannelId,
    ) -> Result<ActorInboxHandle, ManagerError> {
        let entry = self
            .datastore
            .get_buy_request(scid)
            .await
            .map_err(ManagerError::DatastoreLookup)?;

        let session = Session::new(
            self.config.max_parts,
            entry.opening_fee_params,
            entry.expected_payment_size,
            entry.channel_capacity_msat,
            entry.peer_id.to_string(),
        );

        Ok(SessionActor::spawn_session_actor(
            session,
            self.executor.clone(),
            entry.peer_id.to_string(),
            self.config.collect_timeout_secs,
            *scid,
            self.datastore.clone(),
        ))
    }

    #[cfg(test)]
    async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::lsps0::{Msat, Ppm};
    use crate::proto::lsps2::{DatastoreEntry, OpeningFeeParams, Promise, SessionOutcome};
    use async_trait::async_trait;
    use bitcoin::hashes::Hash;
    use chrono::{Duration as ChronoDuration, Utc};
    use std::time::Duration;

    fn test_payment_hash(byte: u8) -> PaymentHash {
        PaymentHash::from_byte_array([byte; 32])
    }

    fn test_scid() -> ShortChannelId {
        ShortChannelId::from(100u64 << 40 | 1u64 << 16)
    }

    fn test_scid_2() -> ShortChannelId {
        ShortChannelId::from(200u64 << 40 | 2u64 << 16)
    }

    fn unknown_scid() -> ShortChannelId {
        ShortChannelId::from(999u64 << 40 | 9u64 << 16 | 9)
    }

    fn test_peer_id() -> cln_rpc::primitives::PublicKey {
        serde_json::from_value(serde_json::json!(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ))
        .unwrap()
    }

    fn opening_fee_params(min_fee_msat: u64) -> OpeningFeeParams {
        OpeningFeeParams {
            min_fee_msat: Msat::from_msat(min_fee_msat),
            proportional: Ppm::from_ppm(1_000),
            valid_until: Utc::now() + ChronoDuration::hours(1),
            min_lifetime: 144,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat::from_msat(1),
            max_payment_size_msat: Msat::from_msat(u64::MAX),
            promise: Promise("test-promise".to_owned()),
        }
    }

    fn test_datastore_entry() -> DatastoreEntry {
        DatastoreEntry {
            peer_id: test_peer_id(),
            opening_fee_params: opening_fee_params(1),
            expected_payment_size: Some(Msat::from_msat(1_000)),
            channel_capacity_msat: Msat::from_msat(100_000_000),
            created_at: Utc::now(),
            channel_id: None,
            funding_psbt: None,
            funding_txid: None,
            preimage: None,
        }
    }

    fn part(htlc_id: u64, amount_msat: u64) -> PaymentPart {
        PaymentPart {
            htlc_id,
            amount_msat: Msat::from_msat(amount_msat),
            cltv_expiry: 100,
        }
    }

    struct MockDatastore {
        entries: HashMap<String, DatastoreEntry>,
    }

    impl MockDatastore {
        fn new() -> Self {
            let mut entries = HashMap::new();
            entries.insert(test_scid().to_string(), test_datastore_entry());
            entries.insert(test_scid_2().to_string(), test_datastore_entry());
            Self { entries }
        }
    }

    #[async_trait]
    impl DatastoreProvider for MockDatastore {
        async fn store_buy_request(
            &self,
            _scid: &ShortChannelId,
            _peer_id: &bitcoin::secp256k1::PublicKey,
            _offer: &OpeningFeeParams,
            _expected_payment_size: &Option<Msat>,
            _channel_capacity_msat: &Msat,
        ) -> anyhow::Result<bool> {
            Ok(true)
        }

        async fn get_buy_request(&self, scid: &ShortChannelId) -> anyhow::Result<DatastoreEntry> {
            self.entries
                .get(&scid.to_string())
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not found: {scid}"))
        }

        async fn del_buy_request(&self, _scid: &ShortChannelId) -> anyhow::Result<()> {
            Ok(())
        }

        async fn finalize_session(
            &self,
            _scid: &ShortChannelId,
            _outcome: SessionOutcome,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update_session_funding(
            &self,
            _scid: &ShortChannelId,
            _channel_id: &str,
            _funding_psbt: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update_session_funding_txid(
            &self,
            _scid: &ShortChannelId,
            _funding_txid: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update_session_preimage(
            &self,
            _scid: &ShortChannelId,
            _preimage: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockExecutor {
        fund_succeeds: bool,
    }

    #[async_trait]
    impl ActionExecutor for MockExecutor {
        async fn fund_channel(
            &self,
            _peer_id: String,
            _channel_capacity_msat: Msat,
            _opening_fee_params: OpeningFeeParams,
        ) -> anyhow::Result<(String, String)> {
            if self.fund_succeeds {
                Ok(("channel-id-1".to_string(), "psbt-1".to_string()))
            } else {
                Err(anyhow::anyhow!("fund error"))
            }
        }

        async fn broadcast_tx(
            &self,
            _channel_id: String,
            _funding_psbt: String,
        ) -> anyhow::Result<String> {
            Ok("mock-txid".to_string())
        }

        async fn abandon_session(
            &self,
            _channel_id: String,
            _funding_psbt: String,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn disconnect(&self, _peer_id: String) -> anyhow::Result<()> {
            Ok(())
        }

        async fn is_channel_alive(&self, _channel_id: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    fn test_manager(fund_succeeds: bool) -> Arc<SessionManager<MockDatastore, MockExecutor>> {
        Arc::new(SessionManager::new(
            Arc::new(MockDatastore::new()),
            Arc::new(MockExecutor { fund_succeeds }),
            SessionConfig {
                max_parts: 3,
                ..SessionConfig::default()
            },
        ))
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn first_part_creates_session() {
        let mgr = test_manager(true);

        let resp = mgr
            .on_part(test_payment_hash(1), test_scid(), part(1, 1_000))
            .await
            .unwrap();

        assert!(matches!(resp, HtlcResponse::Forward { .. }));
        assert_eq!(mgr.session_count().await, 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn second_part_routes_to_existing() {
        let mgr = test_manager(true);
        let hash = test_payment_hash(1);

        // First part reaches threshold (expected=1000) and gets Forward.
        let resp1 = mgr
            .on_part(hash, test_scid(), part(1, 1_000))
            .await
            .unwrap();
        assert!(matches!(resp1, HtlcResponse::Forward { .. }));

        // Session is now in AwaitingSettlement. Second part is forwarded immediately.
        let resp2 = mgr.on_part(hash, test_scid(), part(2, 500)).await.unwrap();
        match resp2 {
            HtlcResponse::Forward { fee_msat, .. } => {
                assert_eq!(fee_msat, 0, "late-arriving part should have zero fee");
            }
            other => panic!("expected Forward, got {other:?}"),
        }

        assert_eq!(mgr.session_count().await, 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn different_hashes_create_separate_sessions() {
        let mgr = test_manager(true);

        let r1 = mgr
            .on_part(test_payment_hash(1), test_scid(), part(1, 1_000))
            .await
            .unwrap();
        let r2 = mgr
            .on_part(test_payment_hash(2), test_scid_2(), part(2, 1_000))
            .await
            .unwrap();

        assert!(matches!(r1, HtlcResponse::Forward { .. }));
        assert!(matches!(r2, HtlcResponse::Forward { .. }));
        assert_eq!(mgr.session_count().await, 2);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn terminated_session_cleaned_up() {
        let mgr = test_manager(true);
        let hash = test_payment_hash(1);

        // First on_part with partial amount — won't reach threshold, blocks.
        let mgr2 = mgr.clone();
        let h1 = tokio::spawn(async move { mgr2.on_part(hash, test_scid(), part(1, 500)).await });

        // Advance past 90s collect timeout.
        tokio::time::sleep(Duration::from_secs(91)).await;

        // First part should have received Fail from timeout.
        let resp = h1.await.unwrap().unwrap();
        assert!(matches!(resp, HtlcResponse::Fail { .. }));

        // Stale entry still in the map.
        assert_eq!(mgr.session_count().await, 1);

        // Next on_part detects dead session and cleans up.
        let err = mgr
            .on_part(hash, test_scid(), part(2, 500))
            .await
            .unwrap_err();
        assert!(matches!(err, ManagerError::SessionTerminated { .. }));
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn datastore_lookup_failure() {
        let mgr = test_manager(true);

        let err = mgr
            .on_part(test_payment_hash(1), unknown_scid(), part(1, 1_000))
            .await
            .unwrap_err();

        assert!(matches!(err, ManagerError::DatastoreLookup { .. }));
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn payment_settled_unknown_hash_is_ok() {
        let mgr = test_manager(true);
        let result = mgr.on_payment_settled(test_payment_hash(99), None).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn payment_settled_active_session() {
        let mgr = test_manager(true);
        let hash = test_payment_hash(1);

        // Create session and forward payment.
        let resp = mgr
            .on_part(hash, test_scid(), part(1, 1_000))
            .await
            .unwrap();
        assert!(matches!(resp, HtlcResponse::Forward { .. }));

        // Settle payment — session is in AwaitingSettlement.
        let result = mgr.on_payment_settled(hash, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn payment_settled_stale_session_cleaned_up() {
        let mgr = test_manager(true);
        let hash = test_payment_hash(1);

        // Create a session with a partial amount — won't reach threshold.
        let mgr2 = mgr.clone();
        let h1 = tokio::spawn(async move { mgr2.on_part(hash, test_scid(), part(1, 500)).await });

        // Advance past 90s collect timeout → actor dies.
        tokio::time::sleep(Duration::from_secs(91)).await;
        let resp = h1.await.unwrap().unwrap();
        assert!(matches!(resp, HtlcResponse::Fail { .. }));

        // Stale entry remains.
        assert_eq!(mgr.session_count().await, 1);

        // on_payment_settled hits dead handle → removes entry.
        let err = mgr.on_payment_settled(hash, None).await.unwrap_err();
        assert!(matches!(err, ManagerError::SessionTerminated { .. }));
        assert_eq!(mgr.session_count().await, 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn payment_failed_unknown_hash_is_ok() {
        let mgr = test_manager(true);
        let result = mgr.on_payment_failed(test_payment_hash(99)).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn payment_failed_active_session() {
        let mgr = test_manager(true);
        let hash = test_payment_hash(1);

        // Create session and forward payment.
        let resp = mgr
            .on_part(hash, test_scid(), part(1, 1_000))
            .await
            .unwrap();
        assert!(matches!(resp, HtlcResponse::Forward { .. }));

        // Fail payment — session is in AwaitingSettlement.
        let result = mgr.on_payment_failed(hash).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn concurrent_first_parts_same_hash() {
        let mgr = test_manager(true);
        let hash = test_payment_hash(1);

        // Two concurrent on_part calls for the same hash.
        // expected_payment_size=1000, so two 500-msat parts reach threshold together.
        let mgr2 = mgr.clone();
        let h1 = tokio::spawn(async move { mgr2.on_part(hash, test_scid(), part(1, 500)).await });
        let mgr3 = mgr.clone();
        let h2 = tokio::spawn(async move { mgr3.on_part(hash, test_scid(), part(2, 500)).await });

        let r1 = h1.await.unwrap().unwrap();
        let r2 = h2.await.unwrap().unwrap();

        assert!(matches!(r1, HtlcResponse::Forward { .. }));
        assert!(matches!(r2, HtlcResponse::Forward { .. }));
        assert_eq!(mgr.session_count().await, 1);
    }
}
