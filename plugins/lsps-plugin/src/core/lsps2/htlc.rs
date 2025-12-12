use crate::{
    core::{
        lsps2::provider::{DatastoreProvider, LightningProvider, Lsps2OfferProvider},
        tlv::{TlvStream, TLV_FORWARD_AMT},
    },
    proto::{
        lsps0::{Msat, ShortChannelId},
        lsps2::{
            compute_opening_fee,
            failure_codes::{TEMPORARY_CHANNEL_FAILURE, UNKNOWN_NEXT_PEER},
            Lsps2PolicyGetChannelCapacityRequest,
        },
    },
};
use bitcoin::hashes::sha256::Hash;
use chrono::Utc;
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HtlcDecision {
    NotOurs,
    Forward {
        payload: TlvStream,
        forward_to: Hash,
        extra_tlvs: TlvStream,
    },

    Reject {
        reason: RejectReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectReason {
    OfferExpired { valid_until: chrono::DateTime<Utc> },
    AmountBelowMinimum { minimum: Msat },
    AmountAboveMaximum { maximum: Msat },
    InsufficientForFee { fee: Msat },
    FeeOverflow,
    PolicyDenied,
    FundingFailed,

    // temporarily
    MppNotSupported,
}

impl RejectReason {
    pub fn failure_code(&self) -> &'static str {
        match self {
            Self::OfferExpired { .. } => TEMPORARY_CHANNEL_FAILURE,
            _ => UNKNOWN_NEXT_PEER,
        }
    }
}

#[derive(Debug, Error)]
pub enum HtlcError {
    #[error("failed to query channel capacity: {0}")]
    CapacityQuery(#[source] anyhow::Error),
    #[error("failed to fund channel: {0}")]
    FundChannel(#[source] anyhow::Error),
    #[error("channel ready check failed: {0}")]
    ChannelReadyCheck(#[source] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct Htlc {
    pub amount_msat: Msat,
    pub extra_tlvs: TlvStream,
}
impl Htlc {
    pub fn new(amount_msat: Msat, tlvs: TlvStream) -> Self {
        Self {
            amount_msat,
            extra_tlvs: tlvs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Onion {
    pub short_channel_id: ShortChannelId,
    pub payload: TlvStream,
}

pub struct HtlcAcceptedHookHandler<A> {
    api: A,
    htlc_minimum_msat: u64,
    backoff_listpeerchannels: Duration,
}

impl<A> HtlcAcceptedHookHandler<A> {
    pub fn new(api: A, htlc_minimum_msat: u64) -> Self {
        Self {
            api,
            htlc_minimum_msat,
            backoff_listpeerchannels: Duration::from_secs(10),
        }
    }
}
impl<A: DatastoreProvider + Lsps2OfferProvider + LightningProvider> HtlcAcceptedHookHandler<A> {
    pub async fn handle(&self, htlc: &Htlc, onion: &Onion) -> Result<HtlcDecision, HtlcError> {
        // A) Is this SCID one that we care about?
        let ds_rec = match self.api.get_buy_request(&onion.short_channel_id).await {
            Ok(rec) => rec,
            Err(_) => return Ok(HtlcDecision::NotOurs),
        };

        // Fixme: Check that we don't have a channel yet with the peer that we await to
        // become READY to use.
        // ---

        // Fixme: We only accept no-mpp for now, mpp and other flows will be added later on
        // Fixme: We continue mpp for now to let the test mock handle the htlc, as we need
        // to test the client implementation for mpp payments.
        if ds_rec.expected_payment_size.is_some() {
            return Ok(HtlcDecision::Reject {
                reason: RejectReason::MppNotSupported,
            });
        }

        // B) Is the fee option menu still valid?
        if Utc::now() >= ds_rec.opening_fee_params.valid_until {
            // Not valid anymore, remove from DS and fail HTLC.
            let _ = self.api.del_buy_request(&onion.short_channel_id).await;
            return Ok(HtlcDecision::Reject {
                reason: RejectReason::OfferExpired {
                    valid_until: ds_rec.opening_fee_params.valid_until,
                },
            });
        }

        // C) Is the amount in the boundaries of the fee menu?
        if htlc.amount_msat.msat() < ds_rec.opening_fee_params.min_fee_msat.msat() {
            return Ok(HtlcDecision::Reject {
                reason: RejectReason::AmountBelowMinimum {
                    minimum: ds_rec.opening_fee_params.min_fee_msat,
                },
            });
        }

        if htlc.amount_msat.msat() > ds_rec.opening_fee_params.max_payment_size_msat.msat() {
            return Ok(HtlcDecision::Reject {
                reason: RejectReason::AmountAboveMaximum {
                    maximum: ds_rec.opening_fee_params.max_payment_size_msat,
                },
            });
        }

        // D) Check that the amount_msat covers the opening fee (only for non-mpp right now)
        let opening_fee = match compute_opening_fee(
            htlc.amount_msat.msat(),
            ds_rec.opening_fee_params.min_fee_msat.msat(),
            ds_rec.opening_fee_params.proportional.ppm() as u64,
        ) {
            Some(fee) if fee + self.htlc_minimum_msat < htlc.amount_msat.msat() => fee,
            Some(fee) => {
                return Ok(HtlcDecision::Reject {
                    reason: RejectReason::InsufficientForFee {
                        fee: Msat::from_msat(fee),
                    },
                })
            }
            None => {
                return Ok(HtlcDecision::Reject {
                    reason: RejectReason::FeeOverflow,
                })
            }
        };

        // E) We made it, open a channel to the peer.
        let ch_cap_req = Lsps2PolicyGetChannelCapacityRequest {
            opening_fee_params: ds_rec.opening_fee_params,
            init_payment_size: htlc.amount_msat,
            scid: onion.short_channel_id,
        };
        let ch_cap_res = self
            .api
            .get_channel_capacity(&ch_cap_req)
            .await
            .map_err(HtlcError::CapacityQuery)?;

        let cap = match ch_cap_res.channel_capacity_msat {
            Some(c) => Msat::from_msat(c),
            None => {
                return Ok(HtlcDecision::Reject {
                    reason: RejectReason::PolicyDenied,
                })
            }
        };

        // We take the policy-giver seriously, if the capacity is too low, we
        // still try to open the channel.
        // Fixme: We may check that the capacity is ge than the
        // (amount_msat - opening fee) in the future.
        // Fixme: Make this configurable, maybe return the whole request from
        // the policy giver?
        let (channel_id, _) = self
            .api
            .fund_jit_channel(&ds_rec.peer_id, &cap)
            .await
            .map_err(HtlcError::FundChannel)?;

        // F) Wait for the peer to send `channel_ready`.
        // Fixme: Use event to check for channel ready,
        // Fixme: Check for htlc timeout if peer refuses to send "ready".
        // Fixme: handle unexpected channel states.
        loop {
            match self
                .api
                .is_channel_ready(&ds_rec.peer_id, &channel_id)
                .await
            {
                Ok(true) => break,
                Ok(false) => tokio::time::sleep(self.backoff_listpeerchannels).await,
                Err(e) => return Err(HtlcError::ChannelReadyCheck(e)),
            };
        }

        // G) We got a working channel, deduct fee and forward htlc.
        let deducted_amt_msat = htlc.amount_msat.msat() - opening_fee;
        let mut payload = onion.payload.clone();
        payload.set_tu64(TLV_FORWARD_AMT, deducted_amt_msat);

        let mut extra_tlvs = htlc.extra_tlvs.clone();
        extra_tlvs.set_u64(65537, opening_fee);

        Ok(HtlcDecision::Forward {
            payload,
            forward_to: channel_id,
            extra_tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tlv::TlvStream;
    use crate::proto::lsps0::{Msat, Ppm, ShortChannelId};
    use crate::proto::lsps2::{
        DatastoreEntry, Lsps2PolicyGetChannelCapacityResponse, Lsps2PolicyGetInfoRequest,
        Lsps2PolicyGetInfoResponse, OpeningFeeParams, Promise,
    };
    use anyhow::{anyhow, Result as AnyResult};
    use async_trait::async_trait;
    use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
    use bitcoin::secp256k1::PublicKey;
    use chrono::{TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::u64;

    fn test_peer_id() -> PublicKey {
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            .parse()
            .unwrap()
    }

    fn test_scid() -> ShortChannelId {
        ShortChannelId::from(123456789u64)
    }

    fn test_channel_id() -> Sha256 {
        Sha256::from_byte_array([1u8; 32])
    }

    fn valid_opening_fee_params() -> OpeningFeeParams {
        OpeningFeeParams {
            min_fee_msat: Msat(2_000),
            proportional: Ppm(10_000), // 1%
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat(1_000_000),
            max_payment_size_msat: Msat(100_000_000),
            promise: Promise::try_from("test").unwrap(),
        }
    }

    fn expired_opening_fee_params() -> OpeningFeeParams {
        OpeningFeeParams {
            valid_until: Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap(),
            ..valid_opening_fee_params()
        }
    }

    fn test_datastore_entry(expected_payment_size: Option<Msat>) -> DatastoreEntry {
        DatastoreEntry {
            peer_id: test_peer_id(),
            opening_fee_params: valid_opening_fee_params(),
            expected_payment_size,
        }
    }

    fn test_onion(scid: ShortChannelId, payload: TlvStream) -> Onion {
        Onion {
            short_channel_id: scid,
            payload,
        }
    }

    fn test_htlc(amount_msat: u64, extra_tlvs: TlvStream) -> Htlc {
        Htlc {
            amount_msat: Msat::from_msat(amount_msat),
            extra_tlvs,
        }
    }

    #[derive(Default, Clone)]
    struct MockApi {
        // Datastore
        buy_request: Arc<Mutex<Option<DatastoreEntry>>>,
        buy_request_error: Arc<Mutex<bool>>,
        del_called: Arc<AtomicUsize>,

        // Policy
        channel_capacity: Arc<Mutex<Option<Option<u64>>>>, // Some(Some(cap)), Some(None) = denied, None = error
        channel_capacity_error: Arc<Mutex<bool>>,

        // Lightning
        fund_result: Arc<Mutex<Option<(Sha256, String)>>>,
        fund_error: Arc<Mutex<bool>>,
        channel_ready: Arc<Mutex<bool>>,
        channel_ready_checks: Arc<AtomicUsize>,
    }

    impl MockApi {
        fn new() -> Self {
            Self::default()
        }

        fn with_buy_request(self, entry: DatastoreEntry) -> Self {
            *self.buy_request.lock().unwrap() = Some(entry);
            self
        }

        fn with_no_buy_request(self) -> Self {
            *self.buy_request_error.lock().unwrap() = true;
            self
        }

        fn with_channel_capacity(self, capacity_msat: u64) -> Self {
            *self.channel_capacity.lock().unwrap() = Some(Some(capacity_msat));
            self
        }

        fn with_channel_denied(self) -> Self {
            *self.channel_capacity.lock().unwrap() = Some(None);
            self
        }

        fn with_channel_capacity_error(self) -> Self {
            *self.channel_capacity_error.lock().unwrap() = true;
            self
        }

        fn with_fund_result(self, channel_id: Sha256, txid: &str) -> Self {
            *self.fund_result.lock().unwrap() = Some((channel_id, txid.to_string()));
            self
        }

        fn with_fund_error(self) -> Self {
            *self.fund_error.lock().unwrap() = true;
            self
        }

        fn with_channel_ready(self, ready: bool) -> Self {
            *self.channel_ready.lock().unwrap() = ready;
            self
        }

        fn del_call_count(&self) -> usize {
            self.del_called.load(Ordering::SeqCst)
        }

        fn channel_ready_check_count(&self) -> usize {
            self.channel_ready_checks.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DatastoreProvider for MockApi {
        async fn store_buy_request(
            &self,
            _scid: &ShortChannelId,
            _peer_id: &PublicKey,
            _fee_params: &OpeningFeeParams,
            _payment_size: &Option<Msat>,
        ) -> AnyResult<bool> {
            unimplemented!("not needed for HTLC tests")
        }

        async fn get_buy_request(&self, _scid: &ShortChannelId) -> AnyResult<DatastoreEntry> {
            if *self.buy_request_error.lock().unwrap() {
                return Err(anyhow!("not found"));
            }
            self.buy_request
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow!("not found"))
        }

        async fn del_buy_request(&self, _scid: &ShortChannelId) -> AnyResult<()> {
            self.del_called.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl Lsps2OfferProvider for MockApi {
        async fn get_offer(
            &self,
            _request: &Lsps2PolicyGetInfoRequest,
        ) -> AnyResult<Lsps2PolicyGetInfoResponse> {
            unimplemented!("not needed for HTLC tests")
        }

        async fn get_channel_capacity(
            &self,
            _params: &Lsps2PolicyGetChannelCapacityRequest,
        ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse> {
            if *self.channel_capacity_error.lock().unwrap() {
                return Err(anyhow!("capacity error"));
            }
            let cap = self
                .channel_capacity
                .lock()
                .unwrap()
                .ok_or_else(|| anyhow!("no capacity set"))?;
            Ok(Lsps2PolicyGetChannelCapacityResponse {
                channel_capacity_msat: cap,
            })
        }
    }

    #[async_trait]
    impl LightningProvider for MockApi {
        async fn fund_jit_channel(
            &self,
            _peer_id: &PublicKey,
            _amount: &Msat,
        ) -> AnyResult<(Sha256, String)> {
            if *self.fund_error.lock().unwrap() {
                return Err(anyhow!("fund error"));
            }
            self.fund_result
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow!("no fund result set"))
        }

        async fn is_channel_ready(
            &self,
            _peer_id: &PublicKey,
            _channel_id: &Sha256,
        ) -> AnyResult<bool> {
            self.channel_ready_checks.fetch_add(1, Ordering::SeqCst);
            Ok(*self.channel_ready.lock().unwrap())
        }
    }

    fn handler(api: MockApi) -> HtlcAcceptedHookHandler<MockApi> {
        HtlcAcceptedHookHandler {
            api,
            htlc_minimum_msat: 1_000,
            backoff_listpeerchannels: Duration::from_millis(1), // Fast for tests
        }
    }

    #[tokio::test]
    async fn continues_when_scid_not_found() {
        let api = MockApi::new().with_no_buy_request();
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert_eq!(result, HtlcDecision::NotOurs);
    }

    #[tokio::test]
    async fn continues_when_mpp_payment() {
        let entry = test_datastore_entry(Some(Msat(50_000_000))); // MPP = has expected size
        let api = MockApi::new().with_buy_request(entry);
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert_eq!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::MppNotSupported
            }
        );
    }

    #[tokio::test]
    async fn fails_when_offer_expired() {
        let mut entry = test_datastore_entry(None);
        entry.opening_fee_params = expired_opening_fee_params();
        let api = MockApi::new().with_buy_request(entry);
        let h = handler(api.clone());

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::OfferExpired { .. }
            }
        ));
        assert_eq!(api.del_call_count(), 1); // Should delete expired entry
    }

    #[tokio::test]
    async fn fails_when_amount_below_min_fee() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new().with_buy_request(entry);
        let h = handler(api);

        // min_fee_msat is 2_000
        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(1_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::AmountBelowMinimum { .. }
            }
        ));
    }

    #[tokio::test]
    async fn fails_when_amount_above_max() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new().with_buy_request(entry);
        let h = handler(api);

        // max_payment_size_msat is 100_000_000
        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(200_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::AmountAboveMaximum { .. }
            }
        ));
    }

    #[tokio::test]
    async fn fails_when_amount_doesnt_cover_fee_plus_minimum() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new().with_buy_request(entry);
        let h = handler(api);

        // min_fee = 2_000, htlc_minimum = 1_000
        // Amount must be > fee + htlc_minimum
        // At 3_000: fee ~= 2_000 + (3_000 * 10_000 / 1_000_000) = 2_030
        // 2_030 + 1_000 = 3_030 > 3_000, so should fail
        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(3_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::InsufficientForFee { .. }
            }
        ));
    }

    #[tokio::test]
    async fn fails_when_fee_computation_overflows() {
        let mut entry = test_datastore_entry(None);
        entry.opening_fee_params.min_fee_msat = Msat(u64::MAX / 2);
        entry.opening_fee_params.proportional = Ppm(u32::MAX);
        entry.opening_fee_params.min_payment_size_msat = Msat(1);
        entry.opening_fee_params.max_payment_size_msat = Msat(u64::MAX);

        let api = MockApi::new().with_buy_request(entry);
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(u64::MAX / 2, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::FeeOverflow,
            }
        ));
    }

    #[tokio::test]
    async fn fails_when_channel_capacity_errors() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity_error();
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.expect_err("should fail");

        assert!(matches!(result, HtlcError::CapacityQuery(_)));
    }

    #[tokio::test]
    async fn fails_when_policy_denies_channel() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new().with_buy_request(entry).with_channel_denied();
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(
            result,
            HtlcDecision::Reject {
                reason: RejectReason::PolicyDenied,
            }
        ));
    }

    #[tokio::test]
    async fn fails_when_fund_channel_errors() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(50_000_000)
            .with_fund_error();
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.expect_err("should fail");

        assert!(matches!(result, HtlcError::FundChannel(_)));
    }

    #[tokio::test]
    async fn success_flow_continues_with_modified_payload() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(50_000_000)
            .with_fund_result(test_channel_id(), "txid123")
            .with_channel_ready(true);
        let h = handler(api.clone());

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        let HtlcDecision::Forward {
            payload,
            forward_to,
            extra_tlvs,
        } = result
        else {
            panic!("expected forward, got {:?}", result)
        };

        assert_eq!(forward_to, test_channel_id());
        assert!(!payload.0.is_empty());
        assert!(!extra_tlvs.0.is_empty());
    }

    #[tokio::test]
    async fn polls_until_channel_ready() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(50_000_000)
            .with_fund_result(test_channel_id(), "txid123")
            .with_channel_ready(false);

        let h = handler(api.clone());

        // Spawn handler, will block on channel ready
        let handle = tokio::spawn(async move {
            let onion = test_onion(test_scid(), TlvStream::default());
            let htlc = test_htlc(10_000_000, TlvStream::default());
            let result = h.handle(&htlc, &onion).await.unwrap();
            result
        });

        // Let it poll a few times
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(api.channel_ready_check_count() > 1);

        // Now make channel ready
        *api.channel_ready.lock().unwrap() = true;

        let result = handle.await.unwrap();
        assert!(matches!(result, HtlcDecision::Forward { .. }));
    }

    #[tokio::test]
    async fn deducts_fee_from_forward_amount() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(50_000_000)
            .with_fund_result(test_channel_id(), "txid123")
            .with_channel_ready(true);
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        let HtlcDecision::Forward { payload, .. } = result else {
            panic!("expected forward, got {:?}", result)
        };

        // Verify payload contains deducted amount
        // fee = max(min_fee, amount * proportional / 1_000_000)
        // fee = max(2_000, 10_000_000 * 10_000 / 1_000_000) = max(2_000, 100_000) = 100_000
        // deducted = 10_000_000 - 100_000 = 9_900_000
        let forward_amt = payload.get_tu64(TLV_FORWARD_AMT).unwrap();
        assert_eq!(forward_amt, Some(9_900_000));
    }

    #[tokio::test]
    async fn extra_tlvs_contain_opening_fee() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(50_000_000)
            .with_fund_result(test_channel_id(), "txid123")
            .with_channel_ready(true);
        let h = handler(api);

        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(10_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        let HtlcDecision::Forward { extra_tlvs, .. } = result else {
            panic!("expected forward, got {:?}", result)
        };

        // Opening fee should be in TLV 65537
        let opening_fee = extra_tlvs.get_u64(65537).unwrap();
        assert_eq!(opening_fee, Some(100_000)); // Same fee calculation as above
    }

    #[tokio::test]
    async fn handles_minimum_valid_amount() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(50_000_000)
            .with_fund_result(test_channel_id(), "txid123")
            .with_channel_ready(true);
        let h = handler(api);

        // Just enough to cover fee + htlc_minimum
        // fee at 1_000_000 = max(2_000, 1_000_000 * 10_000 / 1_000_000) = max(2_000, 10_000) = 10_000
        // Need: fee + htlc_minimum < amount
        // 10_000 + 1_000 = 11_000 < 1_000_000 ✓
        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(1_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(result, HtlcDecision::Forward { .. }));
    }

    #[tokio::test]
    async fn handles_maximum_valid_amount() {
        let entry = test_datastore_entry(None);
        let api = MockApi::new()
            .with_buy_request(entry)
            .with_channel_capacity(200_000_000)
            .with_fund_result(test_channel_id(), "txid123")
            .with_channel_ready(true);
        let h = handler(api);

        // max_payment_size_msat is 100_000_000
        let onion = test_onion(test_scid(), TlvStream::default());
        let htlc = test_htlc(100_000_000, TlvStream::default());
        let result = h.handle(&htlc, &onion).await.unwrap();

        assert!(matches!(result, HtlcDecision::Forward { .. }));
    }
}
