use crate::{
    core::{
        lsps2::provider::{BlockheightProvider, DatastoreProvider, Lsps2OfferProvider},
        router::JsonRpcRouterBuilder,
        server::LspsProtocol,
    },
    proto::{
        jsonrpc::{RpcError, RpcErrorExt as _},
        lsps0::{LSPS0RpcErrorExt as _, ShortChannelId},
        lsps2::{
            Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest, Lsps2GetInfoResponse,
            Lsps2PolicyGetInfoRequest, OpeningFeeParams, ShortChannelIdJITExt,
        },
    },
    register_handler,
};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use std::sync::Arc;

const DEFAULT_CLTV_EXPIRY_DELTA: u32 = 144;

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

pub struct Lsps2ServiceHandler<A> {
    pub api: Arc<A>,
    pub promise_secret: [u8; 32],
}

impl<A> Lsps2ServiceHandler<A> {
    pub fn new(api: Arc<A>, promise_seret: &[u8; 32]) -> Self {
        Lsps2ServiceHandler {
            api,
            promise_secret: promise_seret.to_owned(),
        }
    }
}

#[async_trait]
impl<A: DatastoreProvider + BlockheightProvider + Lsps2OfferProvider + 'static> Lsps2Handler
    for Lsps2ServiceHandler<A>
{
    async fn handle_get_info(
        &self,
        request: Lsps2GetInfoRequest,
    ) -> std::result::Result<Lsps2GetInfoResponse, RpcError> {
        let res_data = self
            .api
            .get_offer(&Lsps2PolicyGetInfoRequest {
                token: request.token.clone(),
            })
            .await
            .map_err(|_| RpcError::internal_error("internal error"))?;

        if res_data.client_rejected {
            return Err(RpcError::client_rejected("client was rejected"));
        };

        let opening_fee_params_menu = res_data
            .policy_opening_fee_params_menu
            .iter()
            .map(|v| v.with_promise(&self.promise_secret))
            .collect::<Vec<OpeningFeeParams>>();

        Ok(Lsps2GetInfoResponse {
            opening_fee_params_menu,
        })
    }

    async fn handle_buy(
        &self,
        peer_id: PublicKey,
        request: Lsps2BuyRequest,
    ) -> core::result::Result<Lsps2BuyResponse, RpcError> {
        let fee_params = request.opening_fee_params;

        // FIXME: In the future we should replace the \`None\` with a meaningful
        // value that reflects the inbound capacity for this node from the
        // public network for a better pre-condition check on the payment_size.
        fee_params.validate(&self.promise_secret, request.payment_size_msat, None)?;

        // Generate a tmp scid to identify jit channel request in htlc.
        let blockheight = self
            .api
            .get_blockheight()
            .await
            .map_err(|_| RpcError::internal_error("internal error"))?;

        // FIXME: Future task: Check that we don't conflict with any jit scid we
        // already handed out -> Check datastore entries.
        let jit_scid = ShortChannelId::generate_jit(blockheight, 12); // Approximately 2 hours in the future.

        let ok = self
            .api
            .store_buy_request(&jit_scid, &peer_id, &fee_params, &request.payment_size_msat)
            .await
            .map_err(|_| RpcError::internal_error("internal error"))?;

        if !ok {
            return Err(RpcError::internal_error("internal error"))?;
        }

        Ok(Lsps2BuyResponse {
            jit_channel_scid: jit_scid,
            // We can make this configurable if necessary.
            lsp_cltv_expiry_delta: DEFAULT_CLTV_EXPIRY_DELTA,
            // We can implement the other mode later on as we might have to do
            // some additional work on core-lightning to enable this.
            client_trusts_lsp: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::lsps0::{Msat, Ppm};
    use crate::proto::lsps2::{
        DatastoreEntry, Lsps2PolicyGetChannelCapacityRequest,
        Lsps2PolicyGetChannelCapacityResponse, Lsps2PolicyGetInfoResponse, OpeningFeeParams,
        PolicyOpeningFeeParams, Promise,
    };
    use anyhow::{anyhow, Result as AnyResult};
    use chrono::{TimeZone, Utc};
    use std::sync::{Arc, Mutex};

    fn test_peer_id() -> PublicKey {
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            .parse()
            .unwrap()
    }

    fn test_secret() -> [u8; 32] {
        [0x42; 32]
    }

    fn test_policy_params() -> PolicyOpeningFeeParams {
        PolicyOpeningFeeParams {
            min_fee_msat: Msat(2_000),
            proportional: Ppm(10_000),
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat(1_000_000),
            max_payment_size_msat: Msat(100_000_000),
        }
    }

    fn test_opening_fee_params(secret: &[u8; 32]) -> OpeningFeeParams {
        test_policy_params().with_promise(secret)
    }

    fn expired_opening_fee_params(secret: &[u8; 32]) -> OpeningFeeParams {
        let mut policy = test_policy_params();
        policy.valid_until = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        policy.with_promise(secret)
    }

    #[derive(Default, Clone)]
    struct MockApi {
        // Responses
        offer_response: Arc<Mutex<Option<Lsps2PolicyGetInfoResponse>>>,
        blockheight: Arc<Mutex<Option<u32>>>,
        store_result: Arc<Mutex<Option<bool>>>,

        // Errors
        offer_error: Arc<Mutex<bool>>,
        blockheight_error: Arc<Mutex<bool>>,
        store_error: Arc<Mutex<bool>>,

        // Capture calls
        stored_requests: Arc<Mutex<Vec<StoredBuyRequest>>>,
    }

    #[derive(Clone, Debug)]
    struct StoredBuyRequest {
        peer_id: PublicKey,
        payment_size: Option<Msat>,
    }

    impl MockApi {
        fn new() -> Self {
            Self::default()
        }

        fn with_offer(self, response: Lsps2PolicyGetInfoResponse) -> Self {
            *self.offer_response.lock().unwrap() = Some(response);
            self
        }

        fn with_offer_menu(self, menu: Vec<PolicyOpeningFeeParams>) -> Self {
            self.with_offer(Lsps2PolicyGetInfoResponse {
                policy_opening_fee_params_menu: menu,
                client_rejected: false,
            })
        }

        fn with_client_rejected(self) -> Self {
            *self.offer_response.lock().unwrap() = Some(Lsps2PolicyGetInfoResponse {
                policy_opening_fee_params_menu: vec![],
                client_rejected: true,
            });
            self
        }

        fn with_blockheight(self, height: u32) -> Self {
            *self.blockheight.lock().unwrap() = Some(height);
            self
        }

        fn with_store_result(self, ok: bool) -> Self {
            *self.store_result.lock().unwrap() = Some(ok);
            self
        }

        fn with_offer_error(self) -> Self {
            *self.offer_error.lock().unwrap() = true;
            self
        }

        fn with_blockheight_error(self) -> Self {
            *self.blockheight_error.lock().unwrap() = true;
            self
        }

        fn with_store_error(self) -> Self {
            *self.store_error.lock().unwrap() = true;
            self
        }

        fn stored_requests(&self) -> Vec<StoredBuyRequest> {
            self.stored_requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Lsps2OfferProvider for MockApi {
        async fn get_offer(
            &self,
            _request: &Lsps2PolicyGetInfoRequest,
        ) -> AnyResult<Lsps2PolicyGetInfoResponse> {
            if *self.offer_error.lock().unwrap() {
                return Err(anyhow!("offer error"));
            }
            self.offer_response
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow!("no offer response set"))
        }

        async fn get_channel_capacity(
            &self,
            _params: &Lsps2PolicyGetChannelCapacityRequest,
        ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse> {
            unimplemented!("not needed for service tests")
        }
    }

    #[async_trait]
    impl BlockheightProvider for MockApi {
        async fn get_blockheight(&self) -> AnyResult<u32> {
            if *self.blockheight_error.lock().unwrap() {
                return Err(anyhow!("blockheight error"));
            }
            self.blockheight
                .lock()
                .unwrap()
                .ok_or_else(|| anyhow!("no blockheight set"))
        }
    }

    #[async_trait]
    impl DatastoreProvider for MockApi {
        async fn store_buy_request(
            &self,
            _scid: &ShortChannelId,
            peer_id: &PublicKey,
            _fee_params: &OpeningFeeParams,
            payment_size: &Option<Msat>,
        ) -> AnyResult<bool> {
            if *self.store_error.lock().unwrap() {
                return Err(anyhow!("store error"));
            }

            self.stored_requests.lock().unwrap().push(StoredBuyRequest {
                peer_id: *peer_id,
                payment_size: *payment_size,
            });

            Ok(self.store_result.lock().unwrap().unwrap_or(true))
        }

        async fn get_buy_request(&self, _scid: &ShortChannelId) -> AnyResult<DatastoreEntry> {
            unimplemented!("not needed for service tests")
        }

        async fn del_buy_request(&self, _scid: &ShortChannelId) -> AnyResult<()> {
            unimplemented!("not needed for service tests")
        }
    }

    fn handler(api: MockApi) -> Lsps2ServiceHandler<MockApi> {
        Lsps2ServiceHandler::new(Arc::new(api), &test_secret())
    }

    #[tokio::test]
    async fn get_info_returns_fee_params_with_promise() {
        let api = MockApi::new().with_offer_menu(vec![test_policy_params()]);
        let h = handler(api);

        let result = h.handle_get_info(Lsps2GetInfoRequest { token: None }).await;

        let response = result.unwrap();
        assert_eq!(response.opening_fee_params_menu.len(), 1);

        let params = &response.opening_fee_params_menu[0];
        assert_eq!(params.min_fee_msat, Msat(2_000));
        assert_eq!(params.proportional, Ppm(10_000));
        assert!(!params.promise.0.is_empty());
    }

    #[tokio::test]
    async fn get_info_returns_multiple_fee_params() {
        let mut params1 = test_policy_params();
        params1.min_fee_msat = Msat(1_000);

        let mut params2 = test_policy_params();
        params2.min_fee_msat = Msat(2_000);

        let api = MockApi::new().with_offer_menu(vec![params1, params2]);
        let h = handler(api);

        let result = h.handle_get_info(Lsps2GetInfoRequest { token: None }).await;

        let response = result.unwrap();
        assert_eq!(response.opening_fee_params_menu.len(), 2);
        assert_eq!(
            response.opening_fee_params_menu[0].min_fee_msat,
            Msat(1_000)
        );
        assert_eq!(
            response.opening_fee_params_menu[1].min_fee_msat,
            Msat(2_000)
        );
    }

    #[tokio::test]
    async fn get_info_returns_empty_menu() {
        let api = MockApi::new().with_offer_menu(vec![]);
        let h = handler(api);

        let result = h.handle_get_info(Lsps2GetInfoRequest { token: None }).await;

        let response = result.unwrap();
        assert!(response.opening_fee_params_menu.is_empty());
    }

    #[tokio::test]
    async fn get_info_rejects_client() {
        let api = MockApi::new().with_client_rejected();
        let h = handler(api);

        let result = h.handle_get_info(Lsps2GetInfoRequest { token: None }).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, 001); // client_rejected code
    }

    #[tokio::test]
    async fn get_info_handles_api_error() {
        let api = MockApi::new().with_offer_error();
        let h = handler(api);

        let result = h.handle_get_info(Lsps2GetInfoRequest { token: None }).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, -32603); // internal error
    }

    #[tokio::test]
    async fn buy_success_with_payment_size() {
        let api = MockApi::new()
            .with_blockheight(800_000)
            .with_store_result(true);
        let h = handler(api.clone());

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(50_000_000)),
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let response = result.unwrap();
        assert!(response.jit_channel_scid.to_u64() > 0);
        assert_eq!(response.lsp_cltv_expiry_delta, DEFAULT_CLTV_EXPIRY_DELTA);
        assert!(!response.client_trusts_lsp);

        // Verify stored
        let stored = api.stored_requests();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].peer_id, test_peer_id());
        assert_eq!(stored[0].payment_size, Some(Msat(50_000_000)));
    }

    #[tokio::test]
    async fn buy_success_without_payment_size() {
        let api = MockApi::new()
            .with_blockheight(800_000)
            .with_store_result(true);
        let h = handler(api.clone());

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: None,
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        assert!(result.is_ok());
        assert_eq!(api.stored_requests()[0].payment_size, None);
    }

    #[tokio::test]
    async fn buy_rejects_invalid_promise() {
        let api = MockApi::new();
        let h = handler(api);

        let mut fee_params = test_opening_fee_params(&test_secret());
        fee_params.promise = Promise::try_from("invalid").unwrap();

        let request = Lsps2BuyRequest {
            opening_fee_params: fee_params,
            payment_size_msat: Some(Msat(50_000_000)),
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, 201); // invalid/unrecognized params
    }

    #[tokio::test]
    async fn buy_rejects_expired_offer() {
        let api = MockApi::new();
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: expired_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(50_000_000)),
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, 201);
    }

    #[tokio::test]
    async fn buy_rejects_payment_below_min() {
        let api = MockApi::new();
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(100)), // Below min_payment_size_msat
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn buy_rejects_payment_above_max() {
        let api = MockApi::new();
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(999_999_999_999)), // Above max
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn buy_rejects_when_fee_exceeds_payment() {
        let api = MockApi::new();
        let h = handler(api);

        // Payment size barely above min_fee, but fee calculation might exceed it
        let mut fee_params = test_policy_params();
        fee_params.min_fee_msat = Msat(10_000);
        fee_params.min_payment_size_msat = Msat(1);
        let fee_params = fee_params.with_promise(&test_secret());

        let request = Lsps2BuyRequest {
            opening_fee_params: fee_params,
            payment_size_msat: Some(Msat(5_000)), // Less than min_fee
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, 202); // fee exceeds payment
    }

    #[tokio::test]
    async fn buy_handles_blockheight_error() {
        let api = MockApi::new().with_blockheight_error();
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(50_000_000)),
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, -32603);
    }

    #[tokio::test]
    async fn buy_handles_store_error() {
        let api = MockApi::new().with_blockheight(800_000).with_store_error();
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(50_000_000)),
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, -32603);
    }

    #[tokio::test]
    async fn buy_handles_store_returns_false() {
        let api = MockApi::new()
            .with_blockheight(800_000)
            .with_store_result(false);
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: Some(Msat(50_000_000)),
        };

        let result = h.handle_buy(test_peer_id(), request).await;

        let err = result.unwrap_err();
        assert_eq!(err.code, -32603);
    }

    #[tokio::test]
    async fn buy_generates_unique_scids() {
        let api = MockApi::new()
            .with_blockheight(800_000)
            .with_store_result(true);
        let h = handler(api);

        let request = Lsps2BuyRequest {
            opening_fee_params: test_opening_fee_params(&test_secret()),
            payment_size_msat: None,
        };

        let r1 = h.handle_buy(test_peer_id(), request.clone()).await.unwrap();
        let r2 = h.handle_buy(test_peer_id(), request).await.unwrap();

        assert_ne!(r1.jit_channel_scid, r2.jit_channel_scid);
    }
}
