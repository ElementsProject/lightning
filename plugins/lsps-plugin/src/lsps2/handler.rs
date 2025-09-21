use crate::{
    jsonrpc::{server::RequestHandler, JsonRpcResponse as _, RequestObject, RpcError},
    lsps0::primitives::ShortChannelId,
    lsps2::{
        model::{
            DatastoreEntry, Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest,
            Lsps2GetInfoResponse, Lsps2PolicyGetInfoRequest, Lsps2PolicyGetInfoResponse,
            OpeningFeeParams, Promise,
        },
        DS_MAIN_KEY, DS_SUB_KEY,
    },
    util::unwrap_payload_with_peer_id,
};
use anyhow::{Context, Result as AnyResult};
use async_trait::async_trait;
use cln_rpc::{
    model::{
        requests::{DatastoreMode, DatastoreRequest, GetinfoRequest},
        responses::{DatastoreResponse, GetinfoResponse},
    },
    ClnRpc,
};
use log::warn;
use rand::{rng, Rng as _};
use std::path::PathBuf;

#[async_trait]
pub trait ClnApi: Send + Sync {
    async fn lsps2_getpolicy(
        &self,
        params: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse>;

    async fn cln_getinfo(&self, params: &GetinfoRequest) -> AnyResult<GetinfoResponse>;

    async fn cln_datastore(&self, params: &DatastoreRequest) -> AnyResult<DatastoreResponse>;
}

const DEFAULT_CLTV_EXPIRY_DELTA: u32 = 144;

#[derive(Clone)]
pub struct ClnApiRpc {
    rpc_path: PathBuf,
}

impl ClnApiRpc {
    pub fn new(rpc_path: PathBuf) -> Self {
        Self { rpc_path }
    }

    async fn create_rpc(&self) -> AnyResult<ClnRpc> {
        ClnRpc::new(&self.rpc_path).await
    }
}

#[async_trait]
impl ClnApi for ClnApiRpc {
    async fn lsps2_getpolicy(
        &self,
        params: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("dev-lsps2-getpolicy", params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling dev-lsps2-getpolicy")
    }

    async fn cln_getinfo(&self, params: &GetinfoRequest) -> AnyResult<GetinfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling getinfo")
    }

    async fn cln_datastore(&self, params: &DatastoreRequest) -> AnyResult<DatastoreResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling datastore")
    }
}

/// Handler for the `lsps2.get_info` method.
pub struct Lsps2GetInfoHandler<A: ClnApi> {
    pub api: A,
    pub promise_secret: [u8; 32],
}

impl<A: ClnApi> Lsps2GetInfoHandler<A> {
    pub fn new(api: A, promise_secret: [u8; 32]) -> Self {
        Self {
            api,
            promise_secret,
        }
    }
}

/// The RequestHandler calls the internal rpc command `dev-lsps2-getinfo`. It
/// expects a plugin has registered this command and manages policies for the
/// LSPS2 service.
#[async_trait]
impl<T: ClnApi + 'static> RequestHandler for Lsps2GetInfoHandler<T> {
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
        let (payload, _) = unwrap_payload_with_peer_id(payload);

        let req: RequestObject<Lsps2GetInfoRequest> = serde_json::from_slice(&payload)
            .map_err(|e| RpcError::parse_error(format!("failed to parse request: {e}")))?;

        if req.id.is_none() {
            // Is a notification we can not reply so we just return
            return Ok(vec![]);
        }
        let params = req
            .params
            .ok_or(RpcError::invalid_params("expected params but was missing"))?;

        let policy_params: Lsps2PolicyGetInfoRequest = params.into();
        let res_data: Lsps2PolicyGetInfoResponse = self
            .api
            .lsps2_getpolicy(&policy_params)
            .await
            .map_err(|e| RpcError {
            code: 200,
            message: format!("failed to fetch policy {e:#}"),
            data: None,
        })?;

        let opening_fee_params_menu = res_data
            .policy_opening_fee_params_menu
            .iter()
            .map(|v| {
                let promise: Promise = v
                    .get_hmac_hex(&self.promise_secret)
                    .try_into()
                    .map_err(|e| RpcError::internal_error(format!("invalid promise: {e}")))?;
                Ok(OpeningFeeParams {
                    min_fee_msat: v.min_fee_msat,
                    proportional: v.proportional,
                    valid_until: v.valid_until,
                    min_lifetime: v.min_lifetime,
                    max_client_to_self_delay: v.max_client_to_self_delay,
                    min_payment_size_msat: v.min_payment_size_msat,
                    max_payment_size_msat: v.max_payment_size_msat,
                    promise,
                })
            })
            .collect::<Result<Vec<_>, RpcError>>()?;

        let res = Lsps2GetInfoResponse {
            opening_fee_params_menu,
        }
        .into_response(req.id.unwrap()); // We checked that we got an id before.

        serde_json::to_vec(&res)
            .map_err(|e| RpcError::internal_error(format!("Failed to serialize response: {}", e)))
    }
}

pub struct Lsps2BuyHandler<A: ClnApi> {
    pub api: A,
    pub promise_secret: [u8; 32],
}

impl<A: ClnApi> Lsps2BuyHandler<A> {
    pub fn new(api: A, promise_secret: [u8; 32]) -> Self {
        Self {
            api,
            promise_secret,
        }
    }
}

#[async_trait]
impl<A: ClnApi + 'static> RequestHandler for Lsps2BuyHandler<A> {
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
        let (payload, peer_id) = unwrap_payload_with_peer_id(payload);

        let req: RequestObject<Lsps2BuyRequest> = serde_json::from_slice(&payload)
            .map_err(|e| RpcError::parse_error(format!("Failed to parse request: {}", e)))?;

        if req.id.is_none() {
            // Is a notification we can not reply so we just return
            return Ok(vec![]);
        }

        let req_params = req
            .params
            .ok_or_else(|| RpcError::invalid_request("Missing params field"))?;

        let fee_params = req_params.opening_fee_params;

        // FIXME: In the future we should replace the \`None\` with a meaningful
        // value that reflects the inbound capacity for this node from the
        // public network for a better pre-condition check on the payment_size.
        fee_params.validate(&self.promise_secret, req_params.payment_size_msat, None)?;

        // Generate a tmp scid to identify jit channel request in htlc.
        let get_info_req = GetinfoRequest {};
        let info = self.api.cln_getinfo(&get_info_req).await.map_err(|e| {
            warn!("Failed to call getinfo via rpc {}", e);
            RpcError::internal_error("Internal error")
        })?;

        // FIXME: Future task: Check that we don't conflict with any jit scid we
        // already handed out -> Check datastore entries.
        let jit_scid_u64 = generate_jit_scid(info.blockheight);
        let jit_scid = ShortChannelId::from(jit_scid_u64);
        let ds_data = DatastoreEntry {
            peer_id,
            opening_fee_params: fee_params,
            expected_payment_size: req_params.payment_size_msat,
        };
        let ds_json = serde_json::to_string(&ds_data).map_err(|e| {
            warn!("Failed to serialize opening fee params to string {}", e);
            RpcError::internal_error("Internal error")
        })?;

        let ds_req = DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::MUST_CREATE),
            string: Some(ds_json),
            key: vec![
                DS_MAIN_KEY.to_string(),
                DS_SUB_KEY.to_string(),
                jit_scid.to_string(),
            ],
        };

        let _ds_res = self.api.cln_datastore(&ds_req).await.map_err(|e| {
            warn!("Failed to store jit request in ds via rpc {}", e);
            RpcError::internal_error("Internal error")
        })?;

        let res = Lsps2BuyResponse {
            jit_channel_scid: jit_scid,
            // We can make this configurable if necessary.
            lsp_cltv_expiry_delta: DEFAULT_CLTV_EXPIRY_DELTA,
            // We can implement the other mode later on as we might have to do
            // some additional work on core-lightning to enable this.
            client_trusts_lsp: false,
        }
        .into_response(req.id.unwrap()); // We checked that we got an id before.

        serde_json::to_vec(&res)
            .map_err(|e| RpcError::internal_error(format!("Failed to serialize response: {}", e)))
    }
}

fn generate_jit_scid(best_blockheigt: u32) -> u64 {
    let mut rng = rng();
    let block = best_blockheigt + 6; // Approx 1 hour in the future and should avoid collision with confirmed channels
    let tx_idx: u32 = rng.random_range(0..5000);
    let output_idx: u16 = rng.random_range(0..10);

    ((block as u64) << 40) | ((tx_idx as u64) << 16) | (output_idx as u64)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{
        jsonrpc::{JsonRpcRequest, ResponseObject},
        lsps0::primitives::{Msat, Ppm},
        lsps2::model::PolicyOpeningFeeParams,
        util::wrap_payload_with_peer_id,
    };
    use chrono::{TimeZone, Utc};
    use cln_rpc::primitives::{Amount, PublicKey};
    use cln_rpc::RpcError as ClnRpcError;
    use serde::Serialize;

    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn create_peer_id() -> PublicKey {
        PublicKey::from_slice(&PUBKEY).expect("Valid pubkey")
    }

    fn create_wrapped_request<T: Serialize>(request: &RequestObject<T>) -> Vec<u8> {
        let payload = serde_json::to_vec(request).expect("Failed to serialize request");
        wrap_payload_with_peer_id(&payload, create_peer_id())
    }

    /// Build a pair: policy params + buy params with a Promise derived from `secret`
    fn params_with_promise(secret: &[u8; 32]) -> (PolicyOpeningFeeParams, OpeningFeeParams) {
        let policy = PolicyOpeningFeeParams {
            min_fee_msat: Msat(2_000),
            proportional: Ppm(10_000),
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 42,
            min_payment_size_msat: Msat(1_000_000),
            max_payment_size_msat: Msat(100_000_000),
        };
        let hex = policy.get_hmac_hex(secret);
        let promise: Promise = hex.try_into().expect("hex->Promise");
        let buy = OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        };
        (policy, buy)
    }

    #[derive(Clone, Default)]
    struct FakeCln {
        lsps2_getpolicy_response: Arc<Mutex<Option<Lsps2PolicyGetInfoResponse>>>,
        lsps2_getpolicy_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_getinfo_response: Arc<Mutex<Option<GetinfoResponse>>>,
        cln_getinfo_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_datastore_response: Arc<Mutex<Option<DatastoreResponse>>>,
        cln_datastore_error: Arc<Mutex<Option<ClnRpcError>>>,
    }

    #[async_trait]
    impl ClnApi for FakeCln {
        async fn lsps2_getpolicy(
            &self,
            _params: &Lsps2PolicyGetInfoRequest,
        ) -> Result<Lsps2PolicyGetInfoResponse, anyhow::Error> {
            if let Some(err) = self.lsps2_getpolicy_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.lsps2_getpolicy_response.lock().unwrap().take() {
                return Ok(res);
            };
            panic!("No lsps2 response defined");
        }

        async fn cln_getinfo(
            &self,
            _params: &GetinfoRequest,
        ) -> Result<GetinfoResponse, anyhow::Error> {
            if let Some(err) = self.cln_getinfo_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.cln_getinfo_response.lock().unwrap().take() {
                return Ok(res);
            };
            panic!("No cln getinfo response defined");
        }

        async fn cln_datastore(
            &self,
            _params: &DatastoreRequest,
        ) -> Result<DatastoreResponse, anyhow::Error> {
            if let Some(err) = self.cln_datastore_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.cln_datastore_response.lock().unwrap().take() {
                return Ok(res);
            };
            panic!("No cln datastore response defined");
        }
    }

    fn minimal_getinfo(height: u32) -> GetinfoResponse {
        GetinfoResponse {
            lightning_dir: String::default(),
            alias: None,
            our_features: None,
            warning_bitcoind_sync: None,
            warning_lightningd_sync: None,
            address: None,
            binding: None,
            blockheight: height,
            color: String::default(),
            fees_collected_msat: Amount::from_msat(0),
            id: PublicKey::from_slice(&PUBKEY).expect("pubkey from slice"),
            network: String::default(),
            num_active_channels: u32::default(),
            num_inactive_channels: u32::default(),
            num_peers: u32::default(),
            num_pending_channels: u32::default(),
            version: String::default(),
        }
    }

    #[tokio::test]
    async fn test_successful_get_info() {
        let promise_secret = [0u8; 32];
        let params = Lsps2PolicyGetInfoResponse {
            policy_opening_fee_params_menu: vec![PolicyOpeningFeeParams {
                min_fee_msat: Msat(2000),
                proportional: Ppm(10000),
                valid_until: Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(),
                min_lifetime: 1000,
                max_client_to_self_delay: 42,
                min_payment_size_msat: Msat(1000000),
                max_payment_size_msat: Msat(100000000),
            }],
        };
        let promise = params.policy_opening_fee_params_menu[0].get_hmac_hex(&promise_secret);
        let fake = FakeCln::default();
        *fake.lsps2_getpolicy_response.lock().unwrap() = Some(params);
        let handler = Lsps2GetInfoHandler::new(fake, promise_secret);

        let request = Lsps2GetInfoRequest { token: None }.into_request(Some("test-id".to_string()));
        let payload = create_wrapped_request(&request);

        let result = handler.handle(&payload).await.unwrap();
        let response: ResponseObject<Lsps2GetInfoResponse> =
            serde_json::from_slice(&result).unwrap();
        let response = response.into_inner().unwrap();

        assert_eq!(
            response.opening_fee_params_menu[0].min_payment_size_msat,
            Msat(1000000)
        );
        assert_eq!(
            response.opening_fee_params_menu[0].max_payment_size_msat,
            Msat(100000000)
        );
        assert_eq!(
            response.opening_fee_params_menu[0].promise,
            promise.try_into().unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_info_rpc_error_handling() {
        let fake = FakeCln::default();
        *fake.lsps2_getpolicy_error.lock().unwrap() = Some(ClnRpcError {
            code: Some(-1),
            message: "not found".to_string(),
            data: None,
        });
        let handler = Lsps2GetInfoHandler::new(fake, [0; 32]);
        let request = Lsps2GetInfoRequest { token: None }.into_request(Some("test-id".to_string()));
        let payload = create_wrapped_request(&request);

        let result = handler.handle(&payload).await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, 200);
        assert!(error.message.contains("failed to fetch policy"));
    }

    #[tokio::test]
    async fn buy_ok_fixed_amount() {
        let secret = [0u8; 32];
        let fake = FakeCln::default();
        *fake.cln_getinfo_response.lock().unwrap() = Some(minimal_getinfo(900_000));
        *fake.cln_datastore_response.lock().unwrap() = Some(DatastoreResponse {
            generation: Some(0),
            hex: None,
            string: None,
            key: vec![],
        });

        let handler = Lsps2BuyHandler::new(fake, secret);
        let (_policy, buy) = params_with_promise(&secret);

        // Set payment_size_msat => "MPP+fixed-invoice" mode.
        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(2_000_000)),
        }
        .into_request(Some("ok-fixed".into()));
        let payload = create_wrapped_request(&req);

        let out = handler.handle(&payload).await.unwrap();
        let resp: ResponseObject<Lsps2BuyResponse> = serde_json::from_slice(&out).unwrap();
        let resp = resp.into_inner().unwrap();

        assert_eq!(resp.lsp_cltv_expiry_delta, DEFAULT_CLTV_EXPIRY_DELTA);
        assert!(!resp.client_trusts_lsp);
        assert!(resp.jit_channel_scid.to_u64() > 0);
    }

    #[tokio::test]
    async fn buy_ok_variable_amount_no_payment_size() {
        let secret = [2u8; 32];
        let fake = FakeCln::default();
        *fake.cln_getinfo_response.lock().unwrap() = Some(minimal_getinfo(900_100));
        *fake.cln_datastore_response.lock().unwrap() = Some(DatastoreResponse {
            generation: Some(0),
            hex: None,
            string: None,
            key: vec![],
        });

        let handler = Lsps2BuyHandler::new(fake, secret);
        let (_policy, buy) = params_with_promise(&secret);

        // No payment_size_msat => "no-MPP+var-invoice" mode.
        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: None,
        }
        .into_request(Some("ok-var".into()));
        let payload = create_wrapped_request(&req);

        let out = handler.handle(&payload).await.unwrap();
        let resp: ResponseObject<Lsps2BuyResponse> = serde_json::from_slice(&out).unwrap();
        assert!(resp.into_inner().is_ok());
    }

    #[tokio::test]
    async fn buy_rejects_invalid_promise_or_past_valid_until_with_201() {
        let secret = [3u8; 32];
        let handler = Lsps2BuyHandler::new(FakeCln::default(), secret);

        // Case A: wrong promise (derive with different secret)
        let (_policy_wrong, mut buy_wrong) = params_with_promise(&[9u8; 32]);
        buy_wrong.valid_until = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(); // future, so only promise is wrong
        let req_wrong = Lsps2BuyRequest {
            opening_fee_params: buy_wrong,
            payment_size_msat: Some(Msat(2_000_000)),
        }
        .into_request(Some("bad-promise".into()));
        let err1 = handler
            .handle(&create_wrapped_request(&req_wrong))
            .await
            .unwrap_err();
        assert_eq!(err1.code, 201);

        // Case B: past valid_until
        let (_policy, mut buy_past) = params_with_promise(&secret);
        buy_past.valid_until = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(); // past
        let req_past = Lsps2BuyRequest {
            opening_fee_params: buy_past,
            payment_size_msat: Some(Msat(2_000_000)),
        }
        .into_request(Some("past-valid".into()));
        let err2 = handler
            .handle(&create_wrapped_request(&req_past))
            .await
            .unwrap_err();
        assert_eq!(err2.code, 201);
    }

    #[tokio::test]
    async fn buy_rejects_when_opening_fee_ge_payment_size_with_202() {
        let secret = [4u8; 32];
        let handler = Lsps2BuyHandler::new(FakeCln::default(), secret);

        // Make min_fee already >= payment_size to trigger 202
        let policy = PolicyOpeningFeeParams {
            min_fee_msat: Msat(10_000),
            proportional: Ppm(0), // no extra percentage
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 42,
            min_payment_size_msat: Msat(1),
            max_payment_size_msat: Msat(u64::MAX / 2),
        };
        let hex = policy.get_hmac_hex(&secret);
        let promise: Promise = hex.try_into().unwrap();
        let buy = OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        };

        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(9_999)), // strictly less than min_fee => opening_fee >= payment_size
        }
        .into_request(Some("too-small".into()));

        let err = handler
            .handle(&create_wrapped_request(&req))
            .await
            .unwrap_err();
        assert_eq!(err.code, 202);
    }

    #[tokio::test]
    async fn buy_rejects_on_fee_overflow_with_203() {
        let secret = [5u8; 32];
        let handler = Lsps2BuyHandler::new(FakeCln::default(), secret);

        // Choose values likely to overflow if multiplication isn't checked:
        // opening_fee = min_fee + payment_size * proportional / 1_000_000
        let policy = PolicyOpeningFeeParams {
            min_fee_msat: Msat(u64::MAX / 2),
            proportional: Ppm(u32::MAX), // 4_294_967_295 ppm
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 42,
            min_payment_size_msat: Msat(1),
            max_payment_size_msat: Msat(u64::MAX),
        };
        let hex = policy.get_hmac_hex(&secret);
        let promise: Promise = hex.try_into().unwrap();
        let buy = OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        };

        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(u64::MAX / 2)),
        }
        .into_request(Some("overflow".into()));

        let err = handler
            .handle(&create_wrapped_request(&req))
            .await
            .unwrap_err();
        assert_eq!(err.code, 203);
    }
}
