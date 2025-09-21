use crate::{
    jsonrpc::{server::RequestHandler, JsonRpcResponse as _, RequestObject, RpcError},
    lsps2::model::{
        Lsps2GetInfoRequest, Lsps2GetInfoResponse, Lsps2PolicyGetInfoRequest,
        Lsps2PolicyGetInfoResponse, OpeningFeeParams, Promise,
    },
    util::unwrap_payload_with_peer_id,
};
use anyhow::{Context, Result as AnyResult};
use async_trait::async_trait;
use cln_rpc::ClnRpc;
use std::path::PathBuf;

#[async_trait]
pub trait ClnApi: Send + Sync {
    async fn lsps2_getpolicy(
        &self,
        params: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse>;
}

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
    use cln_rpc::primitives::PublicKey;
    use cln_rpc::RpcError as ClnRpcError;

    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn create_peer_id() -> PublicKey {
        PublicKey::from_slice(&PUBKEY).expect("Valid pubkey")
    }

    fn create_wrapped_request(request: &RequestObject<Lsps2GetInfoRequest>) -> Vec<u8> {
        let payload = serde_json::to_vec(request).expect("Failed to serialize request");
        wrap_payload_with_peer_id(&payload, create_peer_id())
    }

    #[derive(Clone, Default)]
    struct FakeCln {
        lsps2_getpolicy_response: Arc<Mutex<Option<Lsps2PolicyGetInfoResponse>>>,
        lsps2_getpolicy_error: Arc<Mutex<Option<ClnRpcError>>>,
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
}
