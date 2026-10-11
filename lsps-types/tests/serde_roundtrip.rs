//! Serde roundtrips for all message types: every value must serialize to
//! JSON and deserialize back to an equal value.

use lsps_types::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RequestObject, RpcError};
use lsps_types::lsps0::{
    DateTime, Lsps0listProtocolsRequest, Lsps0listProtocolsResponse, Msat, Ppm, ShortChannelId,
};
use lsps_types::lsps2::{
    Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest, Lsps2GetInfoResponse, OpeningFeeParams,
    Promise,
};
use proptest::prelude::*;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

fn roundtrip<T>(value: &T) -> Result<(), TestCaseError>
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let json = serde_json::to_string(value).expect("serialize");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    prop_assert_eq!(&back, value, "json: {}", json);
    Ok(())
}

fn msat() -> impl Strategy<Value = Msat> {
    any::<u64>().prop_map(Msat::from_msat)
}

fn ppm() -> impl Strategy<Value = Ppm> {
    any::<u32>().prop_map(Ppm::from_ppm)
}

fn scid() -> impl Strategy<Value = ShortChannelId> {
    any::<u64>().prop_map(ShortChannelId::from)
}

/// Millisecond precision from 1970 to 9999, as LSPS0.datetime can express.
fn datetime() -> impl Strategy<Value = DateTime> {
    (0i64..=253_402_300_799_999).prop_map(|ms| {
        chrono::DateTime::from_timestamp_millis(ms)
            .expect("in range")
            .into()
    })
}

/// Printable ASCII without '"' and '\', at most 512 bytes.
fn promise() -> impl Strategy<Value = Promise> {
    "[ !#-\\[\\]-~]{0,512}".prop_map(|s| Promise::try_from(s).expect("valid promise"))
}

fn opening_fee_params() -> impl Strategy<Value = OpeningFeeParams> {
    (
        msat(),
        ppm(),
        datetime(),
        any::<u32>(),
        any::<u32>(),
        msat(),
        msat(),
        promise(),
    )
        .prop_map(
            |(
                min_fee_msat,
                proportional,
                valid_until,
                min_lifetime,
                max_client_to_self_delay,
                min_payment_size_msat,
                max_payment_size_msat,
                promise,
            )| OpeningFeeParams {
                min_fee_msat,
                proportional,
                valid_until,
                min_lifetime,
                max_client_to_self_delay,
                min_payment_size_msat,
                max_payment_size_msat,
                promise,
            },
        )
}

fn get_info_request() -> impl Strategy<Value = Lsps2GetInfoRequest> {
    proptest::option::of(any::<String>()).prop_map(|token| Lsps2GetInfoRequest { token })
}

fn get_info_response() -> impl Strategy<Value = Lsps2GetInfoResponse> {
    proptest::collection::vec(opening_fee_params(), 0..4).prop_map(|opening_fee_params_menu| {
        Lsps2GetInfoResponse {
            opening_fee_params_menu,
        }
    })
}

fn buy_request() -> impl Strategy<Value = Lsps2BuyRequest> {
    (opening_fee_params(), proptest::option::of(msat())).prop_map(
        |(opening_fee_params, payment_size_msat)| Lsps2BuyRequest {
            opening_fee_params,
            payment_size_msat,
        },
    )
}

fn buy_response() -> impl Strategy<Value = Lsps2BuyResponse> {
    (scid(), any::<u32>(), any::<bool>()).prop_map(
        |(jit_channel_scid, lsp_cltv_expiry_delta, client_trusts_lsp)| Lsps2BuyResponse {
            jit_channel_scid,
            lsp_cltv_expiry_delta,
            client_trusts_lsp,
        },
    )
}

fn rpc_error() -> impl Strategy<Value = RpcError> {
    (
        any::<i64>(),
        any::<String>(),
        proptest::option::of(any::<String>()),
    )
        .prop_map(|(code, message, data)| RpcError {
            code,
            message,
            data: data.map(serde_json::Value::String),
        })
}

fn request<T: JsonRpcRequest + Debug>(
    params: impl Strategy<Value = T>,
) -> impl Strategy<Value = RequestObject<T>> {
    (params, proptest::option::of(any::<String>()))
        .prop_map(|(params, id)| params.into_request_with_id(id))
}

fn response<R: Debug>(
    result: impl Strategy<Value = R>,
) -> impl Strategy<Value = JsonRpcResponse<R>> {
    (result, any::<String>()).prop_map(|(result, id)| JsonRpcResponse::success(result, id))
}

proptest! {
    #[test]
    fn primitives(msat in msat(), ppm in ppm(), scid in scid(), datetime in datetime()) {
        roundtrip(&msat)?;
        roundtrip(&ppm)?;
        roundtrip(&scid)?;
        roundtrip(&datetime)?;
    }

    #[test]
    fn promise_roundtrip(promise in promise()) {
        roundtrip(&promise)?;
    }

    #[test]
    fn opening_fee_params_roundtrip(params in opening_fee_params()) {
        roundtrip(&params)?;
    }

    #[test]
    fn list_protocols(protocols in proptest::collection::vec(any::<u8>(), 0..8)) {
        roundtrip(&Lsps0listProtocolsRequest {})?;
        roundtrip(&Lsps0listProtocolsResponse { protocols })?;
    }

    #[test]
    fn get_info(req in get_info_request(), resp in get_info_response()) {
        roundtrip(&req)?;
        roundtrip(&resp)?;
    }

    #[test]
    fn buy(req in buy_request(), resp in buy_response()) {
        roundtrip(&req)?;
        roundtrip(&resp)?;
    }

    #[test]
    fn jsonrpc_requests(
        list_protocols in request(Just(Lsps0listProtocolsRequest {})),
        get_info in request(get_info_request()),
        buy in request(buy_request()),
    ) {
        roundtrip(&list_protocols)?;
        roundtrip(&get_info)?;
        roundtrip(&buy)?;
    }

    #[test]
    fn jsonrpc_responses(
        get_info in response(get_info_response()),
        buy in response(buy_response()),
        error in rpc_error(),
        id in any::<String>(),
    ) {
        roundtrip(&get_info)?;
        roundtrip(&buy)?;
        roundtrip(&JsonRpcResponse::error(error, id))?;
    }
}

/// The example messages from bLIP-52 parse and serialize back to the same
/// JSON.
#[test]
fn spec_examples() {
    fn check<T: Serialize + DeserializeOwned>(json: &str) {
        let value: T = serde_json::from_str(json).expect("parse spec example");
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap(),
        );
    }

    // Example `lsps2.get_info` result.
    check::<Lsps2GetInfoResponse>(
        r#"{
            "opening_fee_params_menu": [
                {
                    "min_fee_msat": "546000",
                    "proportional": 1200,
                    "valid_until": "2023-02-23T08:47:30.511Z",
                    "min_lifetime": 1008,
                    "max_client_to_self_delay": 2016,
                    "min_payment_size_msat": "1000",
                    "max_payment_size_msat": "1000000",
                    "promise": "abcdefghijklmnopqrstuvwxyz"
                },
                {
                    "min_fee_msat": "1092000",
                    "proportional": 2400,
                    "valid_until": "2023-02-27T21:23:57.984Z",
                    "min_lifetime": 1008,
                    "max_client_to_self_delay": 2016,
                    "min_payment_size_msat": "1000",
                    "max_payment_size_msat": "1000000",
                    "promise": "abcdefghijklmnopqrstuvwxyz"
                }
            ]
        }"#,
    );

    // Example `lsps2.buy` request parameters.
    check::<Lsps2BuyRequest>(
        r#"{
            "opening_fee_params": {
                "min_fee_msat": "546000",
                "proportional": 1200,
                "valid_until": "2023-02-23T08:47:30.511Z",
                "min_lifetime": 1008,
                "max_client_to_self_delay": 2016,
                "min_payment_size_msat": "1000",
                "max_payment_size_msat": "1000000",
                "promise": "abcdefghijklmnopqrstuvwxyz"
            },
            "payment_size_msat": "42000"
        }"#,
    );

    // Example successful `lsps2.buy` result.
    check::<Lsps2BuyResponse>(
        r#"{
            "jit_channel_scid": "29451x4815x1",
            "lsp_cltv_expiry_delta" : 144,
            "client_trusts_lsp": false
        }"#,
    );
}
