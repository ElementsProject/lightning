//! LSPS2 (bLIP-52): JIT channel negotiation messages, opening fee
//! parameters and the opening fee computation.

use crate::jsonrpc::{JsonRpcRequest, RpcError};
use crate::lsps0::{Msat, ShortChannelId};
use serde::{Deserialize, Serialize};

mod fee;
mod params;
mod promise;

pub use fee::compute_opening_fee;
pub use params::{OpeningFeeParams, ValidationError};
pub use promise::{Promise, PromiseError};

// Lsps2 specific error codes defined in BLIP-52.
// Are in the range 00200 to 00299.
pub mod error_codes {
    pub const UNRECOGNIZED_OR_STALE_TOKEN: i64 = 200;
    pub const INVALID_OPENING_FEE_PARAMS: i64 = 201;
    pub const PAYMENT_SIZE_TOO_SMALL: i64 = 202;
    pub const PAYMENT_SIZE_TOO_LARGE: i64 = 203;
}

/// The `lsps2.buy` errors defined in bLIP-52.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidOpeningFeeParams,
    PaymentSizeTooSmall,
    PaymentSizeTooLarge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str = match self {
            Error::InvalidOpeningFeeParams => "Invalid opening fee params",
            Error::PaymentSizeTooSmall => "Payment size too small",
            Error::PaymentSizeTooLarge => "Payment size too large",
        };
        write!(f, "{}", &err_str)
    }
}

impl From<Error> for RpcError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidOpeningFeeParams => RpcError::invalid_opening_fee_params(error),
            Error::PaymentSizeTooSmall => RpcError::payment_size_too_small(error),
            Error::PaymentSizeTooLarge => RpcError::payment_size_too_large(error),
        }
    }
}

impl core::error::Error for Error {}

pub trait LSPS2RpcErrorExt {
    rpc_error_methods! {
        unrecognized_or_stale_token, unrecognized_or_stale_token_with_data => error_codes::UNRECOGNIZED_OR_STALE_TOKEN,
        invalid_opening_fee_params, invalid_opening_fee_params_with_data => error_codes::INVALID_OPENING_FEE_PARAMS,
        payment_size_too_small, payment_size_too_small_with_data => error_codes::PAYMENT_SIZE_TOO_SMALL,
        payment_size_too_large, payment_size_too_large_with_data => error_codes::PAYMENT_SIZE_TOO_LARGE
    }
}

impl LSPS2RpcErrorExt for RpcError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsps2GetInfoRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl JsonRpcRequest for Lsps2GetInfoRequest {
    const METHOD: &'static str = "lsps2.get_info";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsps2GetInfoResponse {
    pub opening_fee_params_menu: Vec<OpeningFeeParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsps2BuyRequest {
    pub opening_fee_params: OpeningFeeParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_size_msat: Option<Msat>,
}

impl JsonRpcRequest for Lsps2BuyRequest {
    const METHOD: &'static str = "lsps2.buy";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsps2BuyResponse {
    pub jit_channel_scid: ShortChannelId,
    pub lsp_cltv_expiry_delta: u32,
    // is an optional Boolean. If not specified, it defaults to false. If
    // specified and true, the client MUST trust the LSP to actually create and
    // confirm a valid channel funding transaction.
    #[serde(default)]
    pub client_trusts_lsp: bool,
}
