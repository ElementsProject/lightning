pub use lsps_types::lsps2::*;

use crate::proto::lsps0::{DateTime, Msat, Ppm, ShortChannelId};
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
use serde::{Deserialize, Serialize};

pub mod failure_codes {
    pub const TEMPORARY_CHANNEL_FAILURE: &'static str = "1007";
    pub const UNKNOWN_NEXT_PEER: &'static str = "4010";
}

pub trait ShortChannelIdJITExt {
    fn generate_jit(blockheight: u32, distance: u32) -> Self;
}

impl ShortChannelIdJITExt for ShortChannelId {
    fn generate_jit(blockheight: u32, distance: u32) -> Self {
        use rand::{RngExt as _, rng};

        let mut rng = rng();
        let block = blockheight + distance;
        let tx_idx: u32 = rng.random_range(0..5000);
        let output_idx: u16 = rng.random_range(0..10);

        (((block as u64) << 40) | ((tx_idx as u64) << 16) | (output_idx as u64)).into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lsps2PolicyGetInfoRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl From<Lsps2GetInfoRequest> for Lsps2PolicyGetInfoRequest {
    fn from(value: Lsps2GetInfoRequest) -> Self {
        Self { token: value.token }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lsps2PolicyGetInfoResponse {
    pub policy_opening_fee_params_menu: Vec<PolicyOpeningFeeParams>,
    #[serde(default)]
    pub client_rejected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lsps2PolicyGetChannelCapacityRequest {
    pub opening_fee_params: OpeningFeeParams,
    pub init_payment_size: Msat,
    pub scid: ShortChannelId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lsps2PolicyGetChannelCapacityResponse {
    pub channel_capacity_msat: Option<u64>,
}

/// An internal representation of a policy of parameters for calculating the
/// opening fee for a JIT channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyOpeningFeeParams {
    pub min_fee_msat: Msat,
    pub proportional: Ppm,
    pub valid_until: DateTime,
    pub min_lifetime: u32,
    pub max_client_to_self_delay: u32,
    pub min_payment_size_msat: Msat,
    pub max_payment_size_msat: Msat,
}

impl PolicyOpeningFeeParams {
    pub fn get_hmac_hex(&self, secret: &[u8]) -> String {
        let mut hmac = HmacEngine::<sha256::Hash>::new(secret);
        hmac.input(&self.min_fee_msat.msat().to_be_bytes());
        hmac.input(&self.proportional.ppm().to_be_bytes());
        hmac.input(self.valid_until.as_chrono().to_rfc3339().as_bytes());
        hmac.input(&self.min_lifetime.to_be_bytes());
        hmac.input(&self.max_client_to_self_delay.to_be_bytes());
        hmac.input(&self.min_payment_size_msat.msat().to_be_bytes());
        hmac.input(&self.max_payment_size_msat.msat().to_be_bytes());
        let promise = Hmac::from_engine(hmac)
            .to_byte_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        promise
    }

    pub fn with_promise(&self, secret: &[u8; 32]) -> OpeningFeeParams {
        OpeningFeeParams {
            min_fee_msat: self.min_fee_msat,
            proportional: self.proportional,
            valid_until: self.valid_until,
            min_lifetime: self.min_lifetime,
            max_client_to_self_delay: self.max_client_to_self_delay,
            min_payment_size_msat: self.min_payment_size_msat,
            max_payment_size_msat: self.max_payment_size_msat,
            promise: Promise::try_from(self.get_hmac_hex(secret))
                .expect("hex HMAC is a valid promise"),
        }
    }
}

impl From<&OpeningFeeParams> for PolicyOpeningFeeParams {
    fn from(params: &OpeningFeeParams) -> Self {
        PolicyOpeningFeeParams {
            min_fee_msat: params.min_fee_msat,
            proportional: params.proportional,
            valid_until: params.valid_until,
            min_lifetime: params.min_lifetime,
            max_client_to_self_delay: params.max_client_to_self_delay,
            min_payment_size_msat: params.min_payment_size_msat,
            max_payment_size_msat: params.max_payment_size_msat,
        }
    }
}

/// LSPs MUST check that the opening_fee_params.promise does in fact prove
/// that it previously promised the specified opening_fee_params.
pub fn verify_promise(params: &OpeningFeeParams, secret: &[u8]) -> bool {
    PolicyOpeningFeeParams::from(params).get_hmac_hex(secret) == params.promise.as_str()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DatastoreEntry {
    pub peer_id: cln_rpc::primitives::PublicKey,
    pub opening_fee_params: OpeningFeeParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_payment_size: Option<Msat>,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;

    const SECRET: &[u8; 32] = b"test_secret_key_32_bytes_long___";

    fn policy() -> PolicyOpeningFeeParams {
        PolicyOpeningFeeParams {
            min_fee_msat: Msat::from_msat(1000),
            proportional: Ppm::from_ppm(1000),
            valid_until: (Utc::now() + Duration::hours(1)).into(),
            min_lifetime: 144,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat::from_msat(1000),
            max_payment_size_msat: Msat::from_msat(100_000_000_000),
        }
    }

    #[test]
    fn test_verify_promise_success() {
        let params = policy().with_promise(SECRET);
        assert_eq!(params.promise.as_str().len(), 64);
        assert!(verify_promise(&params, SECRET));
    }

    #[test]
    fn test_verify_promise_changed_param() {
        let mut params = policy().with_promise(SECRET);
        params.min_fee_msat = Msat(10);
        assert!(!verify_promise(&params, SECRET));
    }

    #[test]
    fn test_verify_promise_wrong_secret() {
        let params = policy().with_promise(SECRET);
        assert!(!verify_promise(
            &params,
            b"different_secret_key_32_bytes___"
        ));
    }

    #[test]
    fn test_verify_promise_survives_serde() {
        let params = policy().with_promise(SECRET);
        let json = serde_json::to_string(&params).unwrap();
        let back: OpeningFeeParams = serde_json::from_str(&json).unwrap();
        assert!(verify_promise(&back, SECRET));
    }
}
