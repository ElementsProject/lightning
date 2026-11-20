use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
use lsps_types::{
    lsps0::{DateTime, Msat, Ppm, ShortChannelId},
    lsps2::{Lsps2GetInfoRequest, OpeningFeeParams, Promise},
};
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
        // Rebuild valid_until so it is sent in the LSPS0 datetime format,
        // and compute the promise over exactly the value the client echoes.
        let policy = PolicyOpeningFeeParams {
            valid_until: self.valid_until.as_chrono().into(),
            ..self.clone()
        };
        let promise =
            Promise::try_from(policy.get_hmac_hex(secret)).expect("hex HMAC is a valid promise");
        OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        }
    }
}

impl From<&OpeningFeeParams> for PolicyOpeningFeeParams {
    fn from(params: &OpeningFeeParams) -> Self {
        PolicyOpeningFeeParams {
            min_fee_msat: params.min_fee_msat,
            proportional: params.proportional,
            valid_until: params.valid_until.clone(),
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
    fn test_with_promise_sends_spec_datetime() {
        // A policy plugin may hand out any RFC 3339 string with any
        // precision; the LSP sends the LSPS0 format and its promise must
        // still verify on the echoed params.
        let mut json = serde_json::to_value(policy()).unwrap();
        json["valid_until"] = "2100-01-01T02:00:00.123456789+02:00".into();
        let policy: PolicyOpeningFeeParams = serde_json::from_value(json).unwrap();

        let params = policy.with_promise(SECRET);
        let sent = serde_json::to_value(&params).unwrap();
        assert_eq!(sent["valid_until"], "2100-01-01T00:00:00.123Z");

        let echoed: OpeningFeeParams = serde_json::from_value(sent).unwrap();
        assert!(verify_promise(&echoed, SECRET));
    }

    #[test]
    fn test_verify_promise_survives_serde() {
        let params = policy().with_promise(SECRET);
        let json = serde_json::to_string(&params).unwrap();
        let back: OpeningFeeParams = serde_json::from_str(&json).unwrap();
        assert!(verify_promise(&back, SECRET));
    }

    // Pinned promises. Changing how a promise is computed voids every offer
    // an LSP has handed out and not yet sold, so these must keep passing.
    //
    // The promise is the lowercase hex of
    //
    //   HMAC-SHA256(secret, min_fee_msat u64 ‖ proportional u32
    //                       ‖ valid_until as chrono's to_rfc3339()
    //                       ‖ min_lifetime u32 ‖ max_client_to_self_delay u32
    //                       ‖ min_payment_size_msat u64
    //                       ‖ max_payment_size_msat u64)
    //
    // with the integers big-endian. This is not the LSPS0 wire format:
    // to_rfc3339() writes the instant in UTC with a "+00:00" offset and
    // fractional digits only if they're not zero, so a promise issued at
    // millisecond precision covers "2026-11-05T12:00:00+00:00" or
    // "2026-11-05T12:00:00.123+00:00".

    fn secret_seq() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, b) in (1u8..).zip(bytes.iter_mut()) {
            *b = i;
        }
        bytes
    }

    fn terms(valid_until: &str) -> PolicyOpeningFeeParams {
        PolicyOpeningFeeParams {
            min_fee_msat: Msat(2_500_000),
            proportional: Ppm(1000),
            valid_until: serde_json::from_value(valid_until.into()).unwrap(),
            min_lifetime: 1008,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat(1_000_000),
            max_payment_size_msat: Msat(100_000_000),
        }
    }

    fn max_terms(valid_until: &str) -> PolicyOpeningFeeParams {
        PolicyOpeningFeeParams {
            min_fee_msat: Msat(u64::MAX),
            proportional: Ppm(u32::MAX),
            min_lifetime: u32::MAX,
            max_client_to_self_delay: u32::MAX,
            min_payment_size_msat: Msat(u64::MAX),
            max_payment_size_msat: Msat(u64::MAX),
            ..terms(valid_until)
        }
    }

    fn zero_terms(valid_until: &str) -> PolicyOpeningFeeParams {
        PolicyOpeningFeeParams {
            min_fee_msat: Msat(0),
            proportional: Ppm(0),
            min_lifetime: 0,
            max_client_to_self_delay: 0,
            min_payment_size_msat: Msat(0),
            max_payment_size_msat: Msat(0),
            ..terms(valid_until)
        }
    }

    /// `(secret, policy, promise)`. The same vectors are pinned in blsp's
    /// lsps2-service, which verifies promises this plugin issued.
    fn promise_vectors() -> Vec<([u8; 32], PolicyOpeningFeeParams, &'static str)> {
        vec![
            (
                [0x42; 32],
                terms("2026-11-05T12:00:00Z"),
                "b728579dcc1ede498a6537c29c180fd30b28bacc231d1e6f3332cd74faeace5a",
            ),
            (
                [0x42; 32],
                terms("2026-11-05T12:00:00.123Z"),
                "5240417633c7b123a0e0daafbded66ba9d5607e2ba1a5656db670fe351faee3c",
            ),
            (
                secret_seq(),
                terms("2026-11-05T12:00:00Z"),
                "fe5d444bf738528a75666d55495989d12fee6984d9c72ad7227d0f6cc68f27fc",
            ),
            (
                [0xff; 32],
                max_terms("9999-12-31T23:59:59.999Z"),
                "5c7bd14b2c9625409527820a3bca5bc1b189ea376776046c8ea96bae4889f350",
            ),
            (
                [0; 32],
                zero_terms("1970-01-01T00:00:00Z"),
                "9543ebd29b9d847f173a5830744053bbd2f4ba14a41ddb38858164431d838db6",
            ),
        ]
    }

    #[test]
    fn test_with_promise_matches_pinned_promises() {
        for (secret, policy, promise) in promise_vectors() {
            let params = policy.with_promise(&secret);
            assert_eq!(params.promise.as_str(), promise, "{:?}", policy.valid_until);
            assert!(verify_promise(&params, &secret));
        }
    }

    #[test]
    fn test_verify_promise_accepts_valid_until_in_any_rfc3339_form() {
        // The promise covers the instant, not how the client spells it.
        let promise = "b728579dcc1ede498a6537c29c180fd30b28bacc231d1e6f3332cd74faeace5a";
        for valid_until in [
            "2026-11-05T12:00:00Z",
            "2026-11-05T12:00:00.000Z",
            "2026-11-05T12:00:00+00:00",
            "2026-11-05T13:00:00+01:00",
        ] {
            let mut params = terms(valid_until).with_promise(&[0x42; 32]);
            params.promise = Promise::try_from(promise).unwrap();
            params.valid_until = serde_json::from_value(valid_until.into()).unwrap();
            assert!(verify_promise(&params, &[0x42; 32]), "{valid_until}");
        }
    }
}
