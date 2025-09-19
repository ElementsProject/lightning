use crate::{
    jsonrpc::{JsonRpcRequest, RpcError},
    lsps0::primitives::{DateTime, Msat, Ppm, ShortChannelId},
};
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use chrono::Utc;
use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InvalidOpeningFeeParams,
    PaymentSizeTooSmall,
    PaymentSizeTooLarge,
    ClientRejected,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str = match self {
            Error::InvalidOpeningFeeParams => "invalid opening fee params",
            Error::PaymentSizeTooSmall => "payment size too small",
            Error::PaymentSizeTooLarge => "payment size too large",
            Error::ClientRejected => "client rejected",
        };
        write!(f, "{}", &err_str)
    }
}

impl From<Error> for RpcError {
    fn from(value: Error) -> Self {
        match value {
            Error::InvalidOpeningFeeParams => RpcError {
                code: 201,
                message: "invalid opening fee params".to_string(),
                data: None,
            },
            Error::PaymentSizeTooSmall => RpcError {
                code: 202,
                message: "payment size too small".to_string(),
                data: None,
            },
            Error::PaymentSizeTooLarge => RpcError {
                code: 203,
                message: "payment size too large".to_string(),
                data: None,
            },
            Error::ClientRejected => RpcError {
                code: 001,
                message: "client rejected".to_string(),
                data: None,
            },
        }
    }
}

impl core::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lsps2GetInfoRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl JsonRpcRequest for Lsps2GetInfoRequest {
    const METHOD: &'static str = "lsps2.get_info";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lsps2GetInfoResponse {
    pub opening_fee_params_menu: Vec<OpeningFeeParams>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PromiseError {
    TooLong { length: usize, max: usize },
}

impl core::fmt::Display for PromiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromiseError::TooLong { length, max } => {
                write!(
                    f,
                    "promise string is too long: {} bytes (max allowed {})",
                    length, max
                )
            }
        }
    }
}

impl core::error::Error for PromiseError {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Promise(String);

impl Promise {
    pub const MAX_BYTES: usize = 512;
}

impl TryFrom<String> for Promise {
    type Error = PromiseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let len = s.len();
        if len <= Promise::MAX_BYTES {
            Ok(Promise(s))
        } else {
            Err(PromiseError::TooLong {
                length: len,
                max: Promise::MAX_BYTES,
            })
        }
    }
}

impl TryFrom<&str> for Promise {
    type Error = PromiseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let len = s.len();
        if len <= Promise::MAX_BYTES {
            Ok(Promise(s.to_owned()))
        } else {
            Err(PromiseError::TooLong {
                length: len,
                max: Promise::MAX_BYTES,
            })
        }
    }
}

impl core::fmt::Display for Promise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a set of parameters for calculating the opening fee for a JIT
/// channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)] // LSPS2 requires the client to fail if a field is unrecognized.
pub struct OpeningFeeParams {
    pub min_fee_msat: Msat,
    pub proportional: Ppm,
    pub valid_until: DateTime,
    pub min_lifetime: u32,
    pub max_client_to_self_delay: u32,
    pub min_payment_size_msat: Msat,
    pub max_payment_size_msat: Msat,
    pub promise: Promise, // Max 512 bytes
}

impl OpeningFeeParams {
    pub fn validate(
        &self,
        secret: &[u8],
        payment_size_msat: Option<Msat>,
        receivable: Option<Msat>,
    ) -> Result<(), Error> {
        // LSPs MUST check that the opening_fee_params.promise does in fact
        // prove that it previously promised the specified opening_fee_params.
        let mut hmac = HmacEngine::<sha256::Hash>::new(&secret);
        hmac.input(&self.min_fee_msat.msat().to_be_bytes());
        hmac.input(&self.proportional.ppm().to_be_bytes());
        hmac.input(self.valid_until.to_rfc3339().as_bytes());
        hmac.input(&self.min_lifetime.to_be_bytes());
        hmac.input(&self.max_client_to_self_delay.to_be_bytes());
        hmac.input(&self.min_payment_size_msat.msat().to_be_bytes());
        hmac.input(&self.max_payment_size_msat.msat().to_be_bytes());
        let promise: String = Hmac::from_engine(hmac)
            .to_byte_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        if self.promise != Promise(promise) {
            return Err(Error::InvalidOpeningFeeParams);
        }

        // LSPs MUST check that the opening_fee_params.valid_until is not a past
        // datetime.
        let now = Utc::now();
        if now > self.valid_until {
            debug!("Got invalid opening fee params: timeout, {:?}", self);
            return Err(Error::InvalidOpeningFeeParams);
        }

        // If the payment_size_msat is specified in the request, the LSP:
        //  - MUST compute the opening_fee and check that the computation did
        //         not hit an overflow failure.
        //     - MUST check that the resulting opening_fee is strictly less than
        //            the payment_size_msat.
        //  - SHOULD check that it has sufficient incoming liquidity from the
        //           public network to be able to receive at least
        //           payment_size_msat.
        if let Some(payment_size_msat) = payment_size_msat {
            let opening_fee = compute_opening_fee(
                payment_size_msat.msat(),
                self.min_fee_msat.msat(),
                self.proportional.ppm() as u64,
            )
            .ok_or(Error::PaymentSizeTooLarge)?;
            if opening_fee >= payment_size_msat.msat() {
                return Err(Error::PaymentSizeTooSmall);
            }

            if let Some(rec) = receivable {
                if opening_fee >= rec.msat() {
                    return Err(Error::PaymentSizeTooLarge);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lsps2BuyRequest {
    pub opening_fee_params: OpeningFeeParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_size_msat: Option<Msat>,
}

impl JsonRpcRequest for Lsps2BuyRequest {
    const METHOD: &'static str = "lsps2.buy";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lsps2BuyResponse {
    pub jit_channel_scid: ShortChannelId,
    pub lsp_cltv_expiry_delta: u32,
    // is an optional Boolean. If not specified, it defaults to false. If
    // specified and true, the client MUST trust the LSP to actually create and
    // confirm a valid channel funding transaction.
    #[serde(default)]
    pub client_trusts_lsp: bool,
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
        let mut hmac = HmacEngine::<sha256::Hash>::new(&secret);
        hmac.input(&self.min_fee_msat.msat().to_be_bytes());
        hmac.input(&self.proportional.ppm().to_be_bytes());
        hmac.input(self.valid_until.to_rfc3339().as_bytes());
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DatastoreEntry {
    pub peer_id: cln_rpc::primitives::PublicKey,
    pub opening_fee_params: OpeningFeeParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_payment_size: Option<Msat>,
}

/// Computes the opening fee in millisatoshis as described in LSPS2.
/// Returns None if an arithmetic overflow occurs during calculation.
///
/// # Arguments
/// * `payment_size_msat` - The size of the payment for which the channel is
///   being opened.
/// * `opening_fee_min_fee_msat` - The minimum fee to be paid by the client to
///   the LSP
/// * `opening_fee_proportional` - The proportional fee charged by the LSP
pub fn compute_opening_fee(
    payment_size_msat: u64,
    opening_fee_min_fee_msat: u64,
    opening_fee_proportional: u64,
) -> Option<u64> {
    payment_size_msat
        .checked_mul(opening_fee_proportional)
        .and_then(|f| f.checked_add(999999))
        .and_then(|f| f.checked_div(1000000))
        .map(|f| std::cmp::max(f, opening_fee_min_fee_msat))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    // Helper struct for testing Serde
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        label: String,
        value: Promise,
    }

    // Helper function to create valid opening fee params
    fn create_valid_opening_fee_params(secret: &[u8]) -> OpeningFeeParams {
        let params = OpeningFeeParams {
            min_fee_msat: Msat::from_msat(1000),
            proportional: Ppm::from_ppm(1000),            // 0.1%
            valid_until: Utc::now() + Duration::hours(1), // Valid for 1 hour
            min_lifetime: 144,                            // blocks
            max_client_to_self_delay: 2016,               // blocks
            min_payment_size_msat: Msat::from_msat(1000), // 1 Sat
            max_payment_size_msat: Msat::from_msat(100_000_000_000), // 1 BTC
            promise: Promise("placeholder".to_string()),  // Will be replaced
        };

        // Compute the correct promise
        let mut hmac = HmacEngine::<sha256::Hash>::new(secret);
        hmac.input(&params.min_fee_msat.msat().to_be_bytes());
        hmac.input(&params.proportional.ppm().to_be_bytes());
        hmac.input(params.valid_until.to_rfc3339().as_bytes());
        hmac.input(&params.min_lifetime.to_be_bytes());
        hmac.input(&params.max_client_to_self_delay.to_be_bytes());
        hmac.input(&params.min_payment_size_msat.msat().to_be_bytes());
        hmac.input(&params.max_payment_size_msat.msat().to_be_bytes());
        let promise: String = Hmac::from_engine(hmac)
            .to_byte_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        OpeningFeeParams {
            promise: Promise(promise),
            ..params
        }
    }

    #[test]
    fn test_serde_promise_ok() {
        let json = r#"{"label": "short", "value": "This is valid"}"#;
        let result = serde_json::from_str::<TestData>(json);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.value.0, "This is valid");
    }

    #[test]
    fn test_serde_promise_too_long() {
        let long_value = "a".repeat(513); // Exceeds 512 bytes
        let json = format!(r#"{{"label": "long", "value": "{}"}}"#, long_value);
        let result = serde_json::from_str::<TestData>(&json);
        assert!(result.is_err());
        // Check the error message relates to our PromiseError
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("promise string is too long"));
    }

    #[test]
    fn test_serde_promise_wrong_type() {
        // Input JSON has a number where a string is expected for 'value'
        let json = r#"{"label": "wrong_type", "value": 123}"#;
        let result = serde_json::from_str::<TestData>(json);
        assert!(result.is_err());
        // This error occurs when Serde tries to deserialize 123 as the String
        // required by `try_from = "String"`.
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid type: integer"));
    }

    #[test]
    fn test_validate_success_minimal() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);

        let result = params.validate(secret, None, None);
        assert!(
            result.is_ok(),
            "Valid params with no payment_size should succeed"
        );
    }

    #[test]
    fn test_validate_success_with_payment_size() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);
        let payment_size = Msat::from_msat(10_000_000); // 10M msat

        let result = params.validate(secret, Some(payment_size), None);
        assert!(
            result.is_ok(),
            "Valid params with valid payment_size should succeed"
        );
    }

    #[test]
    fn test_validate_success_with_payment_size_and_receivable() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);
        let payment_size = Msat::from_msat(10_000_000); // 10M msat
        let receivable = Msat::from_msat(50_000_000); // 50M msat

        let result = params.validate(secret, Some(payment_size), Some(receivable));
        assert!(
            result.is_ok(),
            "Valid params with payment_size and receivable should succeed"
        );
    }

    #[test]
    fn test_validate_invalid_promise() {
        let secret = b"test_secret_key_32_bytes_long___";
        let mut params = create_valid_opening_fee_params(secret);
        params.min_fee_msat = Msat(10);

        let result = params.validate(secret, None, None);
        assert!(
            matches!(result, Err(Error::InvalidOpeningFeeParams)),
            "Invalid promise should fail validation"
        );
    }

    #[test]
    fn test_validate_wrong_secret() {
        let secret1 = b"test_secret_key_32_bytes_long___";
        let secret2 = b"different_secret_key_32_bytes___";
        let params = create_valid_opening_fee_params(secret1);

        let result = params.validate(secret2, None, None);
        assert!(
            matches!(result, Err(Error::InvalidOpeningFeeParams)),
            "Wrong secret should fail validation"
        );
    }

    #[test]
    fn test_validate_expired_timestamp() {
        let secret = b"test_secret_key_32_bytes_long___";
        let mut params = create_valid_opening_fee_params(secret);
        params.valid_until = Utc::now() - Duration::hours(1); // Expired 1 hour ago

        // Recompute promise with expired timestamp
        let mut hmac = HmacEngine::<sha256::Hash>::new(secret);
        hmac.input(&params.min_fee_msat.msat().to_be_bytes());
        hmac.input(&params.proportional.ppm().to_be_bytes());
        hmac.input(params.valid_until.to_rfc3339().as_bytes());
        hmac.input(&params.min_lifetime.to_be_bytes());
        hmac.input(&params.max_client_to_self_delay.to_be_bytes());
        hmac.input(&params.min_payment_size_msat.msat().to_be_bytes());
        hmac.input(&params.max_payment_size_msat.msat().to_be_bytes());
        let promise: String = Hmac::from_engine(hmac)
            .to_byte_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        params.promise = Promise(promise);

        let result = params.validate(secret, None, None);
        assert!(
            matches!(result, Err(Error::InvalidOpeningFeeParams)),
            "Expired timestamp should fail validation"
        );
    }

    #[test]
    fn test_validate_payment_size_overflow() {
        let secret = b"test_secret_key_32_bytes_long___";
        let mut params = create_valid_opening_fee_params(secret);
        // Set proportional fee high enough to cause overflow
        params.proportional = Ppm::from_ppm(u32::MAX);

        // Recompute promise
        let mut hmac = HmacEngine::<sha256::Hash>::new(secret);
        hmac.input(&params.min_fee_msat.msat().to_be_bytes());
        hmac.input(&params.proportional.ppm().to_be_bytes());
        hmac.input(params.valid_until.to_rfc3339().as_bytes());
        hmac.input(&params.min_lifetime.to_be_bytes());
        hmac.input(&params.max_client_to_self_delay.to_be_bytes());
        hmac.input(&params.min_payment_size_msat.msat().to_be_bytes());
        hmac.input(&params.max_payment_size_msat.msat().to_be_bytes());
        let promise: String = Hmac::from_engine(hmac)
            .to_byte_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        params.promise = Promise(promise);

        let payment_size = Msat::from_msat(u64::MAX);
        let result = params.validate(secret, Some(payment_size), None);
        assert!(
            matches!(result, Err(Error::PaymentSizeTooLarge)),
            "Overflow in fee calculation should return PaymentSizeTooLarge"
        );
    }

    #[test]
    fn test_validate_opening_fee_equals_payment_size() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);

        // Find a payment size where opening fee equals payment size
        // With min_fee_msat = 1000 and proportional = 1000 (0.1%)
        // The opening fee will be max(1000, payment * 1000 / 1_000_000)
        // So for small payments, fee = 1000
        let payment_size = Msat::from_msat(1000); // Same as min_fee_msat

        let result = params.validate(secret, Some(payment_size), None);
        assert!(
            matches!(result, Err(Error::PaymentSizeTooSmall)),
            "Opening fee equal to payment size should fail"
        );
    }

    #[test]
    fn test_validate_opening_fee_greater_than_payment_size() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);

        // Payment size smaller than minimum fee
        let payment_size = Msat::from_msat(500); // Less than min_fee_msat (1000)

        let result = params.validate(secret, Some(payment_size), None);
        assert!(
            matches!(result, Err(Error::PaymentSizeTooSmall)),
            "Opening fee greater than payment size should fail"
        );
    }

    #[test]
    fn test_validate_opening_fee_equals_receivable() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);

        let payment_size = Msat::from_msat(10_000_000); // 10M msat
        let receivable = Msat::from_msat(1000); // Same as min_fee_msat

        let result = params.validate(secret, Some(payment_size), Some(receivable));
        assert!(
            matches!(result, Err(Error::PaymentSizeTooLarge)),
            "Opening fee equal to receivable should fail"
        );
    }

    #[test]
    fn test_validate_opening_fee_greater_than_receivable() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);

        let payment_size = Msat::from_msat(10_000_000); // 10M msat
        let receivable = Msat::from_msat(500); // Less than min_fee_msat (1000)

        let result = params.validate(secret, Some(payment_size), Some(receivable));
        assert!(
            matches!(result, Err(Error::PaymentSizeTooLarge)),
            "Opening fee greater than receivable should fail"
        );
    }

    #[test]
    fn test_validate_large_payment_proportional_fee() {
        let secret = b"test_secret_key_32_bytes_long___";
        let params = create_valid_opening_fee_params(secret);

        // Large payment where proportional fee dominates
        // Opening fee = max(1000, 1_000_000_000 * 1000 / 1_000_000) = max(1000, 1_000_000) = 1_000_000
        let payment_size = Msat::from_msat(1_000_000_000);

        let result = params.validate(secret, Some(payment_size), None);
        assert!(
            result.is_ok(),
            "Large payment with proportional fee should succeed"
        );
    }

    #[test]
    fn test_validate_max_values() {
        let secret = b"test_secret_key_32_bytes_long___";
        let mut params = OpeningFeeParams {
            min_fee_msat: Msat::from_msat(u64::MAX / 1000), // Avoid overflow
            proportional: Ppm::from_ppm(100),               // Small proportional to avoid overflow
            valid_until: Utc::now() + Duration::hours(1),
            min_lifetime: u32::MAX,
            max_client_to_self_delay: u32::MAX,
            min_payment_size_msat: Msat::from_msat(1),
            max_payment_size_msat: Msat::from_msat(u64::MAX),
            promise: Promise("placeholder".to_string()),
        };

        // Compute promise
        let mut hmac = HmacEngine::<sha256::Hash>::new(secret);
        hmac.input(&params.min_fee_msat.msat().to_be_bytes());
        hmac.input(&params.proportional.ppm().to_be_bytes());
        hmac.input(params.valid_until.to_rfc3339().as_bytes());
        hmac.input(&params.min_lifetime.to_be_bytes());
        hmac.input(&params.max_client_to_self_delay.to_be_bytes());
        hmac.input(&params.min_payment_size_msat.msat().to_be_bytes());
        hmac.input(&params.max_payment_size_msat.msat().to_be_bytes());
        let promise: String = Hmac::from_engine(hmac)
            .to_byte_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        params.promise = Promise(promise);

        let result = params.validate(secret, None, None);
        assert!(result.is_ok(), "Maximum safe values should be valid");
    }
}
