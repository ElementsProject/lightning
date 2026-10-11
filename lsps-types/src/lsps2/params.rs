use super::{Error, Promise, compute_opening_fee};
use crate::lsps0::{DateTime, Msat, Ppm};
use serde::{Deserialize, Serialize};

/// Represents a set of parameters for calculating the opening fee for a JIT
/// channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// Reasons why an [`OpeningFeeParams`] can't be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// `min_payment_size_msat` is greater than `max_payment_size_msat`, so no
    /// payment size is acceptable.
    MinAboveMax { min: Msat, max: Msat },
    /// `valid_until` is in the past.
    Expired { valid_until: DateTime },
    /// Computing the opening fee for `payment_size` overflowed.
    FeeOverflow { payment_size: Msat },
    /// The opening fee is not strictly less than `payment_size`.
    FeeNotBelowPaymentSize {
        opening_fee: Msat,
        payment_size: Msat,
    },
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ValidationError::MinAboveMax { min, max } => write!(
                f,
                "min_payment_size_msat {} is above max_payment_size_msat {}",
                min, max
            ),
            ValidationError::Expired { valid_until } => {
                write!(f, "opening fee params expired at {}", valid_until)
            }
            ValidationError::FeeOverflow { payment_size } => write!(
                f,
                "opening fee computation overflowed for payment size {}",
                payment_size
            ),
            ValidationError::FeeNotBelowPaymentSize {
                opening_fee,
                payment_size,
            } => write!(
                f,
                "opening fee {} is not less than payment size {}",
                opening_fee, payment_size
            ),
        }
    }
}

impl core::error::Error for ValidationError {}

/// Maps a validation failure to the `lsps2.buy` error an LSP returns for it.
impl From<ValidationError> for Error {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::MinAboveMax { .. } | ValidationError::Expired { .. } => {
                Error::InvalidOpeningFeeParams
            }
            ValidationError::FeeOverflow { .. } => Error::PaymentSizeTooLarge,
            ValidationError::FeeNotBelowPaymentSize { .. } => Error::PaymentSizeTooSmall,
        }
    }
}

impl OpeningFeeParams {
    /// Computes the opening fee for `payment_size` with these parameters, see
    /// [`compute_opening_fee`]. Returns `None` on overflow.
    pub fn opening_fee(&self, payment_size: Msat) -> Option<Msat> {
        compute_opening_fee(
            payment_size.msat(),
            self.min_fee_msat.msat(),
            u64::from(self.proportional.ppm()),
        )
        .map(Msat::from_msat)
    }

    /// Checks that `min_payment_size_msat <= max_payment_size_msat`; the
    /// limits are inclusive, so otherwise no payment size is acceptable.
    pub fn check_limits(&self) -> Result<(), ValidationError> {
        if self.min_payment_size_msat > self.max_payment_size_msat {
            return Err(ValidationError::MinAboveMax {
                min: self.min_payment_size_msat,
                max: self.max_payment_size_msat,
            });
        }
        Ok(())
    }

    /// Returns whether `valid_until` is in the past at `now`.
    pub fn is_expired_at(&self, now: &DateTime) -> bool {
        *now > self.valid_until
    }

    /// Computes the opening fee for `payment_size` and checks it as the LSP
    /// must when `payment_size_msat` is specified in `lsps2.buy`:
    ///
    /// > MUST compute the `opening_fee` and check that the computation did
    /// > not hit an overflow failure.
    /// > MUST check that the resulting `opening_fee` is strictly less than
    /// > the `payment_size_msat`.
    ///
    /// Returns the opening fee.
    pub fn check_payment_size(&self, payment_size: Msat) -> Result<Msat, ValidationError> {
        let opening_fee = self
            .opening_fee(payment_size)
            .ok_or(ValidationError::FeeOverflow { payment_size })?;
        if opening_fee >= payment_size {
            return Err(ValidationError::FeeNotBelowPaymentSize {
                opening_fee,
                payment_size,
            });
        }
        Ok(opening_fee)
    }

    /// Runs the checks an LSP does on `lsps2.buy`, except the promise check
    /// which only the LSP that issued the promise can do:
    ///
    /// > LSPs MUST check that the `opening_fee_params.valid_until` is not a
    /// > past datetime.
    ///
    /// and, if `payment_size` is given, [`Self::check_payment_size`].
    /// Returns the opening fee if `payment_size` is given.
    pub fn validate(
        &self,
        now: &DateTime,
        payment_size: Option<Msat>,
    ) -> Result<Option<Msat>, ValidationError> {
        if self.is_expired_at(now) {
            return Err(ValidationError::Expired {
                valid_until: self.valid_until.clone(),
            });
        }
        payment_size
            .map(|size| self.check_payment_size(size))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn datetime(year: i32) -> DateTime {
        Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap().into()
    }

    fn now() -> DateTime {
        datetime(2026)
    }

    fn params() -> OpeningFeeParams {
        OpeningFeeParams {
            min_fee_msat: Msat::from_msat(1000),
            proportional: Ppm::from_ppm(1000), // 0.1%
            valid_until: datetime(2027),
            min_lifetime: 144,                                       // blocks
            max_client_to_self_delay: 2016,                          // blocks
            min_payment_size_msat: Msat::from_msat(1000),            // 1 Sat
            max_payment_size_msat: Msat::from_msat(100_000_000_000), // 1 BTC
            promise: Promise::try_from("promise").unwrap(),
        }
    }

    #[test]
    fn test_validate_success_minimal() {
        assert_eq!(params().validate(&now(), None), Ok(None));
    }

    #[test]
    fn test_validate_success_with_payment_size() {
        // max(1000, ceil(10_000_000 * 1000 / 1_000_000)) = 10_000
        let fee = params().validate(&now(), Some(Msat::from_msat(10_000_000)));
        assert_eq!(fee, Ok(Some(Msat::from_msat(10_000))));
    }

    #[test]
    fn test_validate_expired_timestamp() {
        let p = OpeningFeeParams {
            valid_until: datetime(2025),
            ..params()
        };
        let err = p.validate(&now(), None).unwrap_err();
        assert_eq!(
            err,
            ValidationError::Expired {
                valid_until: datetime(2025)
            }
        );
        assert_eq!(Error::from(err), Error::InvalidOpeningFeeParams);
    }

    #[test]
    fn test_valid_until_is_inclusive() {
        let p = params();
        assert!(!p.is_expired_at(&p.valid_until));
    }

    #[test]
    fn test_validate_payment_size_overflow() {
        let p = OpeningFeeParams {
            proportional: Ppm::from_ppm(u32::MAX),
            ..params()
        };
        let err = p
            .validate(&now(), Some(Msat::from_msat(u64::MAX)))
            .unwrap_err();
        assert!(matches!(err, ValidationError::FeeOverflow { .. }));
        assert_eq!(Error::from(err), Error::PaymentSizeTooLarge);
    }

    #[test]
    fn test_validate_opening_fee_equals_payment_size() {
        // Same as min_fee_msat.
        let err = params()
            .validate(&now(), Some(Msat::from_msat(1000)))
            .unwrap_err();
        assert!(matches!(
            err,
            ValidationError::FeeNotBelowPaymentSize { .. }
        ));
        assert_eq!(Error::from(err), Error::PaymentSizeTooSmall);
    }

    #[test]
    fn test_validate_opening_fee_greater_than_payment_size() {
        // Less than min_fee_msat.
        let err = params()
            .validate(&now(), Some(Msat::from_msat(500)))
            .unwrap_err();
        assert!(matches!(
            err,
            ValidationError::FeeNotBelowPaymentSize { .. }
        ));
    }

    #[test]
    fn test_validate_large_payment_proportional_fee() {
        // max(1000, 1_000_000_000 * 1000 / 1_000_000) = 1_000_000
        let fee = params().validate(&now(), Some(Msat::from_msat(1_000_000_000)));
        assert_eq!(fee, Ok(Some(Msat::from_msat(1_000_000))));
    }

    #[test]
    fn test_validate_max_values() {
        let p = OpeningFeeParams {
            min_fee_msat: Msat::from_msat(u64::MAX / 1000),
            proportional: Ppm::from_ppm(100),
            min_lifetime: u32::MAX,
            max_client_to_self_delay: u32::MAX,
            min_payment_size_msat: Msat::from_msat(1),
            max_payment_size_msat: Msat::from_msat(u64::MAX),
            ..params()
        };
        assert_eq!(p.validate(&now(), None), Ok(None));
    }

    #[test]
    fn test_check_limits() {
        assert_eq!(params().check_limits(), Ok(()));

        let equal = OpeningFeeParams {
            min_payment_size_msat: Msat::from_msat(5000),
            max_payment_size_msat: Msat::from_msat(5000),
            ..params()
        };
        assert_eq!(equal.check_limits(), Ok(()));

        let inverted = OpeningFeeParams {
            min_payment_size_msat: Msat::from_msat(5001),
            max_payment_size_msat: Msat::from_msat(5000),
            ..params()
        };
        assert_eq!(
            inverted.check_limits(),
            Err(ValidationError::MinAboveMax {
                min: Msat::from_msat(5001),
                max: Msat::from_msat(5000),
            })
        );
    }

    #[test]
    fn test_deny_unknown_fields() {
        let mut json = serde_json::to_value(params()).unwrap();
        json["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<OpeningFeeParams>(json).is_err());
    }

    #[test]
    fn test_spec_example_roundtrip() {
        // From bLIP-52 "Example `lsps2.get_info` result".
        let json = r#"{
            "min_fee_msat": "546000",
            "proportional": 1200,
            "valid_until": "2023-02-23T08:47:30.511Z",
            "min_lifetime": 1008,
            "max_client_to_self_delay": 2016,
            "min_payment_size_msat": "1000",
            "max_payment_size_msat": "1000000",
            "promise": "abcdefghijklmnopqrstuvwxyz"
        }"#;
        let p: OpeningFeeParams = serde_json::from_str(json).unwrap();
        assert_eq!(p.min_fee_msat, Msat::from_msat(546_000));
        assert_eq!(p.proportional, Ppm::from_ppm(1200));
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
    }
}
