use core::fmt;
use serde::{
    de::{self},
    Deserialize, Deserializer, Serialize, Serializer,
};

const MSAT_PER_SAT: u64 = 1_000;

/// Represents a monetary amount as defined in LSPS0.msat. Is converted to a
/// `String` in json messages with a suffix `_msat` or `_sat` and internally
/// represented as Millisatoshi `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Msat(pub u64);

impl Msat {
    /// Constructs a new `Msat` struct from a `u64` msat value.
    pub fn from_msat(msat: u64) -> Self {
        Msat(msat)
    }

    /// Construct a new `Msat` struct from a `u64` sat value.
    pub fn from_sat(sat: u64) -> Self {
        Msat(sat * MSAT_PER_SAT)
    }

    /// Returns the sat amount of the field. Is a floored integer division e.g
    /// 100678 becomes 100.
    pub fn to_sats_floor(&self) -> u64 {
        self.0 / 1000
    }

    /// Returns the msat value as `u64`. Is the inner value of `Msat`.
    pub fn msat(&self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for Msat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_msat", self.0)
    }
}

impl Serialize for Msat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Msat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MsatVisitor;

        impl<'de> de::Visitor<'de> for MsatVisitor {
            type Value = Msat;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a number")
            }

            fn visit_str<E>(self, value: &str) -> Result<Msat, E>
            where
                E: de::Error,
            {
                value
                    .parse::<u64>()
                    .map(Msat::from_msat)
                    .map_err(|_| E::custom(format!("Invalid number string: {}", value)))
            }

            // Also handle if JSON mistakenly has a number instead of string
            fn visit_u64<E>(self, value: u64) -> Result<Msat, E>
            where
                E: de::Error,
            {
                Ok(Msat::from_msat(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Msat, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    Err(E::custom("Msat cannot be negative"))
                } else {
                    Ok(Msat::from_msat(value as u64))
                }
            }
        }

        deserializer.deserialize_any(MsatVisitor)
    }
}

/// Represents parts-per-million as defined in LSPS0.ppm. Gets it's own type
/// from the rationals: "This is its own type so that fractions can be expressed
/// using this type, instead of as a floating-point type which might lose
/// accuracy when serialized into text.". Having it as a separate type also
/// provides more clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)] // Key attribute! Serialize/Deserialize as the inner u32
pub struct Ppm(pub u32); // u32 is sufficient as 1,000,000 fits easily

impl Ppm {
    /// Constructs a new `Ppm` from a u32.
    pub const fn from_ppm(value: u32) -> Self {
        Ppm(value)
    }

    /// Applies the proportion to a base amount (e.g., in msats).
    pub fn apply_to(&self, base_msat: u64) -> u64 {
        // Careful about integer division order and potential overflow
        (base_msat as u128 * self.0 as u128 / 1_000_000) as u64
    }

    /// Returns the ppm.
    pub fn ppm(&self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for Ppm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}ppm", self.0)
    }
}

/// Represents a short channel id as defined in LSPS0.scid. Matches with the
/// implementation in cln_rpc.
pub type ShortChannelId = cln_rpc::primitives::ShortChannelId;

/// Represents a datetime as defined in LSPS0.datetime. Uses ISO8601 in UTC
/// timezone.
pub type DateTime = chrono::DateTime<chrono::Utc>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestMessage {
        amount: Msat,
    }

    /// Test serialization of a struct containing Msat.
    #[test]
    fn test_msat_serialization() {
        let msg = TestMessage {
            amount: Msat(12345000),
        };

        let expected_amount_json = r#""amount":"12345000""#;

        // Assert that the field gets serialized as string.
        let json_string = serde_json::to_string(&msg).expect("Serialization failed");
        assert!(
            json_string.contains(expected_amount_json),
            "Serialized JSON should contain '{}'",
            expected_amount_json
        );

        // Parse back to generic json value and check field.
        let json_value: serde_json::Value =
            serde_json::from_str(&json_string).expect("Failed to parse JSON back");
        assert_eq!(
            json_value
                .get("amount")
                .expect("JSON should have 'amount' field"),
            &serde_json::Value::String("12345000".to_string()),
            "JSON 'amount' field should have the correct string value"
        );
    }

    /// Test deserialization into a struct containing Msat.
    #[test]
    fn test_msat_deserialization_and_errors() {
        // Case 1: Input string uses "_msat" suffix
        let json_ok = r#"{"amount":"987654321"}"#;
        let expected_value_msat = Msat(987654321);
        let message1: TestMessage =
            serde_json::from_str(json_ok).expect("Deserialization from string failed");
        assert_eq!(message1.amount, expected_value_msat);

        // Case 2: Non-numeric Value before suffix
        let json_non_numeric = r#"{"amount":"abc"}"#;
        let result_non_numeric = serde_json::from_str::<TestMessage>(json_non_numeric);
        assert!(
            result_non_numeric.is_err(),
            "Deserialization should fail for non-numeric value"
        );
    }
}
