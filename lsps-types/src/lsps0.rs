//! LSPS0 (bLIP-50): transport constants, common schemas and the
//! `lsps0.list_protocols` messages.

use crate::jsonrpc::{JsonRpcRequest, RpcError};
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

// Optional feature bet to set according to LSPS0.
pub const LSP_FEATURE_BIT: usize = 729;

// Required message type for BOLT8 transport.
pub const LSPS0_MESSAGE_TYPE: u16 = 37913;

// Lsps0 specific error codes defined in BLIP-50.
// Are in the range 00000 to 00099.
pub mod error_codes {
    pub const CLIENT_REJECTED: i64 = 1;
}

pub trait LSPS0RpcErrorExt {
    rpc_error_methods! {
        client_rejected, client_rejected_with_data => error_codes::CLIENT_REJECTED,
    }
}

impl LSPS0RpcErrorExt for RpcError {}

/// Error returned by [`decode_frame`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    InvalidMessageType { type_: u16 },
    TooShort(usize),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::InvalidMessageType { type_ } => {
                write!(f, "invalid message type: got {type_}")
            }
            FrameError::TooShort(len) => write!(
                f,
                "message too short: expected at least 2 bytes for type field, got {len}"
            ),
        }
    }
}

impl core::error::Error for FrameError {}

/// Encode raw payload bytes into an LSPS0 frame.
///
/// Format:
/// [0-1] Message type: 37913 (0x9419) as big-endian u16
/// [2..] Payload bytes
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + payload.len());
    bytes.extend_from_slice(&LSPS0_MESSAGE_TYPE.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Decode an LSPS0 frame and return the raw payload bytes.
///
/// Validates that the header matches the LSPS0 message type (37913).
pub fn decode_frame(bytes: &[u8]) -> Result<&[u8], FrameError> {
    if bytes.len() < 2 {
        return Err(FrameError::TooShort(bytes.len()));
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if message_type != LSPS0_MESSAGE_TYPE {
        return Err(FrameError::InvalidMessageType {
            type_: message_type,
        });
    }
    Ok(&bytes[2..])
}

/// Represents a monetary amount as defined in LSPS0.msat. Is converted to a
/// `String` in json messages with a suffix `_msat` or `_sat` and internally
/// represented as Millisatoshi `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Msat(pub u64);

impl Msat {
    /// Constructs a new `Msat` struct from a `u64` msat value.
    pub fn from_msat(msat: u64) -> Self {
        Msat(msat)
    }

    /// Returns the msat value as `u64`. Is the inner value of `Msat`.
    pub fn msat(&self) -> u64 {
        self.0
    }

    /// Adds two amounts, returning `None` on overflow.
    pub fn checked_add(self, rhs: Msat) -> Option<Msat> {
        self.0.checked_add(rhs.0).map(Msat)
    }

    /// Subtracts `rhs` from `self`, returning `None` on underflow.
    pub fn checked_sub(self, rhs: Msat) -> Option<Msat> {
        self.0.checked_sub(rhs.0).map(Msat)
    }
}

impl core::fmt::Display for Msat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_msat", self.0)
    }
}

impl Serialize for Msat {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Msat {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MsatVisitor;

        impl de::Visitor<'_> for MsatVisitor {
            type Value = Msat;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a number")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Msat, E>
            where
                E: de::Error,
            {
                value
                    .parse::<u64>()
                    .map(Msat::from_msat)
                    .map_err(|_| E::custom(format!("Invalid number string: {}", value)))
            }

            // Also handle if JSON mistakenly has a number instead of string
            fn visit_u64<E>(self, value: u64) -> std::result::Result<Msat, E>
            where
                E: de::Error,
            {
                Ok(Msat::from_msat(value))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Msat, E>
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)] // Key attribute! Serialize/Deserialize as the inner u32
pub struct Ppm(pub u32); // u32 is sufficient as 1,000,000 fits easily (spec definition)

impl Ppm {
    /// Constructs a new `Ppm` from a u32.
    pub const fn from_ppm(value: u32) -> Self {
        Ppm(value)
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

/// Represents a short channel id as defined in LSPS0.scid.
/// Format: `{block}x{txindex}x{outnum}` encoding a u64 as
/// `(block << 40) | (txindex << 16) | outnum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortChannelId(u64);

impl ShortChannelId {
    pub fn block(&self) -> u32 {
        (self.0 >> 40) as u32 & 0xFFFFFF
    }
    pub fn txindex(&self) -> u32 {
        (self.0 >> 16) as u32 & 0xFFFFFF
    }
    pub fn outnum(&self) -> u16 {
        self.0 as u16
    }
    pub fn to_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for ShortChannelId {
    fn from(v: u64) -> Self {
        ShortChannelId(v)
    }
}

impl core::fmt::Display for ShortChannelId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}x{}x{}", self.block(), self.txindex(), self.outnum())
    }
}

/// Error returned when parsing a [`ShortChannelId`] from a string fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseShortChannelIdError(String);

impl core::fmt::Display for ParseShortChannelIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "malformed short_channel_id: {}", self.0)
    }
}

impl core::error::Error for ParseShortChannelIdError {}

impl core::str::FromStr for ShortChannelId {
    type Err = ParseShortChannelIdError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('x').collect();
        if parts.len() != 3 {
            return Err(ParseShortChannelIdError(format!(
                "expected 3 parts, got {}",
                parts.len()
            )));
        }
        // LSPS0.scid: "`BBB` is the top 24 bits in decimal text. `TTT` is the
        // middle 24 bits in decimal text. `OOO` is the lowest 16 bits in
        // decimal text."
        let parse = |name: &str, part: &str, bits: u32| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseShortChannelIdError(format!(
                    "{name} is not a decimal number: {part:?}"
                )));
            }
            match part.parse::<u64>() {
                Ok(v) if v < 1 << bits => Ok(v),
                _ => Err(ParseShortChannelIdError(format!(
                    "{name} {part} does not fit in {bits} bits"
                ))),
            }
        };
        let block = parse("block", parts[0], 24)?;
        let txindex = parse("txindex", parts[1], 24)?;
        let outnum = parse("outnum", parts[2], 16)?;
        Ok(ShortChannelId((block << 40) | (txindex << 16) | outnum))
    }
}

impl Serialize for ShortChannelId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ShortChannelId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// Represents a datetime as defined in LSPS0.datetime:
///
/// > Particular points of time in the modern era (a "datetime") MUST be
/// > encoded as a JSON string containing the [ISO 8601] format
/// > `"YYYY-MM-DDThh:mm:ss.uuuZ"`.
/// > These are always in the UTC timezone.
///
/// A datetime built locally (from a [`chrono::DateTime`]) is truncated to
/// milliseconds and serialized in exactly that format. A datetime
/// deserialized from JSON keeps the string it was parsed from and
/// serializes back to that string unchanged, so a client can echo
/// `opening_fee_params` verbatim. Parsing accepts any RFC 3339 datetime.
///
/// Equality, ordering and hashing only consider the point in time, not the
/// string it came from.
///
/// [ISO 8601]: https://www.iso.org/iso-8601-date-and-time-format.html
#[derive(Clone, Debug)]
pub struct DateTime {
    value: chrono::DateTime<chrono::Utc>,
    /// The string this datetime was deserialized from, if any.
    wire: Option<String>,
}

impl DateTime {
    /// Returns the datetime as a [`chrono::DateTime`].
    pub fn as_chrono(&self) -> chrono::DateTime<chrono::Utc> {
        self.value
    }
}

impl From<chrono::DateTime<chrono::Utc>> for DateTime {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        use chrono::SubsecRound as _;
        DateTime {
            value: dt.trunc_subsecs(3),
            wire: None,
        }
    }
}

impl From<DateTime> for chrono::DateTime<chrono::Utc> {
    fn from(dt: DateTime) -> Self {
        dt.value
    }
}

impl PartialEq for DateTime {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for DateTime {}

impl PartialOrd for DateTime {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DateTime {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl core::hash::Hash for DateTime {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

impl core::fmt::Display for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.value, f)
    }
}

impl Serialize for DateTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.wire {
            Some(wire) => serializer.serialize_str(wire),
            None => serializer.collect_str(&self.value.format("%Y-%m-%dT%H:%M:%S%.3fZ")),
        }
    }
}

impl<'de> Deserialize<'de> for DateTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let wire = String::deserialize(deserializer)?;
        // Same parsing as chrono's serde implementation.
        let value = wire
            .parse::<chrono::DateTime<chrono::FixedOffset>>()
            .map_err(de::Error::custom)?
            .with_timezone(&chrono::Utc);
        Ok(DateTime {
            value,
            wire: Some(wire),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsps0listProtocolsRequest {}

impl JsonRpcRequest for Lsps0listProtocolsRequest {
    const METHOD: &'static str = "lsps0.list_protocols";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lsps0listProtocolsResponse {
    pub protocols: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_JSON: &str = r#"{"jsonrpc":"2.0","method":"test","id":"1"}"#;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestMessage {
        amount: Msat,
    }

    #[test]
    fn test_encode_frame() {
        let json = TEST_JSON.as_bytes();
        let wire_bytes = encode_frame(json);

        assert_eq!(wire_bytes.len(), 2 + json.len());
        assert_eq!(wire_bytes[0], 0x94);
        assert_eq!(wire_bytes[1], 0x19);
        assert_eq!(&wire_bytes[2..], json);
    }

    #[test]
    fn test_encode_decode_frame_roundtrip() {
        let json = TEST_JSON.as_bytes();
        let wire_bytes = encode_frame(json);
        let decoded = decode_frame(&wire_bytes).expect("should decode the frame");

        assert_eq!(decoded, json)
    }

    #[test]
    fn test_decode_empty_frame() {
        let result = decode_frame(&[]);
        assert!(matches!(result, Err(FrameError::TooShort(0))));
    }

    #[test]
    fn test_decode_single_byte_frame() {
        let result = decode_frame(&[0x94]);
        assert!(matches!(result, Err(FrameError::TooShort(1))));
    }

    #[test]
    fn test_decode_frame_with_wrong_message_type() {
        let bytes = vec![0x00, 0x01, b'{', b'}'];
        let result = decode_frame(&bytes);
        assert!(matches!(
            result,
            Err(FrameError::InvalidMessageType { type_: 1 })
        ));
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

    #[test]
    fn test_msat_checked_arithmetic() {
        assert_eq!(Msat(1).checked_add(Msat(2)), Some(Msat(3)));
        assert_eq!(Msat(u64::MAX).checked_add(Msat(1)), None);
        assert_eq!(Msat(3).checked_sub(Msat(2)), Some(Msat(1)));
        assert_eq!(Msat(2).checked_sub(Msat(3)), None);
    }

    #[test]
    fn test_scid_spec_example() {
        // LSPS0.scid: "an SCID which would be hex-dumped as the binary blob
        // `083a8400034d0001` [...] would be written as the JSON string
        // `"539268x845x1"`."
        let scid = ShortChannelId::from(0x083a8400034d0001);
        assert_eq!(scid.block(), 539268);
        assert_eq!(scid.txindex(), 845);
        assert_eq!(scid.outnum(), 1);
        assert_eq!(serde_json::to_string(&scid).unwrap(), r#""539268x845x1""#);
        let parsed: ShortChannelId = serde_json::from_str(r#""539268x845x1""#).unwrap();
        assert_eq!(parsed, scid);
    }

    #[test]
    fn test_scid_malformed() {
        for s in [
            "", "1x2", "1x2x3x4", "ax2x3", "1x2x-3", "+1x2x3", "1xx3", " 1x2x3",
        ] {
            assert!(s.parse::<ShortChannelId>().is_err(), "{s} should not parse");
        }
    }

    #[test]
    fn test_scid_component_ranges() {
        let max: ShortChannelId = "16777215x16777215x65535".parse().unwrap();
        assert_eq!(max.to_u64(), u64::MAX);
        assert_eq!(max.to_string(), "16777215x16777215x65535");
        assert_eq!("0x0x0".parse::<ShortChannelId>().unwrap().to_u64(), 0);

        // One above each component's range used to spill into the
        // neighboring bits.
        for s in ["16777216x0x0", "0x16777216x0", "0x0x65536", "1x1x70000"] {
            assert!(s.parse::<ShortChannelId>().is_err(), "{s} should not parse");
        }
    }

    #[test]
    fn test_scid_string_roundtrip() {
        for v in [0u64, 1, 0x083a8400034d0001, u64::MAX, 1 << 40, 1 << 16] {
            let scid = ShortChannelId::from(v);
            assert_eq!(scid.to_string().parse::<ShortChannelId>(), Ok(scid));
        }
    }

    #[test]
    fn test_datetime_serde() {
        let json = r#""2023-02-23T08:47:30.511Z""#;
        let dt: DateTime = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&dt).unwrap(), json);
    }

    #[test]
    fn test_datetime_echoes_received_string() {
        // chrono's own serde would turn the first two into "...30Z" and
        // "...30.511Z".
        for json in [
            r#""2023-02-23T08:47:30.000Z""#,
            r#""2023-02-23T08:47:30.511+00:00""#,
            r#""2023-02-23T08:47:30Z""#,
            r#""2023-02-23T08:47:30.5112Z""#,
            r#""2023-02-23T10:47:30.511+02:00""#,
        ] {
            let dt: DateTime = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&dt).unwrap(), json);
        }
    }

    #[test]
    fn test_datetime_equality_ignores_the_string() {
        let a: DateTime = serde_json::from_str(r#""2023-02-23T08:47:30.511Z""#).unwrap();
        let b: DateTime = serde_json::from_str(r#""2023-02-23T10:47:30.511+02:00""#).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), core::cmp::Ordering::Equal);
        assert_eq!(DateTime::from(a.as_chrono()), a);
    }

    #[test]
    fn test_datetime_local_values_use_the_spec_format() {
        use chrono::TimeZone;
        let whole = chrono::Utc
            .with_ymd_and_hms(2023, 2, 23, 8, 47, 30)
            .unwrap();
        assert_eq!(
            serde_json::to_string(&DateTime::from(whole)).unwrap(),
            r#""2023-02-23T08:47:30.000Z""#
        );

        // Sub-millisecond precision is dropped when the value is built, so
        // the value matches what a peer parses back.
        let precise = whole + chrono::Duration::nanoseconds(511_200_300);
        let dt = DateTime::from(precise);
        assert_eq!(
            serde_json::to_string(&dt).unwrap(),
            r#""2023-02-23T08:47:30.511Z""#
        );
        let parsed: DateTime = serde_json::from_str(&serde_json::to_string(&dt).unwrap()).unwrap();
        assert_eq!(parsed.as_chrono(), dt.as_chrono());
    }

    #[test]
    fn test_datetime_rejects_garbage() {
        for json in [r#""""#, r#""2023-02-23""#, r#""yesterday""#, "1677142050"] {
            assert!(serde_json::from_str::<DateTime>(json).is_err(), "{json}");
        }
    }
}
