//! LSPS0 (bLIP-50): transport constants, common schemas and the
//! `lsps0.list_protocols` messages.

use crate::jsonrpc::{JsonRpcRequest, RpcError};
use core::fmt;
use jiff::{SignedDuration, civil};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::time::{Duration, SystemTime};

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
/// A datetime built locally ([`DateTime::now`],
/// [`DateTime::from_unix_millis`], from a [`SystemTime`]) is truncated to
/// milliseconds and serialized in exactly that format. A datetime
/// deserialized from JSON keeps the string it was parsed from and
/// serializes back to that string unchanged, so a client can echo
/// `opening_fee_params` verbatim.
///
/// Parsing accepts an RFC 3339 `date-time`, `YYYY-MM-DDThh:mm:ss`, with
/// optional fractional seconds of up to nine digits and either `Z` or a
/// `+hh:mm`/`-hh:mm` offset. `t` or a space may stand for `T` and `z` for
/// `Z`. Leap seconds are rejected. A datetime is always within the years
/// 0000 to 9999 in UTC.
///
/// Equality, ordering and hashing only consider the point in time, not the
/// string it came from.
///
/// [ISO 8601]: https://www.iso.org/iso-8601-date-and-time-format.html
#[derive(Clone, Debug)]
pub struct DateTime {
    /// The point in time as a date and time of day in UTC.
    value: civil::DateTime,
    /// The string this datetime was deserialized from, if any.
    wire: Option<String>,
}

const UNIX_EPOCH: civil::DateTime = civil::datetime(1970, 1, 1, 0, 0, 0, 0);
const NANOS_PER_SEC: i128 = 1_000_000_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
/// 0000-01-01T00:00:00Z in nanoseconds since the Unix epoch.
const MIN_UNIX_NANOS: i128 = -62_167_219_200 * NANOS_PER_SEC;
/// 9999-12-31T23:59:59.999999999Z in nanoseconds since the Unix epoch.
const MAX_UNIX_NANOS: i128 = 253_402_300_800 * NANOS_PER_SEC - 1;

/// Error returned when a [`DateTime`] can't be parsed or would be outside
/// the years 0000 to 9999.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DateTimeError(String);

impl core::fmt::Display for DateTimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for DateTimeError {}

impl DateTime {
    /// Returns the current time, truncated to milliseconds.
    pub fn now() -> Self {
        DateTime::try_from(SystemTime::now())
            .expect("the system clock is within the years 0000 to 9999")
    }

    /// Returns the datetime `millis` milliseconds after the Unix epoch.
    pub fn from_unix_millis(millis: i64) -> Result<Self, DateTimeError> {
        Self::local(i128::from(millis) * NANOS_PER_MILLI)
    }

    /// Returns the milliseconds since the Unix epoch. Finer precision of a
    /// parsed datetime is rounded down.
    pub fn unix_millis(&self) -> i64 {
        i64::try_from(self.unix_nanos().div_euclid(NANOS_PER_MILLI))
            .expect("years 0000 to 9999 fit in i64 milliseconds")
    }

    /// Returns this datetime plus `duration`, truncated to milliseconds, or
    /// `None` if that is after the year 9999.
    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        let nanos = i128::try_from(duration.as_nanos()).ok()?;
        Self::local(self.unix_nanos().checked_add(nanos)?).ok()
    }

    /// Returns the datetime in RFC 3339 in UTC with a `+00:00` offset and
    /// no, 3, 6 or 9 fractional digits, as few as are needed, e.g.
    /// `2026-11-05T12:00:00+00:00` or `2026-11-05T12:00:00.123+00:00`.
    ///
    /// This is the format of chrono's `DateTime::to_rfc3339()`, which LSPs
    /// hash into their `promise`. Unlike [`Display`] it never changes.
    ///
    /// [`Display`]: core::fmt::Display
    pub fn to_rfc3339(&self) -> String {
        self.format_utc("+00:00")
    }

    /// A datetime built locally, truncated to milliseconds.
    fn local(unix_nanos: i128) -> Result<Self, DateTimeError> {
        let nanos = unix_nanos.div_euclid(NANOS_PER_MILLI) * NANOS_PER_MILLI;
        if !(MIN_UNIX_NANOS..=MAX_UNIX_NANOS).contains(&nanos) {
            return Err(DateTimeError(format!(
                "{unix_nanos}ns after the Unix epoch is outside the years 0000 to 9999"
            )));
        }
        let value = UNIX_EPOCH
            .checked_add(SignedDuration::from_nanos_i128(nanos))
            .expect("years 0000 to 9999 are valid");
        Ok(DateTime { value, wire: None })
    }

    fn unix_nanos(&self) -> i128 {
        self.value.duration_since(UNIX_EPOCH).as_nanos()
    }

    /// `YYYY-MM-DDThh:mm:ss`, no, 3, 6 or 9 fractional digits, `offset`.
    fn format_utc(&self, offset: &str) -> String {
        let v = self.value;
        let nanos = v.subsec_nanosecond();
        let frac = if nanos == 0 {
            String::new()
        } else if nanos % 1_000_000 == 0 {
            format!(".{:03}", nanos / 1_000_000)
        } else if nanos % 1_000 == 0 {
            format!(".{:06}", nanos / 1_000)
        } else {
            format!(".{nanos:09}")
        };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{frac}{offset}",
            v.year(),
            v.month(),
            v.day(),
            v.hour(),
            v.minute(),
            v.second()
        )
    }
}

impl core::str::FromStr for DateTime {
    type Err = DateTimeError;

    /// Parses `s` like deserializing it: the datetime keeps `s` and
    /// serializes back to it.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err =
            |why: &dyn core::fmt::Display| DateTimeError(format!("invalid datetime {s:?}: {why}"));
        let b = s.as_bytes();
        let digits = |r: core::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
        if b.len() < 20
            || !(digits(0..4)
                && b[4] == b'-'
                && digits(5..7)
                && b[7] == b'-'
                && digits(8..10)
                && matches!(b[10], b'T' | b't' | b' ')
                && digits(11..13)
                && b[13] == b':'
                && digits(14..16)
                && b[16] == b':'
                && digits(17..19))
        {
            return Err(err(&"not YYYY-MM-DDThh:mm:ss followed by an offset"));
        }
        // The bytes are ASCII digits, so these parse.
        let num = |r: core::ops::Range<usize>| -> i32 { s[r].parse().expect("ASCII digits") };
        let second = num(17..19);
        if second == 60 {
            return Err(err(&"leap seconds are not supported"));
        }

        let mut rest = &s[19..];
        let mut nanos = 0;
        if let Some(frac) = rest.strip_prefix('.') {
            let n = frac.bytes().take_while(u8::is_ascii_digit).count();
            if n == 0 || n > 9 {
                return Err(err(&"fractional seconds must have 1 to 9 digits"));
            }
            nanos = frac[..n].parse::<i32>().expect("ASCII digits") * 10i32.pow(9 - n as u32);
            rest = &frac[n..];
        }

        let offset_secs = match rest.as_bytes() {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2]
                if [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit()) =>
            {
                let hours: i64 = rest[1..3].parse().expect("ASCII digits");
                let minutes: i64 = rest[4..6].parse().expect("ASCII digits");
                if hours > 23 || minutes > 59 {
                    return Err(err(&"offset out of range"));
                }
                let secs = hours * 3600 + minutes * 60;
                if *sign == b'-' { -secs } else { secs }
            }
            _ => return Err(err(&"the offset must be Z, +hh:mm or -hh:mm")),
        };

        let local = civil::DateTime::new(
            num(0..4) as i16,
            num(5..7) as i8,
            num(8..10) as i8,
            num(11..13) as i8,
            num(14..16) as i8,
            second as i8,
            nanos,
        )
        .map_err(|e| err(&e))?;
        let value = local
            .checked_sub(SignedDuration::from_secs(offset_secs))
            .ok()
            .filter(|v| v.year() >= 0)
            .ok_or_else(|| err(&"outside the years 0000 to 9999"))?;
        Ok(DateTime {
            value,
            wire: Some(s.to_owned()),
        })
    }
}

impl TryFrom<SystemTime> for DateTime {
    type Error = DateTimeError;

    /// Truncates `time` to milliseconds.
    fn try_from(time: SystemTime) -> Result<Self, Self::Error> {
        let nanos = match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => i128::try_from(after.as_nanos()),
            Err(before) => i128::try_from(before.duration().as_nanos()).map(|n| -n),
        }
        .map_err(|_| DateTimeError("system time outside the years 0000 to 9999".into()))?;
        Self::local(nanos)
    }
}

impl TryFrom<DateTime> for SystemTime {
    type Error = DateTimeError;

    /// Fails only if the platform's `SystemTime` can't represent the
    /// datetime.
    fn try_from(dt: DateTime) -> Result<Self, Self::Error> {
        let nanos = dt.unix_nanos();
        let abs = nanos.unsigned_abs();
        let duration = Duration::new(
            (abs / NANOS_PER_SEC as u128) as u64,
            (abs % NANOS_PER_SEC as u128) as u32,
        );
        if nanos >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(duration)
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(duration)
        }
        .ok_or_else(|| DateTimeError(format!("datetime {dt} out of range for SystemTime")))
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

/// Writes the datetime in RFC 3339 in UTC, e.g. `2023-02-23T08:47:30.511Z`.
impl core::fmt::Display for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.format_utc("Z"))
    }
}

impl Serialize for DateTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.wire {
            Some(wire) => serializer.serialize_str(wire),
            None => {
                let v = self.value;
                serializer.collect_str(&format_args!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    v.year(),
                    v.month(),
                    v.day(),
                    v.hour(),
                    v.minute(),
                    v.second(),
                    v.subsec_nanosecond() / 1_000_000
                ))
            }
        }
    }
}

impl<'de> Deserialize<'de> for DateTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
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
        // Re-encoding the instant would turn the first two into
        // "...30Z"-like spellings and lose the client's exact string.
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
        assert_eq!(DateTime::from_unix_millis(a.unix_millis()).unwrap(), a);
    }

    #[test]
    fn test_datetime_local_values_use_the_spec_format() {
        for (millis, json) in [
            (1677142050000, r#""2023-02-23T08:47:30.000Z""#),
            (1677142050511, r#""2023-02-23T08:47:30.511Z""#),
            (-1, r#""1969-12-31T23:59:59.999Z""#),
            (-62167219200000, r#""0000-01-01T00:00:00.000Z""#),
            (253402300799999, r#""9999-12-31T23:59:59.999Z""#),
        ] {
            let dt = DateTime::from_unix_millis(millis).unwrap();
            assert_eq!(serde_json::to_string(&dt).unwrap(), json, "{millis}");
            assert_eq!(dt.unix_millis(), millis);
        }
    }

    #[test]
    fn test_datetime_local_values_are_truncated_to_millis() {
        let dt = DateTime::from_unix_millis(1677142050511).unwrap();
        let later = dt.checked_add(Duration::from_nanos(200_300)).unwrap();
        assert_eq!(later, dt);
        assert_eq!(
            serde_json::to_string(&later).unwrap(),
            r#""2023-02-23T08:47:30.511Z""#
        );
        let later = dt.checked_add(Duration::from_secs(60)).unwrap();
        assert_eq!(later.unix_millis(), 1677142110511);

        let time = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_677_142_050_511_200_300);
        let dt = DateTime::try_from(time).unwrap();
        assert_eq!(dt.unix_millis(), 1677142050511);
        assert_eq!(
            SystemTime::try_from(dt).unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_millis(1677142050511)
        );

        let now = DateTime::now();
        assert_eq!(now.unix_millis() % 1000, now.unix_millis().rem_euclid(1000));
        assert!(serde_json::to_string(&now).unwrap().ends_with("Z\""));
    }

    #[test]
    fn test_datetime_stays_within_years_0000_to_9999() {
        assert!(DateTime::from_unix_millis(-62167219200001).is_err());
        assert!(DateTime::from_unix_millis(253402300800000).is_err());
        let last = DateTime::from_unix_millis(253402300799999).unwrap();
        assert!(last.checked_add(Duration::from_millis(1)).is_none());
        for s in ["0000-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01"] {
            assert!(s.parse::<DateTime>().is_err(), "{s}");
        }
    }

    #[test]
    fn test_datetime_parsed_values_keep_their_precision() {
        let millis: DateTime = "2023-02-23T08:47:30.511Z".parse().unwrap();
        let finer: DateTime = "2023-02-23T08:47:30.5112Z".parse().unwrap();
        assert!(millis < finer);
        assert_eq!(finer.unix_millis(), millis.unix_millis());
        // Rounded down before the epoch too.
        let pre: DateTime = "1969-12-31T23:59:59.9995Z".parse().unwrap();
        assert_eq!(pre.unix_millis(), -1);
    }

    #[test]
    fn test_datetime_parses_rfc3339() {
        for (input, millis) in [
            ("2023-02-23T08:47:30.511Z", 1677142050511),
            ("2023-02-23T08:47:30Z", 1677142050000),
            ("2023-02-23T08:47:30.123456789Z", 1677142050123),
            ("2023-02-23T10:47:30.511+02:00", 1677142050511),
            ("2023-02-23T08:47:30.511-00:00", 1677142050511),
            ("2023-02-23t08:47:30.511z", 1677142050511),
            ("2023-02-23 08:47:30.511Z", 1677142050511),
            ("1969-12-31T23:59:59.999Z", -1),
        ] {
            let dt: DateTime = input.parse().unwrap();
            assert_eq!(dt.unix_millis(), millis, "{input}");
        }
    }

    #[test]
    fn test_datetime_to_rfc3339() {
        // Hashed into LSPS2 promises: this must not change.
        for (input, rfc3339) in [
            ("2026-11-05T12:00:00Z", "2026-11-05T12:00:00+00:00"),
            ("2026-11-05T12:00:00.000Z", "2026-11-05T12:00:00+00:00"),
            ("2026-11-05T12:00:00.123Z", "2026-11-05T12:00:00.123+00:00"),
            ("2026-11-05T12:00:00.1Z", "2026-11-05T12:00:00.100+00:00"),
            (
                "2026-11-05T12:00:00.1234Z",
                "2026-11-05T12:00:00.123400+00:00",
            ),
            (
                "2026-11-05T12:00:00.123456Z",
                "2026-11-05T12:00:00.123456+00:00",
            ),
            (
                "2026-11-05T12:00:00.1234567Z",
                "2026-11-05T12:00:00.123456700+00:00",
            ),
            (
                "2026-11-05T13:00:00.123+01:00",
                "2026-11-05T12:00:00.123+00:00",
            ),
            ("1969-12-31T23:59:59.999Z", "1969-12-31T23:59:59.999+00:00"),
            ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00+00:00"),
            (
                "9999-12-31T23:59:59.999999999Z",
                "9999-12-31T23:59:59.999999999+00:00",
            ),
        ] {
            let dt: DateTime = input.parse().unwrap();
            assert_eq!(dt.to_rfc3339(), rfc3339, "{input}");
        }
    }

    #[test]
    fn test_datetime_display() {
        let dt: DateTime = "2023-02-23T10:47:30.511+02:00".parse().unwrap();
        assert_eq!(dt.to_string(), "2023-02-23T08:47:30.511Z");
    }

    #[test]
    fn test_datetime_rejects_garbage() {
        for json in [
            r#""""#,
            r#""2023-02-23""#,
            r#""yesterday""#,
            "1677142050",
            // No offset.
            r#""2023-02-23T08:47:30.511""#,
            // A leap second.
            r#""2016-12-31T23:59:60Z""#,
            // Not RFC 3339: an RFC 9557 annotation, no seconds, a comma as
            // the decimal sign, the ISO 8601 basic format, no colon in the
            // offset, an offset without minutes, more than nine fractional
            // digits, no fractional digits.
            r#""2023-02-23T08:47:30.511Z[UTC]""#,
            r#""2023-02-23T08:47Z""#,
            r#""2023-02-23T08:47:30,511Z""#,
            r#""20230223T084730Z""#,
            r#""2023-02-23T08:47:30.511+0200""#,
            r#""2023-02-23T08:47:30.511+02""#,
            r#""2023-02-23T08:47:30.1234567891Z""#,
            r#""2023-02-23T08:47:30.Z""#,
            // Out of range fields.
            r#""2023-02-30T08:47:30Z""#,
            r#""2023-02-23T24:00:00Z""#,
            r#""2023-02-23T08:47:30+24:00""#,
            // Non-ASCII.
            r#""2023-02-23T08:47:30.511Ż""#,
            r#""２０２３-02-23T08:47:30Z""#,
        ] {
            assert!(serde_json::from_str::<DateTime>(json).is_err(), "{json}");
        }
    }
}
