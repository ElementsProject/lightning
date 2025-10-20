//! Backfill structs for missing or incomplete Core Lightning types.
//!
//! This module provides struct implementations that are not available or
//! fully accessible in the core-lightning crate, enabling better compatibility
//! and interoperability with Core Lightning's RPC interface.
use cln_rpc::primitives::{Amount, ShortChannelId};
use hex::FromHex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::lsps2::cln::tlv::TlvStream;

pub const TLV_FORWARD_AMT: u64 = 2;
pub const TLV_OUTGOING_CLTV: u64 = 4;
pub const TLV_SHORT_CHANNEL_ID: u64 = 6;
pub const TLV_PAYMENT_SECRET: u64 = 8;

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Onion {
    pub forward_msat: Option<Amount>,
    #[serde(deserialize_with = "from_hex")]
    pub next_onion: Vec<u8>,
    pub outgoing_cltv_value: Option<u32>,
    pub payload: TlvStream,
    // pub payload: TlvStream,
    #[serde(deserialize_with = "from_hex")]
    pub shared_secret: Vec<u8>,
    pub short_channel_id: Option<ShortChannelId>,
    pub total_msat: Option<Amount>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Htlc {
    pub amount_msat: Amount,
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u16,
    pub id: u64,
    #[serde(deserialize_with = "from_hex")]
    pub payment_hash: Vec<u8>,
    pub short_channel_id: ShortChannelId,
    pub extra_tlvs: Option<TlvStream>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HtlcAcceptedResult {
    Continue,
    Fail,
    Resolve,
}

impl std::fmt::Display for HtlcAcceptedResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HtlcAcceptedResult::Continue => "continue",
            HtlcAcceptedResult::Fail => "fail",
            HtlcAcceptedResult::Resolve => "resolve",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Deserialize)]
pub struct HtlcAcceptedRequest {
    pub htlc: Htlc,
    pub onion: Onion,
    pub forward_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HtlcAcceptedResponse {
    pub result: HtlcAcceptedResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "to_hex")]
    pub payload: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "to_hex")]
    pub forward_to: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "to_hex")]
    pub extra_tlvs: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "to_hex")]
    pub failure_onion: Option<Vec<u8>>,
}

impl HtlcAcceptedResponse {
    pub fn continue_(
        payload: Option<Vec<u8>>,
        forward_to: Option<Vec<u8>>,
        extra_tlvs: Option<Vec<u8>>,
    ) -> Self {
        Self {
            result: HtlcAcceptedResult::Continue,
            payment_key: None,
            payload,
            forward_to,
            extra_tlvs,
            failure_message: None,
            failure_onion: None,
        }
    }

    pub fn fail(failure_message: Option<String>, failure_onion: Option<Vec<u8>>) -> Self {
        Self {
            result: HtlcAcceptedResult::Fail,
            payment_key: None,
            payload: None,
            forward_to: None,
            extra_tlvs: None,
            failure_message,
            failure_onion,
        }
    }
}

/// Deserializes a lowercase hex string to a `Vec<u8>`.
pub fn from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(string).map_err(|err| Error::custom(err.to_string())))
}

pub fn to_hex<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(data) => serializer.serialize_str(&hex::encode(data)),
        None => serializer.serialize_none(),
    }
}

pub mod tlv {
    use anyhow::Result;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
    use std::{convert::TryFrom, fmt};

    #[derive(Clone, Debug)]
    pub struct TlvRecord {
        pub type_: u64,
        pub value: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    pub struct TlvStream(pub Vec<TlvRecord>);

    #[derive(Debug)]
    pub enum TlvError {
        DuplicateType(u64),
        NotSorted,
        LengthMismatch(u64, usize, usize),
        Truncated,
        NonCanonicalBigSize,
        TrailingBytes,
        Hex(hex::FromHexError),
        Other(String),
    }

    impl fmt::Display for TlvError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TlvError::DuplicateType(t) => write!(f, "duplicate tlv type {}", t),
                TlvError::NotSorted => write!(f, "tlv types must be strictly increasing"),
                TlvError::LengthMismatch(t, e, g) => {
                    write!(f, "length mismatch type {}: expected {}, got {}", t, e, g)
                }
                TlvError::Truncated => write!(f, "truncated input"),
                TlvError::NonCanonicalBigSize => write!(f, "non-canonical bigsize encoding"),
                TlvError::TrailingBytes => write!(f, "leftover bytes after parsing"),
                TlvError::Hex(e) => write!(f, "hex error: {}", e),
                TlvError::Other(s) => write!(f, "{}", s),
            }
        }
    }

    impl std::error::Error for TlvError {}
    impl From<hex::FromHexError> for TlvError {
        fn from(e: hex::FromHexError) -> Self {
            TlvError::Hex(e)
        }
    }

    impl TlvStream {
        pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
            self.0.sort_by_key(|r| r.type_);
            for w in self.0.windows(2) {
                if w[0].type_ == w[1].type_ {
                    return Err(TlvError::DuplicateType(w[0].type_).into());
                }
                if w[0].type_ > w[1].type_ {
                    return Err(TlvError::NotSorted.into());
                }
            }
            let mut out = Vec::new();
            for rec in &self.0 {
                out.extend(encode_bigsize(rec.type_));
                out.extend(encode_bigsize(rec.value.len() as u64));
                out.extend(&rec.value);
            }
            Ok(out)
        }

        pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
            let mut recs = Vec::new();
            let mut last_type: Option<u64> = None;

            while !bytes.is_empty() {
                let (t, n1) = decode_bigsize(bytes)?;
                bytes = &bytes[n1..];
                let (len, n2) = decode_bigsize(bytes)?;
                bytes = &bytes[n2..];

                let l =
                    usize::try_from(len).map_err(|_| TlvError::Other("length too large".into()))?;
                if bytes.len() < l {
                    return Err(TlvError::Truncated.into());
                }
                let v = bytes[..l].to_vec();
                bytes = &bytes[l..];

                if let Some(prev) = last_type {
                    if t == prev {
                        return Err(TlvError::DuplicateType(t).into());
                    }
                    if t < prev {
                        return Err(TlvError::NotSorted.into());
                    }
                }
                last_type = Some(t);
                recs.push(TlvRecord { type_: t, value: v });
            }
            Ok(TlvStream(recs))
        }

        pub fn from_bytes_with_length_prefix(bytes: &[u8]) -> Result<Self> {
            if bytes.is_empty() {
                return Err(TlvError::Truncated.into());
            }

            let (length, length_bytes) = decode_bigsize(bytes)?;
            let remaining = &bytes[length_bytes..];

            let length_usize = usize::try_from(length)
                .map_err(|_| TlvError::Other("length prefix too large".into()))?;

            if remaining.len() != length_usize {
                return Err(TlvError::LengthMismatch(0, length_usize, remaining.len()).into());
            }

            Self::from_bytes(remaining)
        }

        /// Attempt to auto-detect whether the input has a length prefix or not
        /// First tries to parse as length-prefixed, then falls back to raw TLV
        /// parsing.
        pub fn from_bytes_auto(bytes: &[u8]) -> Result<Self> {
            // Try length-prefixed first
            if let Ok(stream) = Self::from_bytes_with_length_prefix(bytes) {
                return Ok(stream);
            }

            // Fall back to raw TLV parsing
            Self::from_bytes(bytes)
        }

        /// Get a reference to the value of a TLV record by type.
        pub fn get(&self, type_: u64) -> Option<&[u8]> {
            self.0
                .iter()
                .find(|rec| rec.type_ == type_)
                .map(|rec| rec.value.as_slice())
        }

        /// Insert a TLV record (replaces if type already exists).
        pub fn insert(&mut self, type_: u64, value: Vec<u8>) {
            // If the type already exists, replace its value.
            if let Some(rec) = self.0.iter_mut().find(|rec| rec.type_ == type_) {
                rec.value = value;
                return;
            }
            // Otherwise push and re-sort to maintain canonical order.
            self.0.push(TlvRecord { type_, value });
            self.0.sort_by_key(|r| r.type_);
        }

        /// Remove a record by type.
        pub fn remove(&mut self, type_: u64) -> Option<Vec<u8>> {
            if let Some(pos) = self.0.iter().position(|rec| rec.type_ == type_) {
                Some(self.0.remove(pos).value)
            } else {
                None
            }
        }

        /// Check if a type exists.
        pub fn contains(&self, type_: u64) -> bool {
            self.0.iter().any(|rec| rec.type_ == type_)
        }

        /// Insert or override a `tu64` value for `type_` (keeps canonical TLV order).
        pub fn set_tu64(&mut self, type_: u64, value: u64) {
            let enc = encode_tu64(value);
            if let Some(rec) = self.0.iter_mut().find(|r| r.type_ == type_) {
                rec.value = enc;
            } else {
                self.0.push(TlvRecord { type_, value: enc });
                self.0.sort_by_key(|r| r.type_);
            }
        }

        /// Read a `tu64` if present, validating minimal encoding.
        /// Returns Ok(None) if the type isn't present.
        pub fn get_tu64(&self, type_: u64) -> Result<Option<u64>, TlvError> {
            if let Some(rec) = self.0.iter().find(|r| r.type_ == type_) {
                Ok(Some(decode_tu64(&rec.value)?))
            } else {
                Ok(None)
            }
        }

        /// Insert or override a `u64` value for `type_` (keeps cannonical TLV
        /// order).
        pub fn set_u64(&mut self, type_: u64, value: u64) {
            let enc = value.to_be_bytes().to_vec();
            if let Some(rec) = self.0.iter_mut().find(|r| r.type_ == type_) {
                rec.value = enc;
            } else {
                self.0.push(TlvRecord { type_, value: enc });
                self.0.sort_by_key(|r| r.type_);
            }
        }

        /// Read a `u64` if present.Returns Ok(None) if the type isn't present.
        pub fn get_u64(&self, type_: u64) -> Result<Option<u64>, TlvError> {
            if let Some(rec) = self.0.iter().find(|r| r.type_ == type_) {
                let value = u64::from_be_bytes(
                    rec.value[..]
                        .try_into()
                        .map_err(|e| TlvError::Other(format!("failed not decode to u64: {e}")))?,
                );
                Ok(Some(value))
            } else {
                Ok(None)
            }
        }
    }

    impl Serialize for TlvStream {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut tmp = self.clone();
            let bytes = tmp.to_bytes().map_err(serde::ser::Error::custom)?;
            serializer.serialize_str(&hex::encode(bytes))
        }
    }

    impl<'de> Deserialize<'de> for TlvStream {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = TlvStream;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex string representing a Lightning TLV stream")
                }
                fn visit_str<E: DeError>(self, s: &str) -> Result<Self::Value, E> {
                    let bytes = hex::decode(s).map_err(E::custom)?;
                    TlvStream::from_bytes_auto(&bytes).map_err(E::custom)
                }
            }
            deserializer.deserialize_str(V)
        }
    }

    impl TryFrom<&[u8]> for TlvStream {
        type Error = anyhow::Error;
        fn try_from(value: &[u8]) -> Result<Self> {
            TlvStream::from_bytes(value)
        }
    }

    impl From<Vec<TlvRecord>> for TlvStream {
        fn from(v: Vec<TlvRecord>) -> Self {
            TlvStream(v)
        }
    }

    /// BOLT #1 BigSize encoding
    fn encode_bigsize(x: u64) -> Vec<u8> {
        let mut out = Vec::new();
        if x < 0xfd {
            out.push(x as u8);
        } else if x <= 0xffff {
            out.push(0xfd);
            out.extend_from_slice(&(x as u16).to_be_bytes());
        } else if x <= 0xffff_ffff {
            out.push(0xfe);
            out.extend_from_slice(&(x as u32).to_be_bytes());
        } else {
            out.push(0xff);
            out.extend_from_slice(&x.to_be_bytes());
        }
        out
    }

    fn decode_bigsize(input: &[u8]) -> Result<(u64, usize)> {
        if input.is_empty() {
            return Err(TlvError::Truncated.into());
        }
        match input[0] {
            n @ 0x00..=0xfc => Ok((n as u64, 1)),
            0xfd => {
                if input.len() < 3 {
                    return Err(TlvError::Truncated.into());
                }
                let v = u16::from_be_bytes([input[1], input[2]]) as u64;
                if v < 0xfd {
                    return Err(TlvError::NonCanonicalBigSize.into());
                }
                Ok((v, 3))
            }
            0xfe => {
                if input.len() < 5 {
                    return Err(TlvError::Truncated.into());
                }
                let v = u32::from_be_bytes([input[1], input[2], input[3], input[4]]) as u64;
                if v <= 0xffff {
                    return Err(TlvError::NonCanonicalBigSize.into());
                }
                Ok((v, 5))
            }
            0xff => {
                if input.len() < 9 {
                    return Err(TlvError::Truncated.into());
                }
                let v = u64::from_be_bytes([
                    input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
                ]);
                if v <= 0xffff_ffff {
                    return Err(TlvError::NonCanonicalBigSize.into());
                }
                Ok((v, 9))
            }
        }
    }

    /// Encode a BOLT #1 `tu64`: big-endian, minimal length (no leading 0x00).
    /// Value 0 is encoded as zero-length.
    pub fn encode_tu64(v: u64) -> Vec<u8> {
        if v == 0 {
            return Vec::new();
        }
        let bytes = v.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap(); // safe: v != 0
        bytes[first..].to_vec()
    }

    /// Decode a BOLT #1 `tu64`, enforcing minimal form.
    /// Empty slice -> 0. Leading 0x00 or >8 bytes is invalid.
    fn decode_tu64(raw: &[u8]) -> Result<u64, TlvError> {
        if raw.is_empty() {
            return Ok(0);
        }
        if raw.len() > 8 {
            return Err(TlvError::Other("tu64 too long".into()));
        }
        if raw[0] == 0 {
            return Err(TlvError::Other("non-minimal tu64 (leading zero)".into()));
        }
        let mut buf = [0u8; 8];
        buf[8 - raw.len()..].copy_from_slice(raw);
        Ok(u64::from_be_bytes(buf))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use anyhow::Result;

        // Small helpers to keep tests readable
        fn rec(type_: u64, value: &[u8]) -> TlvRecord {
            TlvRecord {
                type_,
                value: value.to_vec(),
            }
        }

        fn build_bytes(type_: u64, value: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend(super::encode_bigsize(type_));
            v.extend(super::encode_bigsize(value.len() as u64));
            v.extend(value);
            v
        }

        #[test]
        fn encode_then_decode_roundtrip() -> Result<()> {
            let mut stream = TlvStream(vec![rec(1, &[0x01, 0x02]), rec(5, &[0xaa])]);

            // Encode
            let bytes = stream.to_bytes()?;
            // Expect exact TLV sequence:
            // type=1 -> 0x01, len=2 -> 0x02, value=0x01 0x02
            // type=5 -> 0x05, len=1 -> 0x01, value=0xaa
            assert_eq!(hex::encode(&bytes), "010201020501aa");

            // Decode back
            let decoded = TlvStream::from_bytes(&bytes)?;
            assert_eq!(decoded.0.len(), 2);
            assert_eq!(decoded.0[0].type_, 1);
            assert_eq!(decoded.0[0].value, vec![0x01, 0x02]);
            assert_eq!(decoded.0[1].type_, 5);
            assert_eq!(decoded.0[1].value, vec![0xaa]);

            Ok(())
        }

        #[test]
        fn json_hex_roundtrip() -> Result<()> {
            let stream = TlvStream(vec![rec(1, &[0x01, 0x02]), rec(5, &[0xaa])]);

            // Serialize to hex string in JSON
            let json = serde_json::to_string(&stream)?;
            // It's a quoted hex string; check inner value
            let s: String = serde_json::from_str(&json)?;
            assert_eq!(s, "010201020501aa");

            // And back from JSON hex
            let back: TlvStream = serde_json::from_str(&json)?;
            assert_eq!(back.0.len(), 2);
            assert_eq!(back.0[0].type_, 1);
            assert_eq!(back.0[0].value, vec![0x01, 0x02]);
            assert_eq!(back.0[1].type_, 5);
            assert_eq!(back.0[1].value, vec![0xaa]);

            Ok(())
        }

        #[test]
        fn decode_with_len_prefix() -> Result<()> {
            let payload = "1202039896800401760608000073000f2c0007";
            let stream = TlvStream::from_bytes_with_length_prefix(&hex::decode(payload).unwrap())?;
            // let stream: TlvStream = serde_json::from_str(payload)?;
            println!("TLV {:?}", stream.0);

            Ok(())
        }

        #[test]
        fn bigsize_boundary_minimal_encodings() -> Result<()> {
            // Types at 0xfc, 0xfd, 0x10000 to exercise size switches
            let mut stream = TlvStream(vec![
                rec(0x00fc, &[0x11]),      // single-byte bigsize
                rec(0x00fd, &[0x22]),      // 0xfd prefix + u16
                rec(0x0001_0000, &[0x33]), // 0xfe prefix + u32
            ]);

            let bytes = stream.to_bytes()?; // just ensure it encodes
                                            // Decode back to confirm roundtrip/canonical encodings accepted
            let back = TlvStream::from_bytes(&bytes)?;
            assert_eq!(back.0[0].type_, 0x00fc);
            assert_eq!(back.0[1].type_, 0x00fd);
            assert_eq!(back.0[2].type_, 0x0001_0000);
            Ok(())
        }

        #[test]
        fn decode_rejects_non_canonical_bigsize() {
            // (1) Non-canonical: 0xfd 00 fc encodes 0xfc but should be a single byte
            let mut bytes = Vec::new();
            bytes.extend([0xfd, 0x00, 0xfc]); // non-canonical type
            bytes.extend([0x01]); // len = 1
            bytes.extend([0x00]); // value
            let err = TlvStream::from_bytes(&bytes).unwrap_err();
            assert!(format!("{}", err).contains("non-canonical"));

            // (2) Non-canonical: 0xfe 00 00 00 ff encodes 0xff but should be 0xfd-form
            let mut bytes = Vec::new();
            bytes.extend([0xfe, 0x00, 0x00, 0x00, 0xff]);
            bytes.extend([0x01]);
            bytes.extend([0x00]);
            let err = TlvStream::from_bytes(&bytes).unwrap_err();
            assert!(format!("{}", err).contains("non-canonical"));

            // (3) Non-canonical: 0xff 00..01 encodes 1, which should be single byte
            let mut bytes = Vec::new();
            bytes.extend([0xff, 0, 0, 0, 0, 0, 0, 0, 1]);
            bytes.extend([0x01]);
            bytes.extend([0x00]);
            let err = TlvStream::from_bytes(&bytes).unwrap_err();
            assert!(format!("{}", err).contains("non-canonical"));
        }

        #[test]
        fn decode_rejects_out_of_order_types() {
            // Build two TLVs but put type 5 before type 1
            let mut bad = Vec::new();
            bad.extend(build_bytes(5, &[0xaa]));
            bad.extend(build_bytes(1, &[0x00]));

            let err = TlvStream::from_bytes(&bad).unwrap_err();
            assert!(
                format!("{}", err).contains("increasing") || format!("{}", err).contains("sorted"),
                "expected ordering error, got: {err}"
            );
        }

        #[test]
        fn decode_rejects_duplicate_types() {
            // Two records with same type=1
            let mut bad = Vec::new();
            bad.extend(build_bytes(1, &[0x01]));
            bad.extend(build_bytes(1, &[0x02]));
            let err = TlvStream::from_bytes(&bad).unwrap_err();
            assert!(
                format!("{}", err).contains("duplicate"),
                "expected duplicate error, got: {err}"
            );
        }

        #[test]
        fn encode_rejects_duplicate_types() {
            // insert duplicate types and expect encode to fail
            let mut s = TlvStream(vec![rec(1, &[0x01]), rec(1, &[0x02])]);
            let err = s.to_bytes().unwrap_err();
            assert!(
                format!("{}", err).contains("duplicate"),
                "expected duplicate error, got: {err}"
            );
        }

        #[test]
        fn decode_truncated_value() {
            // type=1, len=2 but only 1 byte of value provided
            let mut bytes = Vec::new();
            bytes.extend(encode_bigsize(1));
            bytes.extend(encode_bigsize(2));
            bytes.push(0x00); // missing one more byte
            let err = TlvStream::from_bytes(&bytes).unwrap_err();
            assert!(
                format!("{}", err).contains("truncated"),
                "expected truncated error, got: {err}"
            );
        }

        #[test]
        fn set_and_get_u64_basic() -> Result<()> {
            let mut s = TlvStream::default();
            s.set_u64(42, 123456789);
            assert_eq!(s.get_u64(42)?, Some(123456789));
            Ok(())
        }

        #[test]
        fn set_u64_overwrite_keeps_order() -> Result<()> {
            let mut s = TlvStream(vec![
                TlvRecord {
                    type_: 1,
                    value: vec![0xaa],
                },
                TlvRecord {
                    type_: 10,
                    value: vec![0xbb],
                },
            ]);

            // insert between 1 and 10
            s.set_u64(5, 7);
            assert_eq!(
                s.0.iter().map(|r| r.type_).collect::<Vec<_>>(),
                vec![1, 5, 10]
            );
            assert_eq!(s.get_u64(5)?, Some(7));

            // overwrite existing 5 (no duplicate, order preserved)
            s.set_u64(5, 9);
            let types: Vec<u64> = s.0.iter().map(|r| r.type_).collect();
            assert_eq!(types, vec![1, 5, 10]);
            assert_eq!(s.0.iter().filter(|r| r.type_ == 5).count(), 1);
            assert_eq!(s.get_u64(5)?, Some(9));
            Ok(())
        }

        #[test]
        fn set_and_get_tu64_basic() -> Result<()> {
            let mut s = TlvStream::default();
            s.set_tu64(42, 123456789);
            assert_eq!(s.get_tu64(42)?, Some(123456789));
            Ok(())
        }

        #[test]
        fn get_u64_missing_returns_none() -> Result<()> {
            let s = TlvStream::default();
            assert_eq!(s.get_u64(999)?, None);
            Ok(())
        }

        #[test]
        fn set_tu64_overwrite_keeps_order() -> Result<()> {
            let mut s = TlvStream(vec![
                TlvRecord {
                    type_: 1,
                    value: vec![0xaa],
                },
                TlvRecord {
                    type_: 10,
                    value: vec![0xbb],
                },
            ]);

            // insert between 1 and 10
            s.set_tu64(5, 7);
            assert_eq!(
                s.0.iter().map(|r| r.type_).collect::<Vec<_>>(),
                vec![1, 5, 10]
            );
            assert_eq!(s.get_tu64(5)?, Some(7));

            // overwrite existing 5 (no duplicate, order preserved)
            s.set_tu64(5, 9);
            let types: Vec<u64> = s.0.iter().map(|r| r.type_).collect();
            assert_eq!(types, vec![1, 5, 10]);
            assert_eq!(s.0.iter().filter(|r| r.type_ == 5).count(), 1);
            assert_eq!(s.get_tu64(5)?, Some(9));
            Ok(())
        }

        #[test]
        fn tu64_zero_encodes_empty_and_roundtrips() -> Result<()> {
            let mut s = TlvStream::default();
            s.set_tu64(3, 0);

            // stored value is zero-length
            let rec = s.0.iter().find(|r| r.type_ == 3).unwrap();
            assert!(rec.value.is_empty());

            // wire round-trip
            let mut sc = s.clone();
            let bytes = sc.to_bytes()?;
            let s2 = TlvStream::from_bytes(&bytes)?;
            assert_eq!(s2.get_tu64(3)?, Some(0));
            Ok(())
        }

        #[test]
        fn get_tu64_missing_returns_none() -> Result<()> {
            let s = TlvStream::default();
            assert_eq!(s.get_tu64(999)?, None);
            Ok(())
        }

        #[test]
        fn get_tu64_rejects_non_minimal_and_too_long() {
            // non-minimal: leading zero
            let mut s = TlvStream::default();
            s.0.push(TlvRecord {
                type_: 9,
                value: vec![0x00, 0x01],
            });
            assert!(s.get_tu64(9).is_err());

            // too long: 9 bytes
            let mut s2 = TlvStream::default();
            s2.0.push(TlvRecord {
                type_: 9,
                value: vec![0; 9],
            });
            assert!(s2.get_tu64(9).is_err());
        }

        #[test]
        fn tu64_multi_roundtrip_bytes_and_json() -> Result<()> {
            let mut s = TlvStream::default();
            s.set_tu64(42, 0);
            s.set_tu64(7, 256);

            // wire roundtrip
            let mut sc = s.clone();
            let bytes = sc.to_bytes()?;
            let s2 = TlvStream::from_bytes(&bytes)?;
            assert_eq!(s2.get_tu64(42)?, Some(0));
            assert_eq!(s2.get_tu64(7)?, Some(256));

            // json hex roundtrip (custom Serialize/Deserialize)
            let json = serde_json::to_string(&s)?;
            let s3: TlvStream = serde_json::from_str(&json)?;
            assert_eq!(s3.get_tu64(42)?, Some(0));
            assert_eq!(s3.get_tu64(7)?, Some(256));
            Ok(())
        }
    }
}
