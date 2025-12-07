//! Backfill structs for missing or incomplete Core Lightning types.
//!
//! This module provides struct implementations that are not available or
//! fully accessible in the core-lightning crate, enabling better compatibility
//! and interoperability with Core Lightning's RPC interface.
use cln_rpc::primitives::{Amount, ShortChannelId};
use hex::FromHex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::tlv::TlvStream;

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

#[derive(Debug, Deserialize)]
pub struct InvoicePaymentRequest {
    pub payment: InvoicePaymentRequestPayment,
}

#[derive(Debug, Deserialize)]
pub struct InvoicePaymentRequestPayment {
    pub label: String,
    pub preimage: String,
    pub msat: u64,
}

#[derive(Debug, Deserialize)]
pub struct OpenChannelRequest {
    pub openchannel: OpenChannelRequestOpenChannel,
}

#[derive(Debug, Deserialize)]
pub struct OpenChannelRequestOpenChannel {
    pub id: String,
    pub funding_msat: u64,
    pub push_msat: u64,
    pub dust_limit_msat: u64,
    pub max_htlc_value_in_flight_msat: u64,
    pub channel_reserve_msat: u64,
    pub htlc_minimum_msat: u64,
    pub feerate_per_kw: u32,
    pub to_self_delay: u32,
    pub max_accepted_htlcs: u32,
    pub channel_flags: u64,
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
