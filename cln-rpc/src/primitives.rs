//! Primitive types representing [`Amount`]s, [`PublicKey`]s, ...
use anyhow::Context;
use anyhow::{anyhow, Error, Result};
use bitcoin::hashes::Hash as BitcoinHash;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use serde_json::Value;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::string::ToString;

pub use bitcoin::hashes::sha256::Hash as Sha256;
pub use bitcoin::secp256k1::PublicKey;

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum ChannelState {
    OPENINGD = 0,
    CHANNELD_AWAITING_LOCKIN = 1,
    CHANNELD_NORMAL = 2,
    CHANNELD_SHUTTING_DOWN = 3,
    CLOSINGD_SIGEXCHANGE = 4,
    CLOSINGD_COMPLETE = 5,
    AWAITING_UNILATERAL = 6,
    FUNDING_SPEND_SEEN = 7,
    ONCHAIN = 8,
    DUALOPEND_OPEN_INIT = 9,
    DUALOPEND_AWAITING_LOCKIN = 10,
    CHANNELD_AWAITING_SPLICE = 11,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum HtlcState {
    SENT_ADD_HTLC = 0,
    SENT_ADD_COMMIT = 1,
    RCVD_ADD_REVOCATION = 2,
    RCVD_ADD_ACK_COMMIT = 3,
    SENT_ADD_ACK_REVOCATION = 4,
    RCVD_ADD_ACK_REVOCATION = 5,
    RCVD_REMOVE_HTLC = 6,
    RCVD_REMOVE_COMMIT = 7,
    SENT_REMOVE_REVOCATION = 8,
    SENT_REMOVE_ACK_COMMIT = 9,
    RCVD_REMOVE_ACK_REVOCATION = 10,
    RCVD_ADD_HTLC = 11,
    RCVD_ADD_COMMIT = 12,
    SENT_ADD_REVOCATION = 13,
    SENT_ADD_ACK_COMMIT = 14,
    SENT_REMOVE_HTLC = 15,
    SENT_REMOVE_COMMIT = 16,
    RCVD_REMOVE_REVOCATION = 17,
    RCVD_REMOVE_ACK_COMMIT = 18,
    SENT_REMOVE_ACK_REVOCATION = 19,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum ChannelTypeName {
    #[serde(rename = "static_remotekey/even")]
    STATIC_REMOTEKEY_EVEN = 0,
    #[serde(rename = "anchor_outputs/even")]
    ANCHOR_OUTPUTS_EVEN = 1,
    #[serde(rename = "anchors_zero_fee_htlc_tx/even")]
    ANCHORS_ZERO_FEE_HTLC_TX_EVEN = 2,
    #[serde(rename = "scid_alias/even")]
    SCID_ALIAS_EVEN = 3,
    #[serde(rename = "zeroconf/even")]
    ZEROCONF_EVEN = 4,
    #[serde(rename = "anchors/even")]
    ANCHORS_EVEN = 5,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
#[serde(rename_all = "lowercase")]
pub enum ChannelStateChangeCause {
    UNKNOWN,
    LOCAL,
    USER,
    REMOTE,
    PROTOCOL,
    ONCHAIN,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum AutocleanSubsystem {
    #[serde(rename = "succeededforwards")]
    SUCCEEDEDFORWARDS = 0,
    #[serde(rename = "failedforwards")]
    FAILEDFORWARDS = 1,
    #[serde(rename = "succeededpays")]
    SUCCEEDEDPAYS = 2,
    #[serde(rename = "failedpays")]
    FAILEDPAYS = 3,
    #[serde(rename = "paidinvoices")]
    PAIDINVOICES = 4,
    #[serde(rename = "expiredinvoices")]
    EXPIREDINVOICES = 5,
}

impl TryFrom<i32> for AutocleanSubsystem {
    type Error = crate::Error;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(AutocleanSubsystem::SUCCEEDEDFORWARDS),
            1 => Ok(AutocleanSubsystem::FAILEDFORWARDS),
            2 => Ok(AutocleanSubsystem::SUCCEEDEDPAYS),
            3 => Ok(AutocleanSubsystem::FAILEDPAYS),
            4 => Ok(AutocleanSubsystem::PAIDINVOICES),
            5 => Ok(AutocleanSubsystem::EXPIREDINVOICES),
            _ => Err(anyhow!("Invalid AutocleanSubsystem {}", value)),
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum PluginSubcommand {
    #[serde(rename = "start")]
    START = 0,
    #[serde(rename = "stop")]
    STOP = 1,
    #[serde(rename = "rescan")]
    RESCAN = 2,
    #[serde(rename = "startdir")]
    STARTDIR = 3,
    #[serde(rename = "list")]
    LIST = 4,
}

impl TryFrom<i32> for PluginSubcommand {
    type Error = crate::Error;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(PluginSubcommand::START),
            1 => Ok(PluginSubcommand::STOP),
            2 => Ok(PluginSubcommand::RESCAN),
            3 => Ok(PluginSubcommand::STARTDIR),
            4 => Ok(PluginSubcommand::LIST),
            _ => Err(anyhow!("Invalid PluginSubcommand mapping!")),
        }
    }
}

/// An `Amount` that can also be `any`. Useful for cases in which you
/// want to delegate the Amount selection so someone else, e.g., an
/// amountless invoice.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AmountOrAny {
    Amount(Amount),
    Any,
}

/// An amount that can also be `all`. Useful for cases where you want
/// to delegate the amount computation to the cln node.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AmountOrAll {
    Amount(Amount),
    All,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Amount {
    msat: u64,
}

impl Amount {
    pub fn from_msat(msat: u64) -> Amount {
        Amount { msat }
    }

    pub fn from_sat(sat: u64) -> Amount {
        Amount { msat: 1_000 * sat }
    }

    pub fn from_btc(btc: u64) -> Amount {
        Amount {
            msat: 100_000_000_000 * btc,
        }
    }

    pub fn msat(&self) -> u64 {
        self.msat
    }
}

impl std::ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Self) -> Self::Output {
        Amount {
            msat: self.msat + rhs.msat,
        }
    }
}

impl std::ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Self) -> Self::Output {
        Amount {
            msat: self.msat - rhs.msat,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortChannelId(u64);

impl Serialize for ShortChannelId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ShortChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s: String = Deserialize::deserialize(deserializer)?;
        Ok(Self::from_str(&s).map_err(|e| Error::custom(e.to_string()))?)
    }
}

impl FromStr for ShortChannelId {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Result<Vec<u64>, _> = s.split('x').map(|p| p.parse()).collect();
        let parts = parts.with_context(|| format!("Malformed short_channel_id: {}", s))?;
        if parts.len() != 3 {
            return Err(anyhow!(
                "Malformed short_channel_id: element count mismatch"
            ));
        }

        Ok(ShortChannelId(
            (parts[0] << 40) | (parts[1] << 16) | (parts[2] << 0),
        ))
    }
}
impl Display for ShortChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}x{}", self.block(), self.txindex(), self.outnum())
    }
}
impl ShortChannelId {
    pub fn block(&self) -> u32 {
        (self.0 >> 40) as u32 & 0xFFFFFF
    }
    pub fn txindex(&self) -> u32 {
        (self.0 >> 16) as u32 & 0xFFFFFF
    }
    pub fn outnum(&self) -> u16 {
        self.0 as u16 & 0xFFFF
    }
    pub fn to_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Secret([u8; 32]);

impl TryFrom<Vec<u8>> for Secret {
    type Error = crate::Error;
    fn try_from(v: Vec<u8>) -> Result<Self, crate::Error> {
        if v.len() != 32 {
            Err(anyhow!("Unexpected secret length: {}", hex::encode(v)))
        } else {
            Ok(Secret(v.try_into().unwrap()))
        }
    }
}

impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s: String = Deserialize::deserialize(deserializer)?;
        let h = hex::decode(s).map_err(|_| Error::custom("not a valid hex string"))?;
        Ok(Secret(h.try_into().map_err(|_| {
            Error::custom("not a valid hex-encoded hash")
        })?))
    }
}

impl Secret {
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<Secret> for [u8; 32] {
    fn from(s: Secret) -> [u8; 32] {
        s.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Outpoint {
    pub txid: Sha256,
    pub outnum: u32,
}

impl Serialize for Outpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", hex::encode(&self.txid), self.outnum))
    }
}

impl<'de> Deserialize<'de> for Outpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s: String = Deserialize::deserialize(deserializer)?;

        let splits: Vec<&str> = s.split(':').collect();
        if splits.len() != 2 {
            return Err(Error::custom("not a valid txid:output tuple"));
        }

        let txid_bytes =
            hex::decode(splits[0]).map_err(|_| Error::custom("not a valid hex encoded txid"))?;

        let txid = Sha256::from_slice(&txid_bytes)
            .map_err(|e| Error::custom(format!("Invalid TxId: {}", e)))?;

        let outnum: u32 = splits[1]
            .parse()
            .map_err(|e| Error::custom(format!("{} is not a valid number: {}", s, e)))?;

        Ok(Outpoint { txid, outnum })
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChannelSide {
    LOCAL,
    REMOTE,
}

impl TryFrom<i32> for ChannelSide {
    type Error = crate::Error;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ChannelSide::LOCAL),
            1 => Ok(ChannelSide::REMOTE),
            _ => Err(anyhow!(
                "Invalid ChannelSide mapping, only 0 or 1 are allowed"
            )),
        }
    }
}

impl TryFrom<i32> for ChannelState {
    type Error = crate::Error;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ChannelState::OPENINGD),
            1 => Ok(ChannelState::CHANNELD_AWAITING_LOCKIN),
            2 => Ok(ChannelState::CHANNELD_NORMAL),
            3 => Ok(ChannelState::CHANNELD_SHUTTING_DOWN),
            4 => Ok(ChannelState::CLOSINGD_SIGEXCHANGE),
            5 => Ok(ChannelState::CLOSINGD_COMPLETE),
            6 => Ok(ChannelState::AWAITING_UNILATERAL),
            7 => Ok(ChannelState::FUNDING_SPEND_SEEN),
            8 => Ok(ChannelState::ONCHAIN),
            9 => Ok(ChannelState::DUALOPEND_OPEN_INIT),
            10 => Ok(ChannelState::DUALOPEND_AWAITING_LOCKIN),
            11 => Ok(ChannelState::CHANNELD_AWAITING_SPLICE),
            _ => Err(anyhow!("Invalid channel state {}", value)),
        }
    }
}

impl From<i32> for ChannelTypeName {
    fn from(value: i32) -> Self {
        match value {
            0 => ChannelTypeName::STATIC_REMOTEKEY_EVEN,
            1 => ChannelTypeName::ANCHOR_OUTPUTS_EVEN,
            2 => ChannelTypeName::ANCHORS_ZERO_FEE_HTLC_TX_EVEN,
            3 => ChannelTypeName::SCID_ALIAS_EVEN,
            4 => ChannelTypeName::ZEROCONF_EVEN,
            5 => ChannelTypeName::ANCHORS_EVEN,
            o => panic!("Unmapped ChannelTypeName {}", o),
        }
    }
}

impl From<ChannelTypeName> for i32 {
    fn from(value: ChannelTypeName) -> Self {
        match value {
            ChannelTypeName::STATIC_REMOTEKEY_EVEN => 0,
            ChannelTypeName::ANCHOR_OUTPUTS_EVEN => 1,
            ChannelTypeName::ANCHORS_ZERO_FEE_HTLC_TX_EVEN => 2,
            ChannelTypeName::SCID_ALIAS_EVEN => 3,
            ChannelTypeName::ZEROCONF_EVEN => 4,
            ChannelTypeName::ANCHORS_EVEN => 5,
        }
    }
}

impl From<i32> for HtlcState {
    fn from(value: i32) -> Self {
        match value {
            0 => HtlcState::SENT_ADD_HTLC,
            1 => HtlcState::SENT_ADD_COMMIT,
            2 => HtlcState::RCVD_ADD_REVOCATION,
            3 => HtlcState::RCVD_ADD_ACK_COMMIT,
            4 => HtlcState::SENT_ADD_ACK_REVOCATION,
            5 => HtlcState::RCVD_ADD_ACK_REVOCATION,
            6 => HtlcState::RCVD_REMOVE_HTLC,
            7 => HtlcState::RCVD_REMOVE_COMMIT,
            8 => HtlcState::SENT_REMOVE_REVOCATION,
            9 => HtlcState::SENT_REMOVE_ACK_COMMIT,
            10 => HtlcState::RCVD_REMOVE_ACK_REVOCATION,
            11 => HtlcState::RCVD_ADD_HTLC,
            12 => HtlcState::RCVD_ADD_COMMIT,
            13 => HtlcState::SENT_ADD_REVOCATION,
            14 => HtlcState::SENT_ADD_ACK_COMMIT,
            15 => HtlcState::SENT_REMOVE_HTLC,
            16 => HtlcState::SENT_REMOVE_COMMIT,
            17 => HtlcState::RCVD_REMOVE_REVOCATION,
            18 => HtlcState::RCVD_REMOVE_ACK_COMMIT,
            19 => HtlcState::SENT_REMOVE_ACK_REVOCATION,

            n => panic!("Unmapped HtlcState variant: {}", n),
        }
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let any: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // Amount fields used to be a string with the unit "msat" or
        // "sat" as a suffix. The great consolidation in PR #5306
        // changed that to always be a `u64`, but for backwards
        // compatibility we need to handle both cases.
        let ires: Option<u64> = any.as_u64();
        // TODO(cdecker): Remove string parsing support once the great msat purge is complete
        let sres: Option<&str> = any.as_str();

        match (ires, sres) {
            (Some(i), _) => {
                // Notice that this assumes the field is denominated in `msat`
                Ok(Amount::from_msat(i))
            }
            (_, Some(s)) => s
                .try_into()
                .map_err(|_e| Error::custom("could not parse amount")),
            (None, _) => {
                // We reuse the integer parsing error as that's the
                // default after the great msat purge of 2022.
                Err(Error::custom("could not parse amount"))
            }
        }
    }
}

impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}msat", self.msat))
    }
}

impl Serialize for AmountOrAll {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AmountOrAll::Amount(a) => serializer.serialize_str(&format!("{}msat", a.msat)),
            AmountOrAll::All => serializer.serialize_str("all"),
        }
    }
}

impl Serialize for AmountOrAny {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AmountOrAny::Amount(a) => serializer.serialize_str(&format!("{}msat", a.msat)),
            AmountOrAny::Any => serializer.serialize_str("any"),
        }
    }
}

impl<'de> Deserialize<'de> for AmountOrAny {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Ok(match s.to_lowercase().as_ref() {
            "any" => AmountOrAny::Any,
            v => AmountOrAny::Amount(
                v.try_into()
                    .map_err(|_e| serde::de::Error::custom("could not parse amount"))?,
            ),
        })
    }
}

impl<'de> Deserialize<'de> for AmountOrAll {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Ok(match s.to_lowercase().as_ref() {
            "all" => AmountOrAll::All,
            v => AmountOrAll::Amount(
                v.try_into()
                    .map_err(|_e| serde::de::Error::custom("could not parse amount"))?,
            ),
        })
    }
}

impl TryFrom<&str> for Amount {
    type Error = Error;
    fn try_from(s: &str) -> Result<Amount> {
        let number: u64 = s
            .chars()
            .map(|c| c.to_digit(10))
            .take_while(|opt| opt.is_some())
            .fold(0, |acc, digit| acc * 10 + (digit.unwrap() as u64));

        let s = s.to_lowercase();
        if s.ends_with("msat") {
            Ok(Amount::from_msat(number))
        } else if s.ends_with("sat") {
            Ok(Amount::from_sat(number))
        } else if s.ends_with("btc") {
            Ok(Amount::from_btc(number))
        } else {
            Err(anyhow!("Unable to parse amount from string: {}", s))
        }
    }
}

impl From<Amount> for String {
    fn from(a: Amount) -> String {
        // Best effort msat to sat conversion, for methods that accept
        // sats but not msats
        if a.msat % 1000 == 0 {
            format!("{}sat", a.msat / 1000)
        } else {
            format!("{}msat", a.msat)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Feerate {
    Slow,
    Normal,
    Urgent,
    PerKb(u32),
    PerKw(u32),
}

impl TryFrom<&str> for Feerate {
    type Error = Error;
    fn try_from(s: &str) -> Result<Feerate> {
        let number: u32 = s
            .chars()
            .map(|c| c.to_digit(10))
            .take_while(|opt| opt.is_some())
            .fold(0, |acc, digit| acc * 10 + (digit.unwrap() as u32));

        let s = s.to_lowercase();
        if s.ends_with("perkw") {
            Ok(Feerate::PerKw(number))
        } else if s.ends_with("perkb") {
            Ok(Feerate::PerKb(number))
        } else if s == "slow" {
            Ok(Feerate::Slow)
        } else if s == "normal" {
            Ok(Feerate::Normal)
        } else if s == "urgent" {
            Ok(Feerate::Urgent)
        } else {
            Err(anyhow!("Unable to parse feerate from string: {}", s))
        }
    }
}

impl From<&Feerate> for String {
    fn from(f: &Feerate) -> String {
        match f {
            Feerate::Slow => "slow".to_string(),
            Feerate::Normal => "normal".to_string(),
            Feerate::Urgent => "urgent".to_string(),
            Feerate::PerKb(v) => format!("{}perkb", v),
            Feerate::PerKw(v) => format!("{}perkw", v),
        }
    }
}

impl<'de> Deserialize<'de> for Feerate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let res: Feerate = s
            .as_str()
            .try_into()
            .map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(res)
    }
}

impl Serialize for Feerate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s: String = self.into();
        serializer.serialize_str(&s)
    }
}

#[cfg(test)]
mod test {
    use crate::model::responses::FundchannelResponse;

    use super::*;

    #[test]
    fn test_amount_serde() {
        #[derive(Serialize, PartialEq, Debug, Deserialize)]
        struct T {
            amount: Amount,
        }

        let tests = vec![
            ("{\"amount\": \"10msat\"}", Amount { msat: 10 }, "10msat"),
            ("{\"amount\": \"42sat\"}", Amount { msat: 42_000 }, "42sat"),
            (
                "{\"amount\": \"31337btc\"}",
                Amount {
                    msat: 3_133_700_000_000_000,
                },
                "3133700000000sat",
            ),
        ];

        for (req, res, s) in tests.into_iter() {
            println!("{:?} {:?}", req, res);
            let parsed: T = serde_json::from_str(req).unwrap();
            assert_eq!(res, parsed.amount);

            let serialized: String = parsed.amount.into();
            assert_eq!(s, serialized);
        }
    }

    #[test]
    fn test_amount_all_any() {
        let t = r#"{"any": "any", "all": "all", "not_any": "42msat", "not_all": "31337msat"}"#;

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct T {
            all: AmountOrAll,
            not_all: AmountOrAll,
            any: AmountOrAny,
            not_any: AmountOrAny,
        }

        let parsed: T = serde_json::from_str(t).unwrap();

        let expected = T {
            all: AmountOrAll::All,
            any: AmountOrAny::Any,
            not_all: AmountOrAll::Amount(Amount { msat: 31337 }),
            not_any: AmountOrAny::Amount(Amount { msat: 42 }),
        };
        assert_eq!(expected, parsed);

        let serialized: String = serde_json::to_string(&parsed).unwrap();
        assert_eq!(
            serialized,
            r#"{"all":"all","not_all":"31337msat","any":"any","not_any":"42msat"}"#
        );
    }

    #[test]
    fn test_parse_feerate() {
        let tests = vec![
            ("slow", Feerate::Slow),
            ("normal", Feerate::Normal),
            ("urgent", Feerate::Urgent),
            ("12345perkb", Feerate::PerKb(12345)),
            ("54321perkw", Feerate::PerKw(54321)),
        ];

        for (input, output) in tests.into_iter() {
            let parsed: Feerate = input.try_into().unwrap();
            assert_eq!(parsed, output);
            let serialized: String = (&parsed).into();
            assert_eq!(serialized, input);
        }
    }

    #[test]
    fn test_parse_output_desc() {
        let a = r#"{"address":"1234msat"}"#;
        let od = serde_json::from_str(a).unwrap();

        assert_eq!(
            OutputDesc {
                address: "address".to_string(),
                amount: Amount { msat: 1234 }
            },
            od
        );
        let serialized: String = serde_json::to_string(&od).unwrap();
        assert_eq!(a, serialized);
    }

    #[test]
    fn tlvstream() {
        let stream = TlvStream {
            entries: vec![
                TlvEntry {
                    typ: 31337,
                    value: vec![1, 2, 3, 4, 5],
                },
                TlvEntry {
                    typ: 42,
                    value: vec![],
                },
            ],
        };

        let res = serde_json::to_string(&stream).unwrap();
        assert_eq!(res, "{\"31337\":\"0102030405\",\"42\":\"\"}");
    }

    #[test]
    fn test_fundchannel() {
        let r = serde_json::json!({
            "tx": "0000000000000000000000000000000000000000000000000000000000000000",
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "outnum": 0,
            "channel_id": "0000000000000000000000000000000000000000000000000000000000000000",
            "channel_type": {
        "bits": [1, 3, 5],
        "names": [
                    "static_remotekey/even",
                    "anchor_outputs/even",
                    "anchors_zero_fee_htlc_tx/even",
                    "scid_alias/even",
                    "zeroconf/even"
        ]
            },
        "close_to": "bc1qd23gerv2mn0qdecrmulsjsmkv8lz6t6m0770tg",
        "mindepth": 1,
        });

        let p: FundchannelResponse = serde_json::from_value(r).unwrap();
        assert_eq!(p.channel_type.unwrap().bits, vec![1, 3, 5]);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutputDesc {
    pub address: String,
    pub amount: Amount,
}

impl<'de> Deserialize<'de> for OutputDesc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: std::collections::HashMap<String, Amount> =
            Deserialize::deserialize(deserializer)?;

        let (address, amount) = map.iter().next().unwrap();

        Ok(OutputDesc {
            address: address.to_string(),
            amount: *amount,
        })
    }
}

impl Serialize for OutputDesc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_key(&self.address)?;
        map.serialize_value(&self.amount)?;
        map.end()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Routehop {
    pub id: PublicKey,
    pub scid: ShortChannelId,
    pub feebase: Amount,
    pub feeprop: u32,
    pub expirydelta: u16,
}

#[derive(Clone, Debug)]
pub struct Routehint {
    pub hops: Vec<Routehop>,
}

#[derive(Clone, Debug)]
pub struct RoutehintList {
    pub hints: Vec<Routehint>,
}

use serde::ser::SerializeSeq;

impl Serialize for Routehint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.hops.len()))?;
        for e in self.hops.iter() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl Serialize for RoutehintList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.hints.len()))?;
        for e in self.hints.iter() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for RoutehintList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hints: Vec<Routehint> = Vec::deserialize(deserializer)?;

        Ok(RoutehintList { hints })
    }
}

impl<'de> Deserialize<'de> for Routehint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hops: Vec<Routehop> = Vec::deserialize(deserializer)?;

        Ok(Routehint { hops })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodeRoutehop {
    pub pubkey: PublicKey,
    pub short_channel_id: ShortChannelId,
    pub fee_base_msat: Amount,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
}

#[derive(Clone, Debug)]
pub struct DecodeRoutehint {
    pub hops: Vec<DecodeRoutehop>,
}

#[derive(Clone, Debug)]
pub struct DecodeRoutehintList {
    pub hints: Vec<DecodeRoutehint>,
}

impl Serialize for DecodeRoutehint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.hops.len()))?;
        for e in self.hops.iter() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl Serialize for DecodeRoutehintList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.hints.len()))?;
        for e in self.hints.iter() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for DecodeRoutehintList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hints: Vec<DecodeRoutehint> = Vec::deserialize(deserializer)?;

        Ok(DecodeRoutehintList { hints })
    }
}

impl<'de> Deserialize<'de> for DecodeRoutehint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hops: Vec<DecodeRoutehop> = Vec::deserialize(deserializer)?;

        Ok(DecodeRoutehint { hops })
    }
}

/// An error returned by the lightningd RPC consisting of a code and a
/// message
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RpcError {
    pub code: Option<i32>,
    pub message: String,
    pub data: Option<Value>,
}

impl Display for RpcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = self.code {
            write!(f, "Error code {}: {}", code, self.message)
        } else {
            write!(f, "Error: {}", self.message)
        }
    }
}

impl std::error::Error for RpcError {}

#[derive(Clone, Debug)]
pub struct TlvEntry {
    pub typ: u64,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TlvStream {
    pub entries: Vec<TlvEntry>,
}

impl<'de> Deserialize<'de> for TlvStream {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: std::collections::HashMap<u64, String> = Deserialize::deserialize(deserializer)?;

        let entries = map
            .iter()
            .map(|(k, v)| TlvEntry {
                typ: *k,
                value: hex::decode(v).unwrap(),
            })
            .collect();

        Ok(TlvStream { entries })
    }
}

impl Serialize for TlvStream {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for e in &self.entries {
            map.serialize_key(&e.typ)?;
            map.serialize_value(&hex::encode(&e.value))?;
        }
        map.end()
    }
}
