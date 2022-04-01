use anyhow::Context;
use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use std::str::FromStr;
use std::string::ToString;

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum ChannelState {
    OPENINGD,
    CHANNELD_AWAITING_LOCKIN,
    CHANNELD_NORMAL,
    CHANNELD_SHUTTING_DOWN,
    CLOSINGD_SIGEXCHANGE,
    CLOSINGD_COMPLETE,
    AWAITING_UNILATERAL,
    FUNDING_SPEND_SEEN,
    ONCHAIN,
    DUALOPEND_OPEN_INIT,
    DUALOPEND_AWAITING_LOCKIN,
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
        Amount { msat: msat }
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

#[derive(Clone, Debug)]
pub struct Pubkey([u8; 33]);

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s: String = Deserialize::deserialize(deserializer)?;
        Ok(Self::from_str(&s).map_err(|e| Error::custom(e.to_string()))?)
    }
}

impl FromStr for Pubkey {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw =
            hex::decode(&s).with_context(|| format!("{} is not a valid hex-encoded pubkey", s))?;

        Ok(Pubkey(raw.try_into().map_err(|_| {
            anyhow!("could not convert {} into pubkey", s)
        })?))
    }
}
impl ToString for Pubkey {
    fn to_string(&self) -> String {
        hex::encode(self.0)
    }
}
impl Pubkey {
    pub fn from_slice(data: &[u8]) -> Result<Pubkey, crate::Error> {
        Ok(Pubkey(
            data.try_into().with_context(|| "Not a valid pubkey")?,
        ))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[derive(Clone, Debug)]
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
impl ToString for ShortChannelId {
    fn to_string(&self) -> String {
        format!("{}x{}x{}", self.block(), self.txindex(), self.outnum())
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
}

pub type Secret = [u8; 32];
pub type Txid = [u8; 32];
pub type Hash = [u8; 32];
pub type NodeId = Pubkey;

#[derive(Clone, Debug, PartialEq)]
pub struct Outpoint {
    pub txid: Vec<u8>,
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

        let txid =
            hex::decode(splits[0]).map_err(|_| Error::custom("not a valid hex encoded txid"))?;
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

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s: String = Deserialize::deserialize(deserializer)?;
        let ss: &str = &s;
        ss.try_into()
            .map_err(|_e| Error::custom("could not parse amount"))
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
        format!("{}msat", a.msat)
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
    use super::*;

    #[test]
    fn test_amount_serde() {
        #[derive(Serialize, PartialEq, Debug, Deserialize)]
        struct T {
            amount: Amount,
        }

        let tests = vec![
            ("{\"amount\": \"10msat\"}", Amount { msat: 10 }, "10msat"),
            (
                "{\"amount\": \"42sat\"}",
                Amount { msat: 42_000 },
                "42000msat",
            ),
            (
                "{\"amount\": \"31337btc\"}",
                Amount {
                    msat: 3_133_700_000_000_000,
                },
                "3133700000000000msat",
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
    pub id: Pubkey,
    pub scid: ShortChannelId,
    pub feebase: Amount,
    pub feeprop: u32,
    pub expirydelta: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Routehint {
    pub hops: Vec<Routehop>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutehintList {
    pub hints: Vec<Routehint>,
}
