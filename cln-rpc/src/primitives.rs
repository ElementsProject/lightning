use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
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
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq)]
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
}
