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
}
