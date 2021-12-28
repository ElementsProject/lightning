use anyhow::{anyhow, Error, Result};
use serde::Deserializer;
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum ChannelStateChangeCause {
    UNKNOWN,
    LOCAL,
    USER,
    REMOTE,
    PROTOCOL,
    ONCHAIN,
}

#[derive(Clone, Serialize, Debug, PartialEq)]
pub enum Amount {
    Millisatoshi(u64),
    Satoshi(u64),
    Millibitcoin(u64),
    Bitcoin(u64),
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
            Ok(Amount::Millisatoshi(number))
        } else if s.ends_with("sat") {
            Ok(Amount::Satoshi(number))
        } else if s.ends_with("mbtc") {
            Ok(Amount::Millibitcoin(number))
        } else if s.ends_with("btc") {
            Ok(Amount::Bitcoin(number))
        } else {
            Err(anyhow!("Unable to parse amount from string: {}", s))
        }
    }
}

impl From<Amount> for String {
    fn from(a: Amount) -> String {
        match a {
            Amount::Millisatoshi(v) => format!("{}msat", v),
            Amount::Satoshi(v) => format!("{}sat", v),
            Amount::Millibitcoin(v) => format!("{}mbtc", v),
            Amount::Bitcoin(v) => format!("{}btc", v),
        }
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
            (
                "{\"amount\": \"10msat\"}",
                Amount::Millisatoshi(10),
                "10msat",
            ),
            ("{\"amount\": \"42sat\"}", Amount::Satoshi(42), "42sat"),
            (
                "{\"amount\": \"31337btc\"}",
                Amount::Bitcoin(31337),
                "31337btc",
            ),
            (
                "{\"amount\": \"123mbtc\"}",
                Amount::Millibitcoin(123),
                "123mbtc",
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
