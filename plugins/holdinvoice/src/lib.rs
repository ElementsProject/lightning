use std::{fmt, str::FromStr};

use anyhow::{anyhow, Error};

pub mod hold;
pub mod model;
pub mod util;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Holdstate {
    Open,
    Settled,
    Canceled,
    Accepted,
}
impl Holdstate {
    pub fn as_i32(&self) -> i32 {
        match self {
            Holdstate::Open => 0,
            Holdstate::Settled => 1,
            Holdstate::Canceled => 2,
            Holdstate::Accepted => 3,
        }
    }
    pub fn is_valid_transition(&self, newstate: &Holdstate) -> bool {
        match self {
            Holdstate::Open => !matches!(newstate, Holdstate::Settled),
            Holdstate::Settled => matches!(newstate, Holdstate::Settled),
            Holdstate::Canceled => matches!(newstate, Holdstate::Canceled),
            Holdstate::Accepted => true,
        }
    }
}
impl fmt::Display for Holdstate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Holdstate::Open => write!(f, "open"),
            Holdstate::Settled => write!(f, "settled"),
            Holdstate::Canceled => write!(f, "canceled"),
            Holdstate::Accepted => write!(f, "accepted"),
        }
    }
}
impl FromStr for Holdstate {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(Holdstate::Open),
            "settled" => Ok(Holdstate::Settled),
            "canceled" => Ok(Holdstate::Canceled),
            "accepted" => Ok(Holdstate::Accepted),
            _ => Err(anyhow!("could not parse Holdstate from {}", s)),
        }
    }
}
