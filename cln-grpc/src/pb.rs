tonic::include_proto!("cln");

use cln_rpc::primitives::Amount as JAmount;

impl From<JAmount> for Amount {
    fn from(a: JAmount) -> Self {
        Amount { msat: a.msat() }
    }
}

impl From<Amount> for JAmount {
    fn from(a: Amount) -> Self {
        JAmount::from_msat(a.msat)
    }
}

impl From<&Amount> for JAmount {
    fn from(a: &Amount) -> Self {
        match a {
            Amount {
                unit: Some(amount::Unit::Millisatoshi(v)),
            } => JAmount::Millisatoshi(*v),
            Amount {
                unit: Some(amount::Unit::Satoshi(v)),
            } => JAmount::Satoshi(*v),
            Amount {
                unit: Some(amount::Unit::Bitcoin(v)),
            } => JAmount::Bitcoin(*v),
	    o => panic!("Unhandled conversion from pb:Amount to json:Amount: {:?}", o),
        }
    }
}
