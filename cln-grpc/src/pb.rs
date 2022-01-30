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
