tonic::include_proto!("cln");

use cln_rpc::primitives::{Amount as JAmount, Utxo as JUtxo};

impl From<JAmount> for Amount {
    fn from(a: JAmount) -> Self {
        Amount { msat: a.msat() }
    }
}

impl From<&Amount> for JAmount {
    fn from(a: &Amount) -> Self {
        JAmount::from_msat(a.msat)
    }
}

impl From<JUtxo> for Utxo {
    fn from(a: JUtxo) -> Self {
        Utxo {
            txid: a.txid,
            outnum: a.outnum,
        }
    }
}

impl From<&Utxo> for JUtxo {
    fn from(a: &Utxo) -> Self {
        JUtxo {
            txid: a.txid.clone(),
            outnum: a.outnum,
        }
    }
}
