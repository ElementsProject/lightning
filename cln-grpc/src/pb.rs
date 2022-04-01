tonic::include_proto!("cln");

use cln_rpc::primitives::{
    Amount as JAmount, Feerate as JFeerate, OutputDesc as JOutputDesc, Utxo as JUtxo,
};

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

impl From<&Feerate> for cln_rpc::primitives::Feerate {
    fn from(f: &Feerate) -> cln_rpc::primitives::Feerate {
        use feerate::Style;
        match f.style.clone().unwrap() {
            Style::Slow(_) => JFeerate::Slow,
            Style::Normal(_) => JFeerate::Normal,
            Style::Urgent(_) => JFeerate::Urgent,
            Style::Perkw(i) => JFeerate::PerKw(i),
            Style::Perkb(i) => JFeerate::PerKb(i),
        }
    }
}

impl From<&OutputDesc> for JOutputDesc {
    fn from(od: &OutputDesc) -> JOutputDesc {
        JOutputDesc {
            address: od.address.clone(),
            amount: od.amount.as_ref().unwrap().into(),
        }
    }
}
