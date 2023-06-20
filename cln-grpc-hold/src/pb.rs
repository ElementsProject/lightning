tonic::include_proto!("cln");
use bitcoin::hashes::Hash;
use std::str::FromStr;

use cln_rpc::primitives::{
    Amount as JAmount, AmountOrAll as JAmountOrAll, AmountOrAny as JAmountOrAny,
    Feerate as JFeerate, Outpoint as JOutpoint, OutputDesc as JOutputDesc,
};

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

impl From<JOutpoint> for Outpoint {
    fn from(a: JOutpoint) -> Self {
        Outpoint {
            txid: a.txid.to_vec(),
            outnum: a.outnum,
        }
    }
}

impl From<Outpoint> for JOutpoint {
    fn from(a: Outpoint) -> Self {
        JOutpoint {
            txid: bitcoin::hashes::sha256::Hash::from_slice(&a.txid).unwrap(),
            outnum: a.outnum,
        }
    }
}

impl From<Feerate> for cln_rpc::primitives::Feerate {
    fn from(f: Feerate) -> cln_rpc::primitives::Feerate {
        use feerate::Style;
        match f.style.unwrap() {
            Style::Slow(_) => JFeerate::Slow,
            Style::Normal(_) => JFeerate::Normal,
            Style::Urgent(_) => JFeerate::Urgent,
            Style::Perkw(i) => JFeerate::PerKw(i),
            Style::Perkb(i) => JFeerate::PerKb(i),
        }
    }
}

impl From<cln_rpc::primitives::Feerate> for Feerate {
    fn from(f: cln_rpc::primitives::Feerate) -> Feerate {
        use feerate::Style;
        let style = Some(match f {
            JFeerate::Slow => Style::Slow(true),
            JFeerate::Normal => Style::Normal(true),
            JFeerate::Urgent => Style::Urgent(true),
            JFeerate::PerKb(i) => Style::Perkb(i),
            JFeerate::PerKw(i) => Style::Perkw(i),
        });
        Self { style }
    }
}

impl From<OutputDesc> for JOutputDesc {
    fn from(od: OutputDesc) -> JOutputDesc {
        JOutputDesc {
            address: od.address,
            amount: od.amount.unwrap().into(),
        }
    }
}

impl From<JOutputDesc> for OutputDesc {
    fn from(od: JOutputDesc) -> Self {
        Self {
            address: od.address,
            amount: Some(od.amount.into()),
        }
    }
}

impl From<JAmountOrAll> for AmountOrAll {
    fn from(a: JAmountOrAll) -> Self {
        match a {
            JAmountOrAll::Amount(a) => AmountOrAll {
                value: Some(amount_or_all::Value::Amount(a.into())),
            },
            JAmountOrAll::All => AmountOrAll {
                value: Some(amount_or_all::Value::All(true)),
            },
        }
    }
}

impl From<AmountOrAll> for JAmountOrAll {
    fn from(a: AmountOrAll) -> Self {
        match a.value {
            Some(amount_or_all::Value::Amount(a)) => JAmountOrAll::Amount(a.into()),
            Some(amount_or_all::Value::All(_)) => JAmountOrAll::All,
            None => panic!("AmountOrAll is neither amount nor all: {:?}", a),
        }
    }
}

impl From<JAmountOrAny> for AmountOrAny {
    fn from(a: JAmountOrAny) -> Self {
        match a {
            JAmountOrAny::Amount(a) => AmountOrAny {
                value: Some(amount_or_any::Value::Amount(a.into())),
            },
            JAmountOrAny::Any => AmountOrAny {
                value: Some(amount_or_any::Value::Any(true)),
            },
        }
    }
}
impl From<AmountOrAny> for JAmountOrAny {
    fn from(a: AmountOrAny) -> Self {
        match a.value {
            Some(amount_or_any::Value::Amount(a)) => JAmountOrAny::Amount(a.into()),
            Some(amount_or_any::Value::Any(_)) => JAmountOrAny::Any,
            None => panic!("AmountOrAll is neither amount nor any: {:?}", a),
        }
    }
}
impl From<RouteHop> for cln_rpc::primitives::Routehop {
    fn from(c: RouteHop) -> Self {
        Self {
            id: cln_rpc::primitives::PublicKey::from_slice(&c.id).unwrap(),
            scid: cln_rpc::primitives::ShortChannelId::from_str(&c.short_channel_id).unwrap(),
            feebase: c.feebase.unwrap().into(),
            feeprop: c.feeprop,
            expirydelta: c.expirydelta as u16,
        }
    }
}

impl From<Routehint> for cln_rpc::primitives::Routehint {
    fn from(c: Routehint) -> Self {
        Self {
            hops: c.hops.into_iter().map(|h| h.into()).collect(),
        }
    }
}

impl From<RoutehintList> for cln_rpc::primitives::RoutehintList {
    fn from(c: RoutehintList) -> Self {
        Self {
            hints: c.hints.into_iter().map(|h| h.into()).collect(),
        }
    }
}

impl From<cln_rpc::primitives::Routehop> for RouteHop {
    fn from(c: cln_rpc::primitives::Routehop) -> Self {
        Self {
            id: c.id.serialize().to_vec(),
            feebase: Some(c.feebase.into()),
            feeprop: c.feeprop,
            expirydelta: c.expirydelta as u32,
            short_channel_id: c.scid.to_string(),
        }
    }
}

impl From<cln_rpc::primitives::Routehint> for Routehint {
    fn from(c: cln_rpc::primitives::Routehint) -> Self {
        Self {
            hops: c.hops.into_iter().map(|h| h.into()).collect(),
        }
    }
}

impl From<cln_rpc::primitives::RoutehintList> for RoutehintList {
    fn from(c: cln_rpc::primitives::RoutehintList) -> Self {
        Self {
            hints: c.hints.into_iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<TlvStream> for cln_rpc::primitives::TlvStream {
    fn from(s: TlvStream) -> Self {
        Self {
            entries: s.entries.into_iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<TlvEntry> for cln_rpc::primitives::TlvEntry {
    fn from(e: TlvEntry) -> Self {
        Self {
            typ: e.r#type,
            value: e.value,
        }
    }
}

impl From<cln_rpc::primitives::TlvStream> for TlvStream {
    fn from(s: cln_rpc::primitives::TlvStream) -> Self {
        Self {
            entries: s.entries.into_iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<cln_rpc::primitives::TlvEntry> for TlvEntry {
    fn from(e: cln_rpc::primitives::TlvEntry) -> Self {
        Self {
            r#type: e.typ,
            value: e.value,
        }
    }
}
