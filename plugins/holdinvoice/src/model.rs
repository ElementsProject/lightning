use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use cln_rpc::model::ListinvoicesInvoices;
use parking_lot::Mutex;

use crate::Holdstate;

#[derive(Clone, Debug)]
pub struct HoldHtlc {
    pub amount_msat: u64,
    pub cltv_expiry: u32,
    pub loop_mutex: Arc<tokio::sync::Mutex<bool>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HtlcIdentifier {
    pub scid: String,
    pub htlc_id: u64,
}

#[derive(Clone, Debug)]
pub struct HoldInvoice {
    pub hold_state: Holdstate,
    pub generation: u64,
    pub htlc_data: HashMap<HtlcIdentifier, HoldHtlc>,
    pub last_htlc_expiry: u32,
    pub invoice: ListinvoicesInvoices,
}

#[derive(Clone, Debug)]
pub struct PluginState {
    pub blockheight: Arc<Mutex<u32>>,
    pub holdinvoices: Arc<tokio::sync::Mutex<BTreeMap<String, HoldInvoice>>>,
}
