// Huge json!() macros require lots of recursion
#![recursion_limit = "1024"]

mod convert;
pub mod pb;
mod server;

use std::{fmt, path::PathBuf};

use anyhow::{anyhow, Error};
use cln_rpc::{
    model::{
        DatastoreMode, DatastoreRequest, DatastoreResponse, DeldatastoreRequest,
        DeldatastoreResponse, ListdatastoreDatastore, ListdatastoreRequest, ListdatastoreResponse,
    },
    ClnRpc, Request, Response,
};
use log::debug;

pub use crate::server::Server;

pub const HODLVOICE_PLUGIN_NAME: &str = "hodlvoice";
const HODLVOICE_DATASTORE_STATE: &str = "state";
const HODLVOICE_DATASTORE_HTLC_EXPIRY: &str = "expiry";

#[cfg(test)]
mod test;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Hodlstate {
    Open,
    Settled,
    Canceled,
    Accepted,
}
impl Hodlstate {
    pub fn to_string(&self) -> String {
        match self {
            Hodlstate::Open => "open".to_string(),
            Hodlstate::Settled => "settled".to_string(),
            Hodlstate::Canceled => "canceled".to_string(),
            Hodlstate::Accepted => "accepted".to_string(),
        }
    }
    pub fn from_str(s: &str) -> Result<Hodlstate, Error> {
        match s.to_lowercase().as_str() {
            "open" => Ok(Hodlstate::Open),
            "settled" => Ok(Hodlstate::Settled),
            "canceled" => Ok(Hodlstate::Canceled),
            "accepted" => Ok(Hodlstate::Accepted),
            _ => Err(anyhow!("could not parse Hodlstate from string")),
        }
    }
    pub fn as_i32(&self) -> i32 {
        match self {
            Hodlstate::Open => 0,
            Hodlstate::Settled => 1,
            Hodlstate::Canceled => 2,
            Hodlstate::Accepted => 3,
        }
    }
    pub fn is_valid_transition(&self, newstate: &Hodlstate) -> bool {
        match self {
            Hodlstate::Open => match newstate {
                Hodlstate::Settled => false,
                _ => true,
            },
            Hodlstate::Settled => match newstate {
                Hodlstate::Settled => true,
                _ => false,
            },
            Hodlstate::Canceled => match newstate {
                Hodlstate::Canceled => true,
                _ => false,
            },
            Hodlstate::Accepted => true,
        }
    }
}
impl fmt::Display for Hodlstate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hodlstate::Open => write!(f, "open"),
            Hodlstate::Settled => write!(f, "settled"),
            Hodlstate::Canceled => write!(f, "canceled"),
            Hodlstate::Accepted => write!(f, "accepted"),
        }
    }
}

async fn datastore_raw(
    rpc_path: &PathBuf,
    key: Vec<String>,
    string: Option<String>,
    hex: Option<String>,
    mode: Option<DatastoreMode>,
    generation: Option<u64>,
) -> Result<DatastoreResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let datastore_request = rpc
        .call(Request::Datastore(DatastoreRequest {
            key: key.clone(),
            string: string.clone(),
            hex,
            mode,
            generation,
        }))
        .await
        .map_err(|e| anyhow!("Error calling datastore: {:?}", e))?;
    debug!("datastore_raw: set {:?} to {}", key, string.unwrap());
    match datastore_request {
        Response::Datastore(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in datastore: {:?}", e)),
    }
}

async fn datastore_new_state(
    rpc_path: &PathBuf,
    pay_hash: String,
    string: String,
) -> Result<DatastoreResponse, Error> {
    datastore_raw(
        rpc_path,
        vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash,
            HODLVOICE_DATASTORE_STATE.to_string(),
        ],
        Some(string),
        None,
        Some(DatastoreMode::MUST_CREATE),
        None,
    )
    .await
}

pub async fn datastore_update_state(
    rpc_path: &PathBuf,
    pay_hash: String,
    string: String,
    generation: u64,
) -> Result<DatastoreResponse, Error> {
    datastore_raw(
        rpc_path,
        vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash,
            HODLVOICE_DATASTORE_STATE.to_string(),
        ],
        Some(string),
        None,
        Some(DatastoreMode::MUST_REPLACE),
        Some(generation),
    )
    .await
}

async fn datastore_update_state_forced(
    rpc_path: &PathBuf,
    pay_hash: String,
    string: String,
) -> Result<DatastoreResponse, Error> {
    datastore_raw(
        rpc_path,
        vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash,
            HODLVOICE_DATASTORE_STATE.to_string(),
        ],
        Some(string),
        None,
        Some(DatastoreMode::MUST_REPLACE),
        None,
    )
    .await
}

pub async fn datastore_htlc_expiry(
    rpc_path: &PathBuf,
    pay_hash: String,
    string: String,
) -> Result<DatastoreResponse, Error> {
    datastore_raw(
        rpc_path,
        vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash,
            HODLVOICE_DATASTORE_HTLC_EXPIRY.to_string(),
        ],
        Some(string),
        None,
        Some(DatastoreMode::CREATE_OR_REPLACE),
        None,
    )
    .await
}

// pub async fn datastore_update_htlc_expiry(
//     rpc_path: &PathBuf,
//     pay_hash: String,
//     string: String,
// ) -> Result<DatastoreResponse, Error> {
//     datastore_raw(
//         rpc_path,
//         vec![
//             HODLVOICE_PLUGIN_NAME.to_string(),
//             pay_hash,
//             HODLVOICE_DATASTORE_HTLC_EXPIRY.to_string(),
//         ],
//         Some(string),
//         None,
//         Some(DatastoreMode::MUST_REPLACE),
//         None,
//     )
//     .await
// }

async fn listdatastore_raw(
    rpc_path: &PathBuf,
    key: Option<Vec<String>>,
) -> Result<ListdatastoreResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let datastore_request = rpc
        .call(Request::ListDatastore(ListdatastoreRequest { key }))
        .await
        .map_err(|e| anyhow!("Error calling listdatastore: {:?}", e))?;
    match datastore_request {
        Response::ListDatastore(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in listdatastore: {:?}", e)),
    }
}

pub async fn listdatastore_all(rpc_path: &PathBuf) -> Result<ListdatastoreResponse, Error> {
    listdatastore_raw(rpc_path, Some(vec![HODLVOICE_PLUGIN_NAME.to_string()])).await
}

pub async fn listdatastore_state(
    rpc_path: &PathBuf,
    pay_hash: String,
) -> Result<ListdatastoreDatastore, Error> {
    let response = listdatastore_raw(
        rpc_path,
        Some(vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash.clone(),
            HODLVOICE_DATASTORE_STATE.to_string(),
        ]),
    )
    .await?;
    let data = response.datastore.first().ok_or_else(|| {
        anyhow!(
            "empty result for listdatastore_state with pay_hash: {}",
            pay_hash
        )
    })?;
    Ok(data.clone())
}

pub async fn listdatastore_htlc_expiry(rpc_path: &PathBuf, pay_hash: String) -> Result<u32, Error> {
    let response = listdatastore_raw(
        rpc_path,
        Some(vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash.clone(),
            HODLVOICE_DATASTORE_HTLC_EXPIRY.to_string(),
        ]),
    )
    .await?;
    let data = response
        .datastore
        .first()
        .ok_or_else(|| {
            anyhow!(
                "empty result for listdatastore_htlc_expiry with pay_hash: {}",
                pay_hash
            )
        })?
        .string
        .as_ref()
        .ok_or_else(|| {
            anyhow!(
                "None string for listdatastore_htlc_expiry with pay_hash: {}",
                pay_hash
            )
        })?;
    let cltv = data.parse::<u32>()?;
    Ok(cltv)
}

async fn del_datastore_raw(
    rpc_path: &PathBuf,
    key: Vec<String>,
) -> Result<DeldatastoreResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let del_datastore_request = rpc
        .call(Request::DelDatastore(DeldatastoreRequest {
            key,
            generation: None,
        }))
        .await
        .map_err(|e| anyhow!("Error calling DelDatastore: {:?}", e))?;
    match del_datastore_request {
        Response::DelDatastore(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in DelDatastore: {:?}", e)),
    }
}

pub async fn del_datastore_state(
    rpc_path: &PathBuf,
    pay_hash: String,
) -> Result<DeldatastoreResponse, Error> {
    del_datastore_raw(
        rpc_path,
        vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash,
            HODLVOICE_DATASTORE_STATE.to_string(),
        ],
    )
    .await
}

pub async fn del_datastore_htlc_expiry(
    rpc_path: &PathBuf,
    pay_hash: String,
) -> Result<DeldatastoreResponse, Error> {
    del_datastore_raw(
        rpc_path,
        vec![
            HODLVOICE_PLUGIN_NAME.to_string(),
            pay_hash.clone(),
            HODLVOICE_DATASTORE_HTLC_EXPIRY.to_string(),
        ],
    )
    .await
}

fn short_channel_id_to_string(scid: u64) -> String {
    let block_height = scid >> 40;
    let tx_index = (scid >> 16) & 0xFFFFFF;
    let output_index = scid & 0xFFFF;
    format!("{}x{}x{}", block_height, tx_index, output_index)
}
