//! Messages that we might get from `lightningd` as a response to a
//! query.

use serde::{Deserialize, Serialize};

mod getinfo;

pub use getinfo::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "result")]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Getinfo(Getinfo),
}

