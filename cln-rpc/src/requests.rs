use serde::{Deserialize, Serialize};

mod getinfo;

pub use getinfo::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Getinfo(Getinfo),
}
