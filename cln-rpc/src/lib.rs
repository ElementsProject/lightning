use anyhow::{Error, Result};
use std::path::Path;
mod primitives;
mod responses;

#[macro_use]
extern crate serde_json;
///
pub struct ClnRpc {}

impl ClnRpc {
    pub fn new<P>(path: P) -> Result<ClnRpc>
    where
        P: AsRef<Path>,
    {
        todo!();
    }
}
