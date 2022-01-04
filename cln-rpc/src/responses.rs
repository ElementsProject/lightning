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

#[cfg(test)]
mod test {

    extern crate serde_json;

    use super::*;

    #[test]
    fn test_getinfo_response() {
        let response = json!({
           "id": "030303030303030303030303030303030303030303030303030303030303030303",
           "alias": "HelloWorld",
           "color": "02a5de",
           "num_peers": 15,
           "num_pending_channels": 0,
           "num_active_channels": 10,
           "num_inactive_channels": 0,
           "address": [
              {
                 "type": "torv3",
                 "address": "p4hu3poet2m5ofqtoeyoko65kocmmjkkezoyj3k3kizxf2lzqd.onion",
                 "port": 9735
              }
           ],
           "binding": [
              {
                 "type": "ipv4",
                 "address": "0.0.0.0",
                 "port": 9735
              }
           ],
           "version": "v0.10.1",
           "blockheight": 716138,
           "network": "bitcoin",
           "msatoshi_fees_collected": 46390,
           "fees_collected_msat": "46390msat",
           "lightning-dir": "/mnt/ssd/bitcoin/.lightning/bitcoin"
        });

        let parsed: Getinfo = serde_json::from_str(&response.to_string()).unwrap();
    }
}
