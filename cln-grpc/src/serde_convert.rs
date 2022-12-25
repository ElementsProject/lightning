use crate::pb;
use std::convert::From;
use std::num::ParseIntError;

#[allow(unused_variables)]
impl From<serde_json::Value> for pb::Invoicecreation {
    fn from(c: serde_json::Value) -> Self {
        let obj = c["invoice_creation"].as_object().unwrap();
        let parsed_msat = parse_int(&obj["msat"].as_str().unwrap()).unwrap();

        Self {
            label: String::from(obj["label"].as_str().unwrap()),
            preimage: serde_json::to_vec(&obj["preimage"]).ok(),
            amount_msat: Some(pb::Amount { msat: parsed_msat }),
        }
    }
}

fn parse_int(val: &str) -> Result<u64, ParseIntError> {
    let msat_pos = val.find("m").unwrap_or(val.len());
    val[..msat_pos].parse()
}
