use serde::{Deserialize, Serialize};

use crate::jsonrpc::JsonRpcRequest;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lsps0listProtocolsRequest {}

impl JsonRpcRequest for Lsps0listProtocolsRequest {
    const METHOD: &'static str = "lsps0.list_protocols";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lsps0listProtocolsResponse {
    pub protocols: Vec<u8>,
}
