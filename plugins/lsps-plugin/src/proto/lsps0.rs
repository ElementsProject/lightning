use crate::jsonrpc::JsonRpcRequest;
use serde::{Deserialize, Serialize};


// Constants for JSON-RPC error codes.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

// Lsps0 error definitions. Are in the range 00000 to 00099.
pub const CLIENT_REJECTED: i64 = 1;

pub enum Error {
    ClientRejected(String),
}

impl Error {
    pub fn client_rejected(msg: String) -> Error {
        Self::ClientRejected(msg)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lsps0listProtocolsRequest {}

impl JsonRpcRequest for Lsps0listProtocolsRequest {
    const METHOD: &'static str = "lsps0.list_protocols";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lsps0listProtocolsResponse {
    pub protocols: Vec<u8>,
}
