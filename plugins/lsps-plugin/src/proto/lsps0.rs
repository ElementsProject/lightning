use crate::proto::jsonrpc::JsonRpcRequest;
use serde::{Deserialize, Serialize};

// Optional feature bet to set according to LSPS0.
pub const LSP_FEATURE_BIT: usize = 729;

// Required message type for BOLT8 transport.
pub const LSPS0_MESSAGE_TYPE: u16 = 37913;

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
