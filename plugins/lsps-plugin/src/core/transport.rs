use crate::proto::jsonrpc::{JsonRpcResponse, RequestObject};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use core::fmt::Debug;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Transport-specific errors that may occur when sending or receiving JSON-RPC
/// messages.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Timeout")]
    Timeout,
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Couldn't parse JSON-RPC request")]
    ParseRequest {
        #[source]
        source: serde_json::Error,
    },
    #[error("request is missing id")]
    MissingId,
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::ParseRequest { source: value }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Defines the interface for transporting JSON-RPC messages.
///
/// Implementors of this trait are responsible for actually sending the JSON-RPC
/// request over some transport mechanism (RPC, Bolt8, etc.)
#[async_trait]
pub trait Transport: Send + Sync {
    async fn request<P, R>(
        &self,
        _peer_id: &PublicKey,
        _request: &RequestObject<P>,
    ) -> Result<JsonRpcResponse<R>>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send;
}
