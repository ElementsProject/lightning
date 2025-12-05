use crate::{
    cln_adapters::utils::encode_lsps0_frame_hex,
    core::transport::{Error as TransportError, MessageSender},
};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use cln_rpc::{model::requests::SendcustommsgRequest, ClnRpc};
use std::path::PathBuf;

#[derive(Clone)]
pub struct ClnSender {
    rpc_path: PathBuf,
}

impl ClnSender {
    pub fn new(rpc_path: PathBuf) -> Self {
        Self { rpc_path }
    }
}

#[async_trait]
impl MessageSender for ClnSender {
    async fn send(&self, peer_id: &PublicKey, payload: &[u8]) -> Result<(), TransportError> {
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))?;

        // Encode frame for LSPS0 Bolt8 transport.
        let msg = encode_lsps0_frame_hex(payload);

        rpc.call_typed(&SendcustommsgRequest {
            msg,
            node_id: peer_id.to_owned(),
        })
        .await
        .map_err(|e| TransportError::Internal(e.to_string()))?;

        Ok(())
    }
}
