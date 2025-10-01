use crate::{
    jsonrpc::{server::RequestHandler, JsonRpcResponse, RequestObject, RpcError},
    lsps0::model::{Lsps0listProtocolsRequest, Lsps0listProtocolsResponse},
    util::unwrap_payload_with_peer_id,
};
use async_trait::async_trait;

pub struct Lsps0ListProtocolsHandler {
    pub lsps2_enabled: bool,
}

#[async_trait]
impl RequestHandler for Lsps0ListProtocolsHandler {
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
        let (payload, _) = unwrap_payload_with_peer_id(payload);

        let req: RequestObject<Lsps0listProtocolsRequest> =
            serde_json::from_slice(&payload).unwrap();
        if let Some(id) = req.id {
            let mut protocols = vec![];
            if self.lsps2_enabled {
                protocols.push(2);
            }
            let res = Lsps0listProtocolsResponse { protocols }.into_response(id);
            let res_vec = serde_json::to_vec(&res).unwrap();
            return Ok(res_vec);
        }
        // If request has no ID (notification), return empty Ok result.
        Ok(vec![])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        jsonrpc::{JsonRpcRequest, ResponseObject},
        util::wrap_payload_with_peer_id,
    };
    use cln_rpc::primitives::PublicKey;

    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn create_peer_id() -> PublicKey {
        PublicKey::from_slice(&PUBKEY).expect("Valid pubkey")
    }

    fn create_wrapped_request(request: &RequestObject<Lsps0listProtocolsRequest>) -> Vec<u8> {
        let payload = serde_json::to_vec(request).expect("Failed to serialize request");
        wrap_payload_with_peer_id(&payload, create_peer_id())
    }

    #[tokio::test]
    async fn test_lsps2_disabled_returns_empty_protocols() {
        let handler = Lsps0ListProtocolsHandler {
            lsps2_enabled: false,
        };

        let request = Lsps0listProtocolsRequest {}.into_request(Some("test-id".to_string()));
        let payload = create_wrapped_request(&request);

        let result = handler.handle(&payload).await.unwrap();
        let response: ResponseObject<Lsps0listProtocolsResponse> =
            serde_json::from_slice(&result).unwrap();

        let data = response.into_inner().expect("Should have result data");
        assert!(data.protocols.is_empty());
    }

    #[tokio::test]
    async fn test_lsps2_enabled_returns_protocol_2() {
        let handler = Lsps0ListProtocolsHandler {
            lsps2_enabled: true,
        };

        let request = Lsps0listProtocolsRequest {}.into_request(Some("test-id".to_string()));
        let payload = create_wrapped_request(&request);

        let result = handler.handle(&payload).await.unwrap();
        let response: ResponseObject<Lsps0listProtocolsResponse> =
            serde_json::from_slice(&result).unwrap();

        let data = response.into_inner().expect("Should have result data");
        assert_eq!(data.protocols, vec![2]);
    }
}
