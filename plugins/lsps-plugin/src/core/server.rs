use crate::core::router::{JsonRpcRouter, JsonRpcRouterBuilder, RequestContext};
use crate::proto::lsps0::{Lsps0listProtocolsRequest, Lsps0listProtocolsResponse};

pub trait LspsProtocol: Send + Sync + 'static {
    fn register_handler(&self, router: &mut JsonRpcRouterBuilder);
    fn protocol(&self) -> u8;
}

pub struct LspsService {
    router: JsonRpcRouter,
    supported_protocols: Vec<u8>,
}

impl LspsService {
    pub fn builder() -> LspsServiceBuilder {
        LspsServiceBuilder::new()
    }

    pub async fn handle(&self, ctx: &RequestContext, request: &[u8]) -> Option<Vec<u8>> {
        self.router.handle(ctx, request).await
    }

    pub fn protocols(&self) -> &[u8] {
        &self.supported_protocols
    }
}

pub struct LspsServiceBuilder {
    router_builder: JsonRpcRouterBuilder,
    supported_protocols: Vec<u8>,
}

impl LspsServiceBuilder {
    pub fn new() -> Self {
        Self {
            router_builder: JsonRpcRouterBuilder::new(),
            supported_protocols: vec![],
        }
    }

    pub fn with_protocol<M>(mut self, method: M) -> Self
    where
        M: LspsProtocol,
    {
        let proto = method.protocol();
        self.supported_protocols.push(proto);
        method.register_handler(&mut self.router_builder);
        self
    }

    pub fn build(mut self) -> LspsService {
        self.supported_protocols.sort();
        self.supported_protocols.dedup();
        let supported_protocols: Vec<u8> = self
            .supported_protocols
            .into_iter()
            .filter(|&p| p != 0)
            .collect();

        let protocols_for_rpc = supported_protocols.clone();
        self.router_builder.register(
            "lsps0.list_protocols",
            move |_p: Lsps0listProtocolsRequest| {
                let protocols = protocols_for_rpc.clone();
                async move { Ok(Lsps0listProtocolsResponse { protocols }) }
            },
        );

        let router = self.router_builder.build();

        LspsService {
            router,
            supported_protocols,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> RequestContext {
        RequestContext {
            peer_id: "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                .parse()
                .unwrap(),
        }
    }

    // Minimal mock - just tracks protocol number
    struct MockProtocol(u8);

    impl LspsProtocol for MockProtocol {
        fn register_handler(&self, _router: &mut JsonRpcRouterBuilder) {
            // No-op, we just care about protocol number
        }

        fn protocol(&self) -> u8 {
            self.0
        }
    }

    #[test]
    fn test_protocols_sorted() {
        let service = LspsService::builder()
            .with_protocol(MockProtocol(5))
            .with_protocol(MockProtocol(1))
            .with_protocol(MockProtocol(2))
            .build();

        assert_eq!(service.protocols(), &[1, 2, 5]);
    }

    #[test]
    fn test_protocols_deduped() {
        let service = LspsService::builder()
            .with_protocol(MockProtocol(2))
            .with_protocol(MockProtocol(2))
            .build();

        assert_eq!(service.protocols(), &[2]);
    }

    #[test]
    fn test_protocol_zero_filtered() {
        let service = LspsService::builder()
            .with_protocol(MockProtocol(0))
            .with_protocol(MockProtocol(2))
            .build();

        assert_eq!(service.protocols(), &[2]);
    }

    #[tokio::test]
    async fn test_list_protocols_returns_registered() {
        let service = LspsService::builder()
            .with_protocol(MockProtocol(2))
            .with_protocol(MockProtocol(1))
            .build();

        let request = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "lsps0.list_protocols",
            "params": {}
        }))
        .unwrap();

        let response = service.handle(&test_context(), &request).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&response).unwrap();

        assert_eq!(parsed["result"]["protocols"], serde_json::json!([1, 2]));
    }

    #[tokio::test]
    async fn test_list_protocols_empty() {
        let service = LspsService::builder().build();

        let request = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "lsps0.list_protocols",
            "params": {}
        }))
        .unwrap();

        let response = service.handle(&test_context(), &request).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&response).unwrap();

        assert_eq!(parsed["result"]["protocols"], serde_json::json!([]));
    }
}
