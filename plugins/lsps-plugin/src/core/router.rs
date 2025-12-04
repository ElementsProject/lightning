use crate::proto::jsonrpc::{RpcError, RpcErrorExt};
use bitcoin::secp256k1::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{collections::HashMap, future::Future, pin::Pin};

pub type BoxedHandler = Box<
    dyn Fn(
            &RequestContext,
            &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, RpcError>> + Send>>
        + Send
        + Sync,
>;

/// Convenience macro to register a handler at the JsonRpcRouterBuilder.
#[macro_export]
macro_rules! register_handler {
    ($builder:expr, $handler:expr, $method:literal, $fn:ident) => {{
        let h = $handler.clone();
        $crate::core::router::JsonRpcRouterBuilder::register($builder, $method, move |p| {
            let h = h.clone();
            async move { h.$fn(p).await }
        });
    }};

    // With context (peer_id)
    ($builder:expr, $handler:expr, $method:literal, $fn:ident, with_peer) => {{
        let h = $handler.clone();
        $crate::core::router::JsonRpcRouterBuilder::register_with_context(
            $builder,
            $method,
            move |ctx, p| {
                let h = h.clone();
                async move { h.$fn(ctx.peer_id, p).await }
            },
        );
    }};
}

#[derive(Clone)]
pub struct RequestContext {
    pub peer_id: PublicKey,
}

/// Builder for a generic JSON-RPC 2.0 router
pub struct JsonRpcRouterBuilder {
    handlers: HashMap<&'static str, BoxedHandler>,
}

impl JsonRpcRouterBuilder {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn register<P, R, F, Fut>(&mut self, method: &'static str, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = Result<R, RpcError>> + Send + 'static,
    {
        let boxed: BoxedHandler = Box::new(move |_ctx, params: &[u8]| {
            let handler = handler.clone();
            let params: Result<P, _> = serde_json::from_slice(params);
            Box::pin(async move {
                let params = params.map_err(|e| RpcError::invalid_params(e))?;
                let result = handler(params).await?;
                serde_json::to_value(&result).map_err(|_| RpcError::internal_error("parsing error"))
            })
        });
        self.handlers.insert(method, boxed);
    }

    pub fn register_with_context<P, R, F, Fut>(&mut self, method: &'static str, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + Send + 'static,
        F: Fn(RequestContext, P) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = Result<R, RpcError>> + Send + 'static,
    {
        let boxed: BoxedHandler = Box::new(move |ctx: &RequestContext, params: &[u8]| {
            let handler = handler.clone();
            let ctx = ctx.clone();
            let params: Result<P, _> = serde_json::from_slice(params);
            Box::pin(async move {
                let params = params.map_err(|e| RpcError::invalid_params(e))?;
                let result = handler(ctx, params).await?;
                serde_json::to_value(&result).map_err(|_| RpcError::internal_error("parsing error"))
            })
        });
        self.handlers.insert(method, boxed);
    }

    pub fn build(self) -> JsonRpcRouter {
        JsonRpcRouter {
            handlers: self.handlers,
        }
    }
}

/// Generic JSON-RPC 2.0 router
pub struct JsonRpcRouter {
    handlers: HashMap<&'static str, BoxedHandler>,
}

impl JsonRpcRouter {
    pub async fn handle(&self, ctx: &RequestContext, request: &[u8]) -> Option<Vec<u8>> {
        #[derive(Deserialize)]
        struct BorrowedRequest<'a> {
            jsonrpc: &'a str,
            method: &'a str,
            #[serde(borrow)]
            id: Option<&'a str>,
            #[serde(borrow)]
            params: Option<&'a RawValue>,
        }

        let req: BorrowedRequest<'_> = match serde_json::from_slice(request) {
            Ok(req) => req,
            Err(_) => {
                return Some(error_response(
                    None,
                    RpcError::parse_error("failed to parse request"),
                ))
            }
        };

        if req.jsonrpc != "2.0" {
            return Some(error_response(req.id, RpcError::invalid_request("")));
        }

        let handler = match self.handlers.get(req.method) {
            Some(h) => h,
            None => return Some(error_response(req.id, RpcError::method_not_found(""))),
        };

        // Notification -> no response
        let id = match req.id {
            Some(id) => id,
            None => return None,
        };

        let param_bytes = match req.params {
            Some(raw) => raw.get().as_bytes(),
            None => b"{}",
        };

        Some(match handler(ctx, param_bytes).await {
            Ok(r) => success_response(id, r),
            Err(e) => error_response(Some(id), e),
        })
    }

    pub fn methods(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }
}

fn success_response(id: &str, result: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
    .unwrap()
}

fn error_response(id: Option<&str>, error: RpcError) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message,
            "data": error.data
        }
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::jsonrpc::{INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR};
    use serde::{Deserialize, Serialize};
    use serde_json::{self, json};

    // Simple types for testing
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct AddParams {
        a: i32,
        b: i32,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct AddResult {
        sum: i32,
    }

    fn test_peer_id() -> PublicKey {
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            .parse()
            .unwrap()
    }

    fn test_context() -> RequestContext {
        RequestContext {
            peer_id: test_peer_id(),
        }
    }

    #[tokio::test]
    async fn dispatches_to_registered_handler_and_returns_success() {
        let mut builder = JsonRpcRouterBuilder::new();
        builder.register("add", |p: AddParams| async move {
            Ok(AddResult { sum: p.a + p.b })
        });

        let router = builder.build();

        let req = json!({
            "jsonrpc": "2.0",
            "method": "add",
            "id": "1",
            "params": { "a": 1, "b": 2 },
        });

        let req_bytes = serde_json::to_vec(&req).unwrap();

        let resp_bytes = router
            .handle(&test_context(), &req_bytes)
            .await
            .expect("should not be a notification");

        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], "1");
        assert_eq!(resp["result"]["sum"], 3);
        assert!(resp.get("error").is_none());
    }

    #[tokio::test]
    async fn returns_none_for_notification() {
        let mut builder = JsonRpcRouterBuilder::new();
        builder.register("add", |p: AddParams| async move {
            Ok(AddResult { sum: p.a + p.b })
        });

        let router = builder.build();

        // No `id` → notification
        let req = json!({
            "jsonrpc": "2.0",
            "method": "add",
            "params": { "a": 10, "b": 20 },
        });

        let req_bytes = serde_json::to_vec(&req).unwrap();
        let resp = router.handle(&test_context(), &req_bytes).await;

        assert!(resp.is_none(), "notifications must not produce a response");
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let builder = JsonRpcRouterBuilder::new();
        let router = builder.build();

        let req = json!({
            "jsonrpc": "2.0",
            "method": "does.not.exist",
            "id": "42",
            "params": {},
        });

        let req_bytes = serde_json::to_vec(&req).unwrap();
        let resp_bytes = router
            .handle(&test_context(), &req_bytes)
            .await
            .expect("not a notification");

        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], "42");
        assert_eq!(resp["error"]["code"], METHOD_NOT_FOUND);
        assert!(resp.get("result").is_none());
    }

    #[tokio::test]
    async fn invalid_json_returns_parse_error_with_null_id() {
        let builder = JsonRpcRouterBuilder::new();
        let router = builder.build();

        // Not valid JSON at all
        let resp_bytes = router
            .handle(&test_context(), b"this is not json")
            .await
            .expect("parse error still produces a response");

        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], serde_json::Value::Null);
        assert_eq!(resp["error"]["code"], PARSE_ERROR);
    }

    #[tokio::test]
    async fn wrong_jsonrpc_version_returns_invalid_request() {
        let builder = JsonRpcRouterBuilder::new();
        let router = builder.build();

        let req = json!({
            "jsonrpc": "1.0", // wrong
            "method": "add",
            "id": "1",
            "params": {},
        });

        let req_bytes = serde_json::to_vec(&req).unwrap();
        let resp_bytes = router
            .handle(&test_context(), &req_bytes)
            .await
            .expect("not a notification");

        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert_eq!(resp["error"]["code"], INVALID_REQUEST);
        assert_eq!(resp["id"], "1");
    }

    #[tokio::test]
    async fn bad_params_return_invalid_params_error() {
        let mut builder = JsonRpcRouterBuilder::new();
        builder.register("add", |p: AddParams| async move {
            Ok(AddResult { sum: p.a + p.b })
        });

        let router = builder.build();

        // `params` is a string, but handler expects AddParams → serde should fail → invalid_params
        let req = json!({
            "jsonrpc": "2.0",
            "method": "add",
            "id": "1",
            "params": "not an object",
        });

        let req_bytes = serde_json::to_vec(&req).unwrap();
        let resp_bytes = router
            .handle(&test_context(), &req_bytes)
            .await
            .expect("not a notification");

        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();

        assert_eq!(resp["error"]["code"], INVALID_PARAMS);
        assert_eq!(resp["id"], "1");
        assert!(resp.get("result").is_none());
    }

    #[test]
    fn methods_returns_registered_method_names() {
        let mut builder = JsonRpcRouterBuilder::new();

        builder.register("add", |p: AddParams| async move {
            Ok(AddResult { sum: p.a + p.b })
        });

        builder.register("sub", |p: AddParams| async move {
            Ok(AddResult { sum: p.a - p.b })
        });

        let router = builder.build();

        let mut methods = router.methods();
        methods.sort();

        assert_eq!(methods, vec!["add", "sub"]);
    }
}
