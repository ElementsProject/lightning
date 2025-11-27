use crate::proto::jsonrpc::RpcError;
use crate::{jsonrpc::client::Result, proto::jsonrpc::JsonRpcResponse};
use async_trait::async_trait;
use log::{debug, trace};
use std::{collections::HashMap, sync::Arc};

/// Responsible for writing JSON-RPC responses back to clients.
///
/// This trait abstracts the mechanism for sending responses back to the client,
/// allowing handlers to remain transport-agnostic. Implementations of this
/// trait handle the actual transmission of response data over the underlying
/// transport.
#[async_trait]
pub trait JsonRpcResponseWriter: Send + 'static {
    /// Writes the provided payload as a response.
    async fn write(&mut self, payload: &[u8]) -> Result<()>;
}

/// Processes JSON-RPC requests and produces responses.
///
/// This trait defines the interface for handling specific JSON-RPC methods.
/// Each method supported by the server should have a corresponding handler
/// that implements this trait.
#[async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    /// Handles a JSON-RPC request.
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError>;
}

/// Builder for creating JSON-RPC servers.
pub struct JsonRpcServerBuilder {
    handlers: HashMap<String, Arc<dyn RequestHandler>>,
}

impl JsonRpcServerBuilder {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Registers a handler for a specific JSON-RPC method.
    pub fn with_handler(mut self, method: String, handler: Arc<dyn RequestHandler>) -> Self {
        self.handlers.insert(method, handler);
        self
    }

    /// Builds a JSON-RPC server with the configured handlers.
    pub fn build(self) -> JsonRpcServer {
        JsonRpcServer {
            handlers: Arc::new(self.handlers),
        }
    }
}

/// Server for handling JSON-RPC 2.0 requests.
///
/// Dispatches incoming JSON-RPC requests to the appropriate handlers based on
/// the method name, and manages the response lifecycle.
#[derive(Clone)]
pub struct JsonRpcServer {
    handlers: Arc<HashMap<String, Arc<dyn RequestHandler>>>,
}

impl JsonRpcServer {
    pub fn builder() -> JsonRpcServerBuilder {
        JsonRpcServerBuilder::new()
    }

    // Processes a JSON-RPC message and writes the response.
    ///
    /// This is the main entry point for handling JSON-RPC requests. It:
    /// 1. Parses and validates the incoming request
    /// 2. Routes the request to the appropriate handler
    /// 3. Writes the response back to the client (if needed)
    pub async fn handle_message(
        &self,
        payload: &[u8],
        writer: &mut dyn JsonRpcResponseWriter,
    ) -> Result<()> {
        trace!("Handle request with payload: {:?}", payload);
        let value: serde_json::Value = serde_json::from_slice(payload)?;
        let id = value.get("id").and_then(|id| id.as_str());
        let method = value.get("method").and_then(|method| method.as_str());
        let jsonrpc = value.get("jsonrpc").and_then(|jrpc| jrpc.as_str());

        trace!(
            "Validate request: id={:?}, method={:?}, jsonrpc={:?}",
            id,
            method,
            jsonrpc
        );
        let method = match (jsonrpc, method) {
            (Some(jrpc), Some(method)) if jrpc == "2.0" => method,
            (_, _) => {
                debug!("Got invalid request {}", value);
                let err = RpcError {
                    code: -32600,
                    message: "Invalid request".into(),
                    data: None,
                };
                return self.maybe_write_error(id, err, writer).await;
            }
        };

        trace!("Get handler for id={:?}, method={:?}", id, method);
        if let Some(handler) = self.handlers.get(method) {
            trace!(
                "Call handler for id={:?}, method={:?}, with payload={:?}",
                id,
                method,
                payload
            );
            match handler.handle(payload).await {
                Ok(res) => return self.maybe_write(id, &res, writer).await,
                Err(e) => {
                    debug!("Handler returned with error: {}", e);
                    return self.maybe_write_error(id, e, writer).await;
                }
            };
        } else {
            debug!("No handler found for method: {}", method);
            let err = RpcError {
                code: -32601,
                message: "Method not found".into(),
                data: None,
            };
            return self.maybe_write_error(id, err, writer).await;
        }
    }

    /// Writes a response if the request has an ID.
    ///
    /// For notifications (requests without an ID), no response is written.
    async fn maybe_write(
        &self,
        id: Option<&str>,
        payload: &[u8],
        writer: &mut dyn JsonRpcResponseWriter,
    ) -> Result<()> {
        // No need to respond when we don't have an id - it's a notification
        if id.is_some() {
            return writer.write(payload).await;
        }
        Ok(())
    }

    /// Writes an error response if the request has an ID.
    ///
    /// For notifications (requests without an ID), no response is written.
    async fn maybe_write_error(
        &self,
        id: Option<&str>,
        err: RpcError,
        writer: &mut dyn JsonRpcResponseWriter,
    ) -> Result<()> {
        // No need to respond when we don't have an id - it's a notification
        if let Some(id) = id {
            let err_res = JsonRpcResponse::error(err, id);
            let err_vec = serde_json::to_vec(&err_res)?;
            return writer.write(&err_vec).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_json_rpc_server {
    use super::*;

    #[derive(Default)]
    struct MockWriter {
        log_content: String,
    }

    #[async_trait]
    impl JsonRpcResponseWriter for MockWriter {
        async fn write(&mut self, payload: &[u8]) -> Result<()> {
            println!("Write payload={:?}", &payload);
            let byte_str = String::from_utf8(payload.to_vec()).unwrap();
            self.log_content = byte_str;
            Ok(())
        }
    }

    // Echo handler
    pub struct Echo;

    #[async_trait]
    impl RequestHandler for Echo {
        async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
            println!("Called handler with payload: {:?}", &payload);
            Ok(payload.to_vec())
        }
    }

    #[tokio::test]
    async fn test_notification() {
        // A notification should not respond to the client so there is no need
        // to write payload to the writer;
        let server = JsonRpcServer::builder()
            .with_handler("echo".to_string(), Arc::new(Echo))
            .build();

        let mut writer = MockWriter {
            log_content: String::default(),
        };

        let msg = r#"{"jsonrpc":"2.0","method":"echo","params":{"age":99,"name":"Satoshi"}}"#; // No id signals a notification.
        let res = server.handle_message(msg.as_bytes(), &mut writer).await;
        assert!(res.is_ok());
        assert!(writer.log_content.is_empty()); // Was a notification we don't expect a response;
    }

    #[tokio::test]
    async fn missing_method_field() {
        // We verify the request data, check that we return an error when we
        // don't understand the request.
        let server = JsonRpcServer::builder()
            .with_handler("echo".to_string(), Arc::new(Echo))
            .build();

        let mut writer = MockWriter {
            log_content: String::default(),
        };

        let msg = r#"{"jsonrpc":"2.0","params":{"age":99,"name":"Satoshi"},"id":"unique-id-123"}"#;
        let res = server.handle_message(msg.as_bytes(), &mut writer).await;
        assert!(res.is_ok());
        let expected = r#"{"jsonrpc":"2.0","id":"unique-id-123","error":{"code":-32600,"message":"Invalid request"}}"#; // Unknown method say_hello
        assert_eq!(writer.log_content, expected);
    }

    #[tokio::test]
    async fn wrong_version() {
        // We only accept requests that have jsonrpc version 2.0.
        let server = JsonRpcServer::builder()
            .with_handler("echo".to_string(), Arc::new(Echo))
            .build();

        let mut writer = MockWriter {
            log_content: String::default(),
        };

        let msg = r#"{"jsonrpc":"1.0","method":"echo","params":{"age":99,"name":"Satoshi"},"id":"unique-id-123"}"#;
        let res = server.handle_message(msg.as_bytes(), &mut writer).await;
        assert!(res.is_ok());
        let expected = r#"{"jsonrpc":"2.0","id":"unique-id-123","error":{"code":-32600,"message":"Invalid request"}}"#; // Unknown method say_hello
        assert_eq!(writer.log_content, expected);
    }

    #[tokio::test]
    async fn propper_request() {
        // Check that we call the handler and write back to the writer when
        // processing a well-formed request.
        let server = JsonRpcServer::builder()
            .with_handler("echo".to_string(), Arc::new(Echo))
            .build();

        let mut writer = MockWriter {
            log_content: String::default(),
        };

        let msg = r#"{"jsonrpc":"2.0","method":"echo","params":{"age":99,"name":"Satoshi"},"id":"unique-id-123"}"#;
        let res = server.handle_message(msg.as_bytes(), &mut writer).await;
        assert!(res.is_ok());
        assert_eq!(writer.log_content, msg.to_string());
    }

    #[tokio::test]
    async fn unknown_method() {
        // We don't know the method and need to send back an error to the client.
        let server = JsonRpcServer::builder()
            .with_handler("echo".to_string(), Arc::new(Echo))
            .build();

        let mut writer = MockWriter {
            log_content: String::default(),
        };

        let msg = r#"{"jsonrpc":"2.0","method":"say_hello","params":{"age":99,"name":"Satoshi"},"id":"unique-id-123"}"#; // Unknown method say_hello
        let res = server.handle_message(msg.as_bytes(), &mut writer).await;
        assert!(res.is_ok());
        let expected = r#"{"jsonrpc":"2.0","id":"unique-id-123","error":{"code":-32601,"message":"Method not found"}}"#; // Unknown method say_hello
        assert_eq!(writer.log_content, expected);
    }

    #[tokio::test]
    async fn test_handler() {
        let server = JsonRpcServer::builder()
            .with_handler("echo".to_string(), Arc::new(Echo))
            .build();

        let mut writer = MockWriter {
            log_content: String::default(),
        };

        let msg = r#"{"jsonrpc":"2.0","method":"echo","params":{"age":99,"name":"Satoshi"},"id":"unique-id-123"}"#;
        let res = server.handle_message(msg.as_bytes(), &mut writer).await;
        assert!(res.is_ok());
        assert_eq!(writer.log_content, msg.to_string());
    }
}
