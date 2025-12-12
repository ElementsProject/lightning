use crate::proto::jsonrpc::{JsonRpcResponse, RequestObject};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use core::fmt::Debug;
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::{oneshot, Mutex};

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
        peer_id: &PublicKey,
        request: &RequestObject<P>,
    ) -> Result<JsonRpcResponse<R>>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send;
}

#[async_trait]
pub trait MessageSender: Send + Sync + Clone + 'static {
    async fn send(&self, peer: &PublicKey, payload: &[u8]) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct PendingRequests {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<Vec<u8>>>>>,
}

impl PendingRequests {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, id: String) -> oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().await.insert(id, tx);
        rx
    }

    pub async fn complete(&self, id: &str, data: Vec<u8>) -> bool {
        if let Some(tx) = self.inner.lock().await.remove(id) {
            tx.send(data).is_ok()
        } else {
            false
        }
    }

    pub async fn remove(&self, id: &str) {
        self.inner.lock().await.remove(id);
    }
}

#[derive(Clone)]
pub struct MultiplexedTransport<S> {
    sender: S,
    pending: PendingRequests,
    timeout: Duration,
}

impl<S: MessageSender> MultiplexedTransport<S> {
    pub fn new(sender: S, pending: PendingRequests, timeout: Duration) -> Self {
        Self {
            sender,
            pending,
            timeout,
        }
    }

    pub fn pending(&self) -> &PendingRequests {
        &self.pending
    }

    pub fn sender(&self) -> &S {
        &self.sender
    }
}

#[async_trait]
impl<S: MessageSender> Transport for MultiplexedTransport<S> {
    async fn request<P, R>(
        &self,
        peer_id: &PublicKey,
        request: &RequestObject<P>,
    ) -> Result<JsonRpcResponse<R>>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let id = request.id.as_ref().ok_or(Error::MissingId)?;
        let payload = serde_json::to_vec(request)?;

        // Register pending before sending
        let rx = self.pending().insert(id.clone()).await;

        // Send via backend
        if let Err(e) = self.sender.send(peer_id, &payload).await {
            self.pending.remove(id).await;
            return Err(e);
        };

        let response_bytes = tokio::time::timeout(self.timeout, rx)
            .await
            .map_err(|_| {
                let pending = self.pending.clone();
                let id = id.clone();
                tokio::spawn(async move { pending.remove(&id).await });
                Error::Timeout
            })?
            .map_err(|_| Error::Internal("channel closed unexpectedly".into()))?;

        Ok(serde_json::from_slice(&response_bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_peer() -> PublicKey {
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            .parse()
            .unwrap()
    }

    // Mock sender that captures calls
    #[derive(Clone, Default)]
    struct MockSender {
        call_count: Arc<AtomicUsize>,
        should_fail: bool,
    }

    #[async_trait]
    impl MessageSender for MockSender {
        async fn send(&self, _peer: &PublicKey, _payload: &[u8]) -> Result<()> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(Error::Internal("mock failure".into()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_pending_requests_roundtrip() {
        let pending = PendingRequests::new();

        let rx = pending.insert("test-id".to_string()).await;

        // Simulate response arriving
        let completed = pending.complete("test-id", b"response".to_vec()).await;
        assert!(completed);

        let result = rx.await.unwrap();
        assert_eq!(result, b"response");
    }

    #[tokio::test]
    async fn test_pending_requests_unknown_id() {
        let pending = PendingRequests::new();

        let completed = pending.complete("unknown", b"data".to_vec()).await;
        assert!(!completed);
    }

    #[tokio::test]
    async fn test_pending_requests_remove() {
        let pending = PendingRequests::new();

        let _rx = pending.insert("test-id".to_string()).await;
        pending.remove("test-id").await;

        let completed = pending.complete("test-id", b"data".to_vec()).await;
        assert!(!completed);
    }

    #[tokio::test]
    async fn test_transport_sends_via_sender() {
        let sender = MockSender::default();
        let call_count = sender.call_count.clone();

        let pending = PendingRequests::new();
        let transport = MultiplexedTransport::new(sender, pending, Duration::from_secs(1));

        // Start request (will timeout since no response)
        let request = RequestObject {
            jsonrpc: "2.0".into(),
            method: "test".into(),
            params: Some(serde_json::json!({})),
            id: Some("1".into()),
        };

        let result: Result<JsonRpcResponse<serde_json::Value>> =
            transport.request(&test_peer(), &request).await;

        // Should have sent
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        // Should timeout (no response)
        assert!(matches!(result, Err(Error::Timeout)));
    }

    #[tokio::test]
    async fn test_transport_send_failure_cleans_up() {
        let sender = MockSender {
            should_fail: true,
            ..Default::default()
        };

        let pending = PendingRequests::new();
        let transport = MultiplexedTransport::new(sender, pending, Duration::from_secs(1));

        let request = RequestObject {
            jsonrpc: "2.0".into(),
            method: "test".into(),
            params: Some(serde_json::json!({})),
            id: Some("1".into()),
        };

        let result: Result<JsonRpcResponse<serde_json::Value>> =
            transport.request(&test_peer(), &request).await;

        assert!(matches!(result, Err(Error::Internal(_))));

        // Pending should be cleaned up
        let completed = transport.pending().complete("1", b"data".to_vec()).await;
        assert!(!completed);
    }

    #[tokio::test]
    async fn test_transport_missing_id() {
        let sender = MockSender::default();

        let pending = PendingRequests::new();
        let transport = MultiplexedTransport::new(sender, pending, Duration::from_secs(1));

        let request = RequestObject::<()> {
            jsonrpc: "2.0".into(),
            method: "test".into(),
            params: None,
            id: None, // Missing!
        };

        let result: Result<JsonRpcResponse<serde_json::Value>> =
            transport.request(&test_peer(), &request).await;

        assert!(matches!(result, Err(Error::MissingId)));
    }
}
