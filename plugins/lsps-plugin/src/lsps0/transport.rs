use crate::{
    core::transport::{Error, Transport},
    proto::lsps0::LSPS0_MESSAGE_TYPE,
};
use async_trait::async_trait;
use cln_plugin::Plugin;
use cln_rpc::{primitives::PublicKey, ClnRpc};
use log::{debug, error, trace};
use serde::{de::Visitor, Deserialize, Serialize};
use std::{
    array::TryFromSliceError,
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Weak},
};
use tokio::{
    sync::{mpsc, RwLock},
    time::Duration,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Trait that must be implemented by plugin state to access the custom message hook manager.
///
/// This trait allows the hook handler to access the custom message hook manager
/// from the plugin state, enabling proper message routing.
pub trait WithCustomMessageHookManager {
    fn get_custommsg_hook_manager(&self) -> &CustomMessageHookManager;
}

// Manages subscriptions for the custom message hook.
///
/// The `CustomMessageHookManager` is responsible for:
/// 1. Maintaining a registry of message ID to receiver mappings
/// 2. Processing incoming LSPS0 messages and routing them to subscribers
/// 3. Cleaning up expired subscriptions
///
/// It uses weak references to avoid memory leaks when timeouts occ
#[derive(Clone)]
pub struct CustomMessageHookManager {
    /// Maps message IDs to weak references of response channels
    subs: Arc<RwLock<HashMap<String, Weak<mpsc::Sender<CustomMsg>>>>>,
}

impl CustomMessageHookManager {
    /// Creates a new CustomMessageHookManager.
    pub fn new() -> Self {
        Self {
            subs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribes to receive a message with a specific ID.
    ///
    /// Registers a weak reference to a channel that will receive the message
    /// when it arrives. Using weak references allows for automatic cleanup if
    /// the receiver is dropped due to timeout.
    async fn subscribe_hook_once<I: Into<String>>(
        &self,
        id: I,
        channel: Weak<mpsc::Sender<CustomMsg>>,
    ) {
        let id = id.into();
        trace!("Subscribe to custom message hook for message id={}", id);
        let mut sub_lock = self.subs.write().await;
        sub_lock.insert(id, channel);
    }

    /// Processes an incoming LSP message.
    ///
    /// Extracts the message ID from the payload, finds the corresponding
    /// subscriber, and forwards the message to them if found.
    async fn process_lsp_message(&self, payload: CustomMsg, peer_id: &str) -> bool {
        // Convert the binary payload to a string
        let lsps_msg_string = match String::from_utf8(payload.payload.clone()) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to deserialize custommsg payload from {peer_id}: {e}");
                return false;
            }
        };

        let id = match extract_message_id(&lsps_msg_string) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to get id from lsps message from {peer_id}: {e}");
                return false;
            }
        };

        let mut subs_lock = self.subs.write().await;
        // Clean up any expired subscriptions
        subs_lock.retain(|_, v| Weak::strong_count(v) > 0);
        subs_lock.shrink_to_fit();

        // Find send to, and remove the subscriber for this message ID
        if let Some(tx) = subs_lock.remove(&id).map(|v| v.upgrade()).flatten() {
            if let Err(e) = tx.send(payload).await {
                error!("Failed to send custommsg to subscriber for id={}: {e}", id);
                return false;
            }
            return true;
        }

        debug!(
            "No subscriber found for message with id={} from {peer_id}",
            id
        );
        false
    }

    /// Handles the custommsg hook from Core Lightning.
    ///
    /// This method should be registered as a hook handler in a Core Lightning
    /// plugin. It processes incoming custom messages and routes LSPS0 messages
    /// to the appropriate subscribers.
    pub async fn on_custommsg<S>(
        p: Plugin<S>,
        v: serde_json::Value,
    ) -> Result<serde_json::Value, anyhow::Error>
    where
        S: Clone + Sync + Send + 'static + WithCustomMessageHookManager,
    {
        // Default response is to continue processing.
        let continue_response = Ok(serde_json::json!({
          "result": "continue"
        }));

        // Parse the custom message hook return value.
        let custommsg: CustomMsgHookReturn = match serde_json::from_value(v) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to deserialize custommsg: {e}");
                return continue_response;
            }
        };

        // Only process LSPS0 message types.
        if custommsg.payload.message_type != LSPS0_MESSAGE_TYPE {
            debug!(
                "Custommsg is not of type LSPS0 (got {}), skipping",
                custommsg.payload.message_type
            );
            return continue_response;
        }

        // Route the message to the appropriate handler.
        // Can be moved into a separate task via tokio::spawn if needed;
        let hook_watcher = p.state().get_custommsg_hook_manager();
        hook_watcher
            .process_lsp_message(custommsg.payload, &custommsg.peer_id)
            .await;
        return continue_response;
    }
}

/// Transport implementation for JSON-RPC over Lightning Network using BOLT8
/// and BOLT1 custom messages.
///
/// The `Bolt8Transport` allows JSON-RPC requests to be transmitted as custom
/// messages between Lightning Network nodes. It uses Core Lightning's
/// `sendcustommsg` RPC call to send messages and the `custommsg` hook to
/// receive responses.
#[derive(Clone)]
pub struct Bolt8Transport {
    /// The node ID of the destination node.
    endpoint: cln_rpc::primitives::PublicKey,
    /// Path to the Core Lightning RPC socket.
    rpc_path: PathBuf,
    /// Timeout for requests.
    request_timeout: Duration,
    /// Hook manager for routing messages.
    hook_watcher: CustomMessageHookManager,
}

impl Bolt8Transport {
    /// Creates a new Bolt8Transport.
    ///
    /// # Arguments
    /// * `endpoint` - Node ID of the destination node as a hex string
    /// * `rpc_path` - Path to the Core Lightning socket
    /// * `hook_watcher` - Hook manager to use for message routing
    /// * `timeout` - Optional timeout for requests (defaults to DEFAULT_TIMEOUT)
    ///
    /// # Returns
    /// A new `Bolt8Transport` instance or an error if the node ID is invalid
    pub fn new(
        endpoint: &str,
        rpc_path: PathBuf,
        hook_watcher: CustomMessageHookManager,
        timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        let endpoint = cln_rpc::primitives::PublicKey::from_str(endpoint)
            .map_err(|e| Error::Internal(e.to_string()))?;
        let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
        Ok(Self {
            endpoint,
            rpc_path,
            request_timeout: timeout,
            hook_watcher,
        })
    }

    /// Connects to the Core Lightning node.
    async fn connect_to_node(&self) -> Result<ClnRpc, Error> {
        ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Error::Internal(e.to_string()))
    }

    /// Sends a custom message to the destination node.
    async fn send_custom_msg(&self, client: &mut ClnRpc, payload: Vec<u8>) -> Result<(), Error> {
        send_custommsg(client, payload, self.endpoint).await
    }

    /// Waits for a response with timeout.
    async fn wait_for_response(
        &self,
        mut rx: mpsc::Receiver<CustomMsg>,
    ) -> Result<CustomMsg, Error> {
        tokio::time::timeout(self.request_timeout, rx.recv())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or(Error::Internal(String::from("Channel unexpectedly closed")))
    }
}

/// Sends a custom message to the destination node.
pub async fn send_custommsg(
    client: &mut ClnRpc,
    payload: Vec<u8>,
    peer: PublicKey,
) -> Result<(), Error> {
    let msg = CustomMsg {
        message_type: LSPS0_MESSAGE_TYPE,
        payload,
    };

    let request = cln_rpc::model::requests::SendcustommsgRequest {
        msg: msg.to_string(),
        node_id: peer,
    };

    client
        .call_typed(&request)
        .await
        .map_err(|e| Error::Internal(format!("Failed to send custom msg: {e}")))
        .map(|r| {
            trace!("Successfully queued custom msg: {}", r.status);
            ()
        })
}

#[async_trait]
impl Transport for Bolt8Transport {
    /// Sends a JSON-RPC request and waits for a response.
    async fn send(
        &self,
        _peer_id: &PublicKey,
        request: String,
    ) -> core::result::Result<String, Error> {
        let id = extract_message_id(&request)?;
        let mut client = self.connect_to_node().await?;

        let (tx, rx) = mpsc::channel(1);
        trace!(
            "Subscribing to custom msg hook manager for request id={}",
            id
        );

        // Create a strong reference that will be dropped after timeout.
        let tx_arc = Arc::new(tx);

        self.hook_watcher
            .subscribe_hook_once(id, Arc::downgrade(&tx_arc))
            .await;
        self.send_custom_msg(&mut client, request.into_bytes())
            .await?;

        let res = self.wait_for_response(rx).await?;

        if res.message_type != LSPS0_MESSAGE_TYPE {
            return Err(Error::Internal(format!(
                "unexpected response message type: expected {}, got {}",
                LSPS0_MESSAGE_TYPE, res.message_type
            )));
        }

        core::str::from_utf8(&res.payload)
            .map_err(|e| {
                Error::Internal(format!(
                    "failed to decode msg payload {:?}: {}",
                    res.payload, e
                ))
            })
            .map(|s| s.into())
    }

    /// Sends a notification without waiting for a response.
    async fn notify(
        &self,
        _peer_id: &PublicKey,
        request: String,
    ) -> core::result::Result<(), Error> {
        let mut client = self.connect_to_node().await?;
        self.send_custom_msg(&mut client, request.into_bytes())
            .await
    }
}

// Extracts the message ID from a JSON-RPC message.
fn extract_message_id(msg: &str) -> core::result::Result<String, serde_json::Error> {
    let id_only: IdOnly = serde_json::from_str(msg)?;
    Ok(id_only.id)
}

/// Represents a custom message with type and payload.
#[derive(Clone, Debug, PartialEq)]
pub struct CustomMsg {
    pub message_type: u16,
    pub payload: Vec<u8>,
}

impl core::fmt::Display for CustomMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = Vec::with_capacity(2 + self.payload.len());
        bytes.extend_from_slice(&self.message_type.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        write!(f, "{}", hex::encode(bytes))
    }
}

impl FromStr for CustomMsg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| Error::Internal(e.to_string()))?;

        if bytes.len() < 2 {
            return Err(Error::Internal(
                "hex string too short to contain a valid message_type".to_string(),
            ));
        }

        let message_type_bytes: [u8; 2] = bytes[..2]
            .try_into()
            .map_err(|e: TryFromSliceError| Error::Internal(e.to_string()))?;
        let message_type = u16::from_be_bytes(message_type_bytes);
        let payload = bytes[2..].to_owned();
        Ok(CustomMsg {
            message_type,
            payload,
        })
    }
}

impl Serialize for CustomMsg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Visitor for deserializing CustomMsg from strings.
struct CustomMsgVisitor;

impl<'de> Visitor<'de> for CustomMsgVisitor {
    type Value = CustomMsg;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a hex string representing a CustomMsg")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        CustomMsg::from_str(v).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for CustomMsg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CustomMsgVisitor)
    }
}

/// Struct to extract just the ID from a JSON-RPC message.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct IdOnly {
    id: String,
}

/// Return type from custommsg hook.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CustomMsgHookReturn {
    peer_id: String,
    payload: CustomMsg,
}

#[cfg(test)]
mod test_transport {
    use super::*;
    use serde_json::json;

    // Helper to create a test JSON-RPC request
    fn create_test_request(id: &str) -> String {
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "test_method",
            "params": {"test": "value"},
            "id": id
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn test_deserialize_custommsg() {
        let hex_str = r#"94197b226a736f6e727063223a22322e30222c226d6574686f64223a226c737073302e6c6973745f70726f746f636f6c73222c22706172616d73223a7b7d2c226964223a226135633665613536366333383038313936346263227d"#;
        let msg = CustomMsg::from_str(hex_str).unwrap();
        assert_eq!(msg.message_type, LSPS0_MESSAGE_TYPE);
    }

    #[tokio::test]
    async fn test_extract_message_id() {
        // Test with string ID
        let request = create_test_request("test-id-123");
        let id = extract_message_id(&request).unwrap();
        assert_eq!(id, "test-id-123");
    }

    #[tokio::test]
    async fn custom_msg_serialization() {
        let original = CustomMsg {
            message_type: 0x1234,
            payload: b"test payload".to_vec(),
        };

        // Test to_string and parsing from that string
        let serialized = original.to_string();

        // Convert hex to bytes
        let bytes = hex::decode(&serialized).unwrap();

        // Verify structure
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);
        assert_eq!(&bytes[2..], b"test payload");

        // Test deserialization
        let deserialized: CustomMsg =
            serde_json::from_str(&serde_json::to_string(&serialized).unwrap()).unwrap();

        assert_eq!(deserialized.message_type, original.message_type);
        assert_eq!(deserialized.payload, original.payload);
    }

    #[tokio::test]
    async fn hook_manager_subscribe_and_process() {
        let hook_manager = CustomMessageHookManager::new();

        // Create test message
        let test_id = "test-id-456";
        let test_request = create_test_request(test_id);
        let test_msg = CustomMsg {
            message_type: LSPS0_MESSAGE_TYPE,
            payload: test_request.as_bytes().to_vec(),
        };

        // Set up a subscription
        let (tx, mut rx) = mpsc::channel(1);
        let tx_arc = Arc::new(tx);
        hook_manager
            .subscribe_hook_once(test_id, Arc::downgrade(&tx_arc))
            .await;

        // Process the message
        let processed = hook_manager
            .process_lsp_message(test_msg.clone(), "peer123")
            .await;
        assert!(processed);

        // Verify the received message
        let received_msg = rx.recv().await.unwrap();
        assert_eq!(received_msg.message_type, LSPS0_MESSAGE_TYPE);
        assert_eq!(received_msg.payload, test_request.as_bytes());
    }

    #[tokio::test]
    async fn hook_manager_no_subscriber() {
        let hook_manager = CustomMessageHookManager::new();

        // Create test message with ID that has no subscriber
        let test_request = create_test_request("unknown-id");
        let test_msg = CustomMsg {
            message_type: LSPS0_MESSAGE_TYPE,
            payload: test_request.as_bytes().to_vec(),
        };

        // Process the message
        let processed = hook_manager.process_lsp_message(test_msg, "peer123").await;
        assert!(!processed);
    }

    #[tokio::test]
    async fn hook_manager_clean_up_after_timeout() {
        let hook_manager = CustomMessageHookManager::new();

        // Create test message
        let test_id = "test-id-456";
        let test_request = create_test_request(test_id);
        let test_msg = CustomMsg {
            message_type: LSPS0_MESSAGE_TYPE,
            payload: test_request.as_bytes().to_vec(),
        };

        // Set up a subscription
        let (tx, _rx) = mpsc::channel(1);
        let tx_arc = Arc::new(tx);
        hook_manager
            .subscribe_hook_once(test_id, Arc::downgrade(&tx_arc))
            .await;

        // drop the reference pointer here to simulate a timeout.
        drop(tx_arc);

        // Should not process as the reference has been dropped.
        let processed = hook_manager
            .process_lsp_message(test_msg.clone(), "peer123")
            .await;
        assert!(!processed);
        assert!(hook_manager.subs.read().await.is_empty());
    }
}
