use crate::options::ConfigOption;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
#[serde(rename_all = "snake_case")]
pub(crate) enum Request {
    // Builtin
    Getmanifest(GetManifestCall),
    Init(InitCall),
    // Hooks
    //     PeerConnected,
    //     CommitmentRevocation,
    //     DbWrite,
    //     InvoicePayment,
    //     Openchannel,
    //     Openchannel2,
    //     Openchannel2Changed,
    //     Openchannel2Sign,
    //     RbfChannel,
    //     HtlcAccepted,
    //     RpcCommand,
    //     Custommsg,
    //     OnionMessage,
    //     OnionMessageBlinded,
    //     OnionMessageOurpath,

    // Bitcoin backend
    //     Getchaininfo,
    //     Estimatefees,
    //     Getrawblockbyheight,
    //     Getutxout,
    //     Sendrawtransaction,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
#[serde(rename_all = "snake_case")]
pub(crate) enum Notification {
    //     ChannelOpened,
    //     ChannelOpenFailed,
    //     ChannelStateChanged,
    //     Connect,
    //     Disconnect,
    //     InvoicePayment,
    //     InvoiceCreation,
    //     Warning,
    //     ForwardEvent,
    //     SendpaySuccess,
    //     SendpayFailure,
    //     CoinMovement,
    //     OpenchannelPeerSigs,
    //     Shutdown,
}

#[derive(Deserialize, Debug)]
pub(crate) struct GetManifestCall {}

#[derive(Deserialize, Debug)]
pub(crate) struct InitCall {
    pub(crate) options: HashMap<String, Value>,
    pub configuration: Configuration,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Configuration {
    #[serde(rename = "lightning-dir")]
    pub lightning_dir: String,
    #[serde(rename = "rpc-file")]
    pub rpc_file: String,
    pub startup: bool,
    pub network: String,
    pub feature_set: HashMap<String, String>,

    // The proxy related options are only populated if a proxy was
    // configured.
    pub proxy: Option<ProxyInfo>,
    #[serde(rename = "torv3-enabled")]
    pub torv3_enabled: Option<bool>,
    pub always_use_proxy: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyInfo {
    #[serde(alias = "type")]
    pub typ: String,
    pub address: String,
    pub port: i64,
}

#[derive(Debug)]
pub(crate) enum JsonRpc<N, R> {
    Request(serde_json::Value, R),
    Notification(N),
    CustomRequest(serde_json::Value, Value),
    CustomNotification(Value),
}

/// This function disentangles the various cases:
///
///   1) If we have an `id` then it is a request
///
///   2) Otherwise it's a notification that doesn't require a
///   response.
///
/// Furthermore we distinguish between the built-in types and the
/// custom user notifications/methods:
///
///   1) We either match a built-in type above,
///
///   2) Or it's a custom one, so we pass it around just as a
///   `serde_json::Value`
impl<'de, N, R> Deserialize<'de> for JsonRpc<N, R>
where
    N: Deserialize<'de> + Debug,
    R: Deserialize<'de> + Debug,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        struct IdHelper {
            id: Option<serde_json::Value>,
        }

        let v = Value::deserialize(deserializer)?;
        let helper = IdHelper::deserialize(&v).map_err(de::Error::custom)?;
        match helper.id {
            Some(id) => match R::deserialize(v.clone()) {
                Ok(r) => Ok(JsonRpc::Request(id, r)),
                Err(_) => Ok(JsonRpc::CustomRequest(id, v)),
            },
            None => match N::deserialize(v.clone()) {
                Ok(n) => Ok(JsonRpc::Notification(n)),
                Err(_) => Ok(JsonRpc::CustomNotification(v)),
            },
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub(crate) struct RpcMethod {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) usage: String,
}

#[derive(Serialize, Default, Debug, Clone)]
pub struct NotificationTopic {
    pub method: String,
}

impl NotificationTopic {
    pub fn method(&self) -> &str {
        &self.method
    }
}

impl NotificationTopic {
    pub fn new(method: &str) -> Self {
        Self {
            method: method.to_string(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub(crate) struct GetManifestResponse {
    pub(crate) options: Vec<ConfigOption>,
    pub(crate) rpcmethods: Vec<RpcMethod>,
    pub(crate) subscriptions: Vec<String>,
    pub(crate) notifications: Vec<NotificationTopic>,
    pub(crate) hooks: Vec<String>,
    pub(crate) dynamic: bool,
    pub(crate) nonnumericids: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) custommessages : Vec<u16>
}

#[derive(Serialize, Default, Debug)]
pub struct InitResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<String>,
}

pub trait Response: Serialize + Debug {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::messages;
    use serde_json::json;

    #[test]
    fn test_init_message_parsing() {
        let value = json!({
            "jsonrpc": "2.0",
            "method": "init",
            "params": {
                "options": {
                    "greeting": "World",
                    "number": [0]
                },
                "configuration": {
                    "lightning-dir": "/home/user/.lightning/testnet",
                    "rpc-file": "lightning-rpc",
                    "startup": true,
                    "network": "testnet",
                    "feature_set": {
                        "init": "02aaa2",
                        "node": "8000000002aaa2",
                        "channel": "",
                        "invoice": "028200"
                    },
                    "proxy": {
                        "type": "ipv4",
                        "address": "127.0.0.1",
                        "port": 9050
                    },
                    "torv3-enabled": true,
                    "always_use_proxy": false
                }
            },
            "id": "10",
        });
        let req: JsonRpc<Notification, Request> = serde_json::from_value(value).unwrap();
        match req {
            messages::JsonRpc::Request(_, messages::Request::Init(init)) => {
                assert_eq!(init.options["greeting"], "World");
                assert_eq!(
                    init.configuration.lightning_dir,
                    String::from("/home/user/.lightning/testnet")
                );
            }
            _ => panic!("Couldn't parse init message"),
        }
    }
}
