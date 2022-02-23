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
pub struct GetManifestCall {}

#[derive(Deserialize, Debug)]
pub(crate) struct InitCall {
    pub(crate) options: HashMap<String, Value>,
}

#[derive(Debug)]
pub enum JsonRpc<N, R> {
    Request(usize, R),
    Notification(N),
    CustomRequest(usize, Value),
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
            id: Option<usize>,
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

#[derive(Serialize, Default, Debug)]
pub(crate) struct GetManifestResponse {
    pub(crate) options: Vec<ConfigOption>,
    pub(crate) rpcmethods: Vec<RpcMethod>,
    pub(crate) subscriptions: Vec<String>,
    pub(crate) hooks: Vec<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct InitResponse {}

pub trait Response: Serialize + Debug {}
