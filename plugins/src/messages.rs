use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
#[serde(rename_all = "snake_case")]
pub(crate) enum Request {
    // Builtin
    Getmanifest(GetManifestCall),
    Init(InitRequest),

    // Hooks
    PeerConnected,
    CommitmentRevocation,
    DbWrite,
    InvoicePayment,
    Openchannel,
    Openchannel2,
    Openchannel2Changed,
    Openchannel2Sign,
    RbfChannel,
    HtlcAccepted,
    RpcCommand,
    Custommsg,
    OnionMessage,
    OnionMessageBlinded,
    OnionMessageOurpath,

    // Bitcoin backend
    Getchaininfo,
    Estimatefees,
    Getrawblockbyheight,
    Getutxout,
    Sendrawtransaction,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
#[serde(rename_all = "snake_case")]
pub(crate) enum Notification {
    ChannelOpened,
    ChannelOpenFailed,
    ChannelStateChanged,
    Connect,
    Disconnect,
    InvoicePayment,
    InvoiceCreation,
    Warning,
    ForwardEvent,
    SendpaySuccess,
    SendpayFailure,
    CoinMovement,
    OpenchannelPeerSigs,
    Shutdown,
}

#[derive(Deserialize, Debug)]
pub struct GetManifestCall {}

#[derive(Deserialize, Debug)]
pub struct InitRequest {
    pub options: Value,
    pub configuration: HashMap<String, Value>,
}

#[derive(Debug)]
pub enum JsonRpc<N, R> {
    Request(usize, R),
    Notification(N),
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
            Some(id) => {
                let r = R::deserialize(v).map_err(de::Error::custom)?;
                Ok(JsonRpc::Request(id, r))
            }
            None => {
                let n = N::deserialize(v).map_err(de::Error::custom)?;
                Ok(JsonRpc::Notification(n))
            }
        }
    }
}
