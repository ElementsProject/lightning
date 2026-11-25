//! Common structs to handle JSON-RPC decoding and encoding. They are
//! generic over the Notification and Request types.

use serde::de::{self, Deserializer};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;

#[derive(Debug)]
pub enum JsonRpc<N, R> {
    Request(serde_json::Value, R),
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
        let v = Value::deserialize(deserializer)?;
        let id = v
            .as_object()
            .ok_or_else(|| de::Error::custom("expected a JSON-RPC object"))?
            .get("id")
            .cloned();
        match id {
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

impl<N, R> Serialize for JsonRpc<N, R>
where
    N: Serialize + Debug,
    R: Serialize + Debug,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            JsonRpc::Notification(r) => {
                let r = serde_json::to_value(r).map_err(serde::ser::Error::custom)?;
                let mut s = serializer.serialize_struct("Notification", 3)?;
                s.serialize_field("jsonrpc", "2.0")?;
                s.serialize_field("method", &r["method"])?;
                s.serialize_field("params", &r["params"])?;
                s.end()
            }
            JsonRpc::Request(id, r) => {
                let r = serde_json::to_value(r).map_err(serde::ser::Error::custom)?;
                let mut s = serializer.serialize_struct("Request", 4)?;
                s.serialize_field("jsonrpc", "2.0")?;
                s.serialize_field("id", id)?;
                s.serialize_field("method", &r["method"])?;
                s.serialize_field("params", &r["params"])?;
                s.end()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jsonrpc_null_id_is_request_not_notification() {
        let req_null_id = json!({"jsonrpc": "2.0", "id": null, "method": "ping", "params": {}});
        let parsed: JsonRpc<Value, Value> = serde_json::from_value(req_null_id).unwrap();
        match parsed {
            JsonRpc::Request(id, _) => assert_eq!(id, Value::Null),
            JsonRpc::Notification(_) => panic!("expected Request for null id, got Notification"),
        }

        let notif = json!({"jsonrpc": "2.0", "method": "connect", "params": {}});
        let parsed: JsonRpc<Value, Value> = serde_json::from_value(notif).unwrap();
        assert!(matches!(parsed, JsonRpc::Notification(_)));

        assert!(serde_json::from_value::<JsonRpc<Value, Value>>(json!(42)).is_err());
    }

    #[test]
    fn test_jsonrpc_serialize_propagates_error() {
        #[derive(Debug)]
        struct FailingSerialize;
        impl Serialize for FailingSerialize {
            fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("cannot serialize"))
            }
        }

        let notif: JsonRpc<FailingSerialize, ()> = JsonRpc::Notification(FailingSerialize);
        assert!(serde_json::to_string(&notif).is_err());

        let req: JsonRpc<(), FailingSerialize> = JsonRpc::Request(json!(1), FailingSerialize);
        assert!(serde_json::to_string(&req).is_err());
    }
}
