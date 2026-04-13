/// Verify serde round-trip: serialize to JSON, deserialize back, and
/// check the re-serialized value matches the first serialization.
macro_rules! assert_serde_roundtrip {
    ($value:expr, $type:ty) => {{
        let v = serde_json::to_value(&$value).unwrap();
        let rt: $type = serde_json::from_value(v.clone()).unwrap();
        let v2 = serde_json::to_value(&rt).unwrap();
        assert_eq!(v, v2);
    }};
}

use crate::{
    codec::JsonCodec,
    hooks::{actions::*, events::*},
    notifications::{BlockAddedNotification, CustomMsgNotification},
    primitives::{Amount, JsonObjectOrArray, JsonScalar},
    ClnRpc, Notification, RpcError,
};

use super::*;
use crate::model::*;
use crate::primitives::PublicKey;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::str::FromStr;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, FramedRead};

#[tokio::test]
async fn call_raw_request() {
    // Set up a pair of unix-streams
    // The frame is a mock rpc-server
    let (uds1, uds2) = UnixStream::pair().unwrap();
    let mut cln = ClnRpc::from_stream(uds1).unwrap();
    let mut frame = Framed::new(uds2, JsonCodec::default());

    // Define the request and response send in the RPC-message
    let rpc_request = serde_json::json!({
        "id" : 1,
        "jsonrpc" : "2.0",
        "params" : {},
        "method" : "some_method"
    });
    let rpc_request2 = rpc_request.clone();

    let rpc_response = serde_json::json!({
        "jsonrpc" : "2.0",
        "id" : "1",
        "result" : {"field_6" : 6}
    });

    // Spawn the task that performs the RPC-call
    // Check that it reads the response correctly
    let handle = tokio::task::spawn(async move { cln.call_raw_request(rpc_request2).await });

    // Verify that our emulated server received a request
    // and sendt the response
    let read_req = dbg!(frame.next().await.unwrap().unwrap());
    assert_eq!(&rpc_request, &read_req);
    frame.send(rpc_response).await.unwrap();

    // Get the result from `call_raw_request` and verify
    let actual_response: Result<serde_json::Value, RpcError> = handle.await.unwrap();
    let actual_response = actual_response.unwrap();
    assert_eq!(actual_response, json!({"field_6" : 6}));
}

#[tokio::test]
async fn call_raw() {
    let req = serde_json::json!({});
    let (uds1, uds2) = UnixStream::pair().unwrap();
    let mut cln = ClnRpc::from_stream(uds1).unwrap();

    let mut read = FramedRead::new(uds2, JsonCodec::default());
    tokio::task::spawn(async move {
        let _: serde_json::Value = cln.call_raw("getinfo", &req).await.unwrap();
    });

    let read_req = dbg!(read.next().await.unwrap().unwrap());

    assert_eq!(
        json!({"id": 1, "method": "getinfo", "params": {}, "jsonrpc": "2.0"}),
        read_req
    );
}

#[tokio::test]
async fn test_call_enum_remote_error() {
    // Set up the rpc-connection
    // The frame represents a Mock rpc-server
    let (uds1, uds2) = UnixStream::pair().unwrap();
    let mut cln = ClnRpc::from_stream(uds1).unwrap();
    let mut frame = Framed::new(uds2, JsonCodec::default());

    // Construct the request and response
    let req = Request::Ping(requests::PingRequest {
        id: PublicKey::from_str(
            "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
        )
        .unwrap(),
        len: None,
        pongbytes: None,
    });

    let mock_resp = json!({
        "id" : 1,
        "jsonrpc" : "2.0",
        "error" : {
            "code" : 666,
            "message" : "MOCK_ERROR"
        }
    });

    // Spawn the task which calls the rpc
    let handle = tokio::task::spawn(async move { cln.call(req).await });

    // Ensure the mock receives the request and returns a response
    let _ = dbg!(frame.next().await.unwrap().unwrap());
    frame.send(mock_resp).await.unwrap();

    let rpc_response: Result<_, RpcError> = handle.await.unwrap();
    let rpc_error: RpcError = rpc_response.unwrap_err();

    println!("RPC_ERROR : {:?}", rpc_error);
    assert_eq!(rpc_error.code.unwrap(), 666);
    assert_eq!(rpc_error.message, "MOCK_ERROR");
}

#[tokio::test]
async fn test_call_enum() {
    // Set up the rpc-connection
    // The frame represents a Mock rpc-server
    let (uds1, uds2) = UnixStream::pair().unwrap();
    let mut cln = ClnRpc::from_stream(uds1).unwrap();
    let mut frame = Framed::new(uds2, JsonCodec::default());

    // We'll use the Ping request here because both the request
    // and response have few arguments
    let req = Request::Ping(requests::PingRequest {
        id: PublicKey::from_str(
            "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
        )
        .unwrap(),
        len: None,
        pongbytes: None,
    });
    let mock_resp = json!({
        "id" : 1,
        "jsonrpc" : "2.0",
        "result" : { "totlen" : 123 }
    });

    // we create a task that sends the response and returns the response
    let handle = tokio::task::spawn(async move { cln.call(req).await });

    // Ensure our mock receives the request and sends the response
    let read_req = dbg!(frame.next().await.unwrap().unwrap());
    assert_eq!(
        read_req,
        json!({"id" : 1, "jsonrpc" : "2.0", "method" : "ping", "params" : {"id" : "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b"}})
    );
    frame.send(mock_resp).await.unwrap();

    // Verify that the error response is correct
    let rpc_response: Result<_, RpcError> = handle.await.unwrap();
    match rpc_response.unwrap() {
        Response::Ping(ping) => {
            assert_eq!(ping.totlen, 123);
        }
        _ => panic!("A Request::Getinfo should return Response::Getinfo"),
    }
}

#[tokio::test]
async fn test_call_typed() {
    // Set up the rpc-connection
    // The frame represents a Mock rpc-server
    let (uds1, uds2) = UnixStream::pair().unwrap();
    let mut cln = ClnRpc::from_stream(uds1).unwrap();
    let mut frame = Framed::new(uds2, JsonCodec::default());

    // We'll use the Ping request here because both the request
    // and response have few arguments
    let req = requests::PingRequest {
        id: PublicKey::from_str(
            "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
        )
        .unwrap(),
        len: None,
        pongbytes: None,
    };
    let mock_resp = json!({
        "id" : 1,
        "jsonrpc" : "2.0",
        "result" : { "totlen" : 123 }
    });

    // we create a task that sends the response and returns the response
    let handle = tokio::task::spawn(async move { cln.call_typed(&req).await });

    // Ensure our mock receives the request and sends the response
    _ = dbg!(frame.next().await.unwrap().unwrap());
    frame.send(mock_resp).await.unwrap();

    // Verify that the error response is correct
    let rpc_response: Result<_, RpcError> = handle.await.unwrap();
    let ping_response = rpc_response.unwrap();
    assert_eq!(ping_response.totlen, 123);
}

#[tokio::test]
async fn test_call_typed_remote_error() {
    // Create a dummy rpc-request
    let req = requests::GetinfoRequest {};

    // Create a dummy error response
    let response = json!({
    "id" : 1,
    "jsonrpc" : "2.0",
    "error" : {
        "code" : 666,
        "message" : "MOCK_ERROR",
    }});

    let (uds1, uds2) = UnixStream::pair().unwrap();
    let mut cln = ClnRpc::from_stream(uds1).unwrap();

    // Send out the request
    let mut frame = Framed::new(uds2, JsonCodec::default());

    let handle = tokio::task::spawn(async move { cln.call_typed(&req).await });

    // Dummy-server ensures the request has been received and send the error response
    let _ = dbg!(frame.next().await.unwrap().unwrap());
    frame.send(response).await.unwrap();

    let rpc_response = handle.await.unwrap();
    let rpc_error = rpc_response.expect_err("Must be an RPC-error response");

    assert_eq!(rpc_error.code.unwrap(), 666);
    assert_eq!(rpc_error.message, "MOCK_ERROR");
}

#[test]
fn serialize_custom_msg_notification() {
    let msg = CustomMsgNotification {
        peer_id: PublicKey::from_str(
            "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
        )
        .unwrap(),
        payload: String::from("941746573749"),
    };

    let notification = Notification::CustomMsg(msg);

    assert_eq!(
        serde_json::to_value(notification).unwrap(),
        serde_json::json!(
            {
                "custommsg" : {
                    "peer_id" : "0364aeb75519be29d1af7b8cc6232dbda9fdabb79b66e4e1f6a223750954db210b",
                    "payload" : "941746573749"
                }
            }
        )
    );
}

#[test]
fn serialize_block_added_notification() {
    let block_added = BlockAddedNotification {
        hash: crate::primitives::Sha256::from_str(
            "000000000000000000000acab8abe0c67a52ed7e5a90a19c64930ff11fa84eca",
        )
        .unwrap(),
        height: 830702,
    };

    let notification = Notification::BlockAdded(block_added);

    assert_eq!(
        serde_json::to_value(notification).unwrap(),
        serde_json::json!({
            "block_added" : {
                "hash" : "000000000000000000000acab8abe0c67a52ed7e5a90a19c64930ff11fa84eca",
                "height" : 830702
            }
        })
    )
}

#[test]
fn deserialize_connect_notification() {
    let connect_json = serde_json::json!({
        "connect" :  {
            "address" : {
                "address" : "127.0.0.1",
                "port" : 38012,
                "type" : "ipv4"
            },
            "direction" : "in",
            "id" : "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
        }
    });

    let _: Notification = serde_json::from_value(connect_json).unwrap();
}

#[test]
fn test_peer_connected_hook() {
    let peer_connected_payload = serde_json::json!({
          "peer": {
            "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
            "direction": "in",
            "addr": "34.239.230.56:9735",
            "features": ""

            }
    });
    let peer_connected: PeerConnectedEvent =
        serde_json::from_value(peer_connected_payload).unwrap();
    assert_eq!(
        peer_connected.peer.id,
        PublicKey::from_str("03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f")
            .unwrap()
    );
    assert_eq!(peer_connected.peer.addr, "34.239.230.56:9735");
    assert_eq!(
        peer_connected.peer.direction,
        PeerConnectedPeerDirection::IN
    );
    assert_eq!(peer_connected.peer.features, "");
    assert_serde_roundtrip!(peer_connected, PeerConnectedEvent);
}

#[test]
fn test_recover_hook() {
    let r = serde_json::json!(
        {
            "codex32": "cl10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqjdsjnzedu43ns"
    });
    let d: RecoverHookEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.codex32,
        "cl10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqjdsjnzedu43ns"
    );
    assert_serde_roundtrip!(d, RecoverHookEvent);
}

#[test]
fn test_commitment_revocation_hook() {
    let r = serde_json::json!({
        "commitment_txid": "58eea2cf538cfed79f4d6b809b920b40bb6b35962c4bb4cc81f5550a7728ab05",
        "penalty_tx": "02000000000101...ac00000000",
        "channel_id": "fb16398de93e8690c665873715ef590c038dfac5dd6c49a9d4b61dccfcedc2fb",
        "commitnum": 21
    });
    let d: CommitmentRevocationEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.commitment_txid,
        "58eea2cf538cfed79f4d6b809b920b40bb6b35962c4bb4cc81f5550a7728ab05"
    );
    assert_eq!(d.penalty_tx, "02000000000101...ac00000000");
    assert_eq!(
        d.channel_id.to_string(),
        "fb16398de93e8690c665873715ef590c038dfac5dd6c49a9d4b61dccfcedc2fb"
    );
    assert_eq!(d.commitnum, 21);
    assert_serde_roundtrip!(d, CommitmentRevocationEvent);
}

#[test]
fn test_db_write_hook() {
    let r = serde_json::json!({
      "data_version": 42,
      "writes": [
        "PRAGMA foreign_keys = ON"
      ]
    });
    let d: DbWriteEvent = serde_json::from_value(r).unwrap();
    assert_eq!(d.data_version, 42);
    assert_eq!(d.writes, vec!["PRAGMA foreign_keys = ON"]);
    assert_serde_roundtrip!(d, DbWriteEvent);
}

#[test]
fn test_invoice_payment_hook() {
    let r = serde_json::json!({
      "payment": {
        "label": "unique-label-for-invoice",
        "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
        "msat": 10000
      }
    });
    let d: InvoicePaymentHookEvent = serde_json::from_value(r).unwrap();
    assert_eq!(d.payment.label, "unique-label-for-invoice");
    assert_eq!(
        hex::encode(d.payment.preimage.to_vec()),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(d.payment.msat, Amount::from_msat(10000));
    assert_serde_roundtrip!(d, InvoicePaymentHookEvent);
}

#[test]
fn test_openchannel_hook() {
    let r = serde_json::json!({
      "openchannel": {
        "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
        "funding_msat": 100000000,
        "push_msat": 0,
        "dust_limit_msat": 546000,
        "max_htlc_value_in_flight_msat": 18446744073709551615u64,
        "channel_reserve_msat": 1000000,
        "htlc_minimum_msat": 0,
        "feerate_per_kw": 7500,
        "to_self_delay": 5,
        "max_accepted_htlcs": 483,
        "channel_flags": 1
      }
    });
    let d: OpenchannelEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.openchannel.id.to_string(),
        "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f"
    );
    assert_eq!(d.openchannel.funding_msat, Amount::from_msat(100000000));
    assert_eq!(d.openchannel.push_msat, Amount::from_msat(0));
    assert_eq!(d.openchannel.dust_limit_msat, Amount::from_msat(546000));
    assert_eq!(
        d.openchannel.max_htlc_value_in_flight_msat,
        Amount::from_msat(18446744073709551615)
    );
    assert_eq!(
        d.openchannel.channel_reserve_msat,
        Amount::from_msat(1000000)
    );
    assert_eq!(d.openchannel.htlc_minimum_msat, Amount::from_msat(0));
    assert_eq!(d.openchannel.feerate_per_kw, 7500);
    assert_eq!(d.openchannel.to_self_delay, 5);
    assert_eq!(d.openchannel.max_accepted_htlcs, 483);
    assert_eq!(d.openchannel.channel_flags, 1);
    assert_serde_roundtrip!(d, OpenchannelEvent);
}

#[test]
fn test_openchannel2_hook() {
    let r = serde_json::json!({
        "openchannel2": {
      "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
      "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
      "their_funding_msat": 100000000,
      "dust_limit_msat": 546000,
      "max_htlc_value_in_flight_msat": 18446744073709551615u64,
      "htlc_minimum_msat": 0,
      "funding_feerate_per_kw": 7500,
      "commitment_feerate_per_kw": 7500,
      "feerate_our_max": 10000,
      "feerate_our_min": 253,
      "to_self_delay": 5,
      "max_accepted_htlcs": 483,
      "channel_flags": 1,
      "channel_type": {"bits": [12, 22], "names": ["static_remotekey/even", "anchors/even"]},
      "locktime": 2453,
      "channel_max_msat": 16777215000u64,
      "requested_lease_msat": 100000000,
      "lease_blockheight_start": 683990,
      "node_blockheight": 683990,
      "require_confirmed_inputs": true
    }
      });
    let d: Openchannel2Event = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.openchannel2.id.to_string(),
        "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f"
    );
    assert_eq!(
        d.openchannel2.channel_id.to_string(),
        "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7"
    );
    assert_eq!(
        d.openchannel2.their_funding_msat,
        Amount::from_msat(100000000)
    );
    assert_eq!(d.openchannel2.dust_limit_msat, Amount::from_msat(546000));
    assert_eq!(
        d.openchannel2.max_htlc_value_in_flight_msat,
        Amount::from_msat(18446744073709551615)
    );
    assert_eq!(d.openchannel2.htlc_minimum_msat, Amount::from_msat(0));
    assert_eq!(d.openchannel2.funding_feerate_per_kw, 7500);
    assert_eq!(d.openchannel2.commitment_feerate_per_kw, 7500);
    assert_eq!(d.openchannel2.feerate_our_max, 10000);
    assert_eq!(d.openchannel2.feerate_our_min, 253);
    assert_eq!(d.openchannel2.to_self_delay, 5);
    assert_eq!(d.openchannel2.max_accepted_htlcs, 483);
    assert_eq!(d.openchannel2.channel_flags, 1);
    assert_eq!(
        d.openchannel2.channel_type.as_ref().unwrap().bits,
        vec![12, 22]
    );
    assert_eq!(
        d.openchannel2.channel_type.as_ref().unwrap().names,
        vec!["static_remotekey/even", "anchors/even"]
    );
    assert_eq!(d.openchannel2.locktime, 2453);
    assert_eq!(
        d.openchannel2.channel_max_msat,
        Amount::from_msat(16777215000)
    );
    assert_eq!(
        d.openchannel2.requested_lease_msat.as_ref().unwrap(),
        &Amount::from_msat(100000000)
    );
    assert_eq!(
        *d.openchannel2.lease_blockheight_start.as_ref().unwrap(),
        683990
    );
    assert_eq!(*d.openchannel2.node_blockheight.as_ref().unwrap(), 683990);
    assert!(d.openchannel2.require_confirmed_inputs);
    assert_serde_roundtrip!(d, Openchannel2Event);
}

#[test]
fn test_openchannel2_changed_hook() {
    let r = serde_json::json!({
        "openchannel2_changed": {
            "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
            "psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr...",
            "require_confirmed_inputs": false
        }
    });
    let d: Openchannel2ChangedEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.openchannel2_changed.channel_id.to_string(),
        "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7"
    );
    assert_eq!(
        d.openchannel2_changed.psbt,
        "cHNidP8BADMCAAAAAQ+yBipSVZr..."
    );
    assert!(!d.openchannel2_changed.require_confirmed_inputs);
    assert_serde_roundtrip!(d, Openchannel2ChangedEvent);
}

#[test]
fn test_openchannel2_sign_hook() {
    let r = serde_json::json!({
        "openchannel2_sign": {
            "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
            "psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
        }
    });
    let d: Openchannel2SignEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.openchannel2_sign.channel_id.to_string(),
        "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7"
    );
    assert_eq!(d.openchannel2_sign.psbt, "cHNidP8BADMCAAAAAQ+yBipSVZr...");
    assert_serde_roundtrip!(d, Openchannel2SignEvent);
}

#[test]
fn test_rbf_channel_hook() {
    let r = serde_json::json!({
      "rbf_channel": {
        "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
        "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
        "their_last_funding_msat": 100000000,
        "their_funding_msat": 100000000,
        "our_last_funding_msat": 100000000,
        "funding_feerate_per_kw": 7500,
        "feerate_our_max": 10000,
        "feerate_our_min": 253,
        "channel_max_msat": 16777215000u64,
        "locktime": 2453,
        "requested_lease_msat": 100000000,
        "require_confirmed_inputs": true
      }
    });
    let d: RbfChannelEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.rbf_channel.id.to_string(),
        "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f"
    );
    assert_eq!(
        d.rbf_channel.channel_id.to_string(),
        "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7"
    );
    assert_eq!(
        d.rbf_channel.their_last_funding_msat,
        Amount::from_msat(100000000)
    );
    assert_eq!(
        d.rbf_channel.their_funding_msat,
        Amount::from_msat(100000000)
    );
    assert_eq!(
        d.rbf_channel.our_last_funding_msat,
        Amount::from_msat(100000000)
    );
    assert_eq!(d.rbf_channel.funding_feerate_per_kw, 7500);
    assert_eq!(d.rbf_channel.feerate_our_max, 10000);
    assert_eq!(d.rbf_channel.feerate_our_min, 253);
    assert_eq!(
        d.rbf_channel.channel_max_msat,
        Amount::from_msat(16777215000)
    );
    assert_eq!(d.rbf_channel.locktime, 2453);
    assert_eq!(
        d.rbf_channel.requested_lease_msat.unwrap(),
        Amount::from_msat(100000000)
    );
    assert!(d.rbf_channel.require_confirmed_inputs);
    assert_serde_roundtrip!(d, RbfChannelEvent);
}

#[test]
fn test_htlc_accepted_hook() {
    let r = serde_json::json!({
      "peer_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
      "onion": {
        "payload": "",
        "short_channel_id": "1x2x3",
        "forward_msat": 42,
        "outgoing_cltv_value": 500014,
        "shared_secret": "0000000000000000000000000000000000000000000000000000000000000000",
        "next_onion": "[1365bytes of serialized onion]"
      },
      "htlc": {
        "short_channel_id": "4x5x6",
        "id": 27,
        "amount_msat": 43,
        "cltv_expiry": 500028,
        "cltv_expiry_relative": 10,
        "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "extra_tlvs": "fdffff012afe00010001020539"
      },
      "forward_to": "0000000000000000000000000000000000000000000000000000000000000000"
    });
    let d: HtlcAcceptedEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.peer_id.unwrap().to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );

    assert_eq!(d.onion.payload, "");
    assert_eq!(d.onion.short_channel_id.unwrap().to_string(), "1x2x3");
    assert_eq!(d.onion.forward_msat.unwrap(), Amount::from_msat(42));
    assert_eq!(d.onion.outgoing_cltv_value.unwrap(), 500014);
    assert_eq!(
        hex::encode(d.onion.shared_secret.to_vec()),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(d.onion.next_onion, "[1365bytes of serialized onion]");

    assert_eq!(d.htlc.short_channel_id.to_string(), "4x5x6");
    assert_eq!(d.htlc.id, 27);
    assert_eq!(d.htlc.amount_msat, Amount::from_msat(43));
    assert_eq!(d.htlc.cltv_expiry, 500028);
    assert_eq!(d.htlc.cltv_expiry_relative, 10);
    assert_eq!(
        d.htlc.payment_hash.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        d.htlc.extra_tlvs.as_ref().unwrap(),
        "fdffff012afe00010001020539"
    );

    assert_eq!(
        d.forward_to.unwrap().to_string(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_serde_roundtrip!(d, HtlcAcceptedEvent);
}

#[test]
fn test_rpc_command_hook() {
    let r = serde_json::json!({
        "rpc_command": {
            "id": "3",
            "method": "method_name",
            "params": {
                "param_1": [],
                "param_2": {},
                "param_n": "",
            }
        }
    });
    let d: RpcCommandEvent = serde_json::from_value(r).unwrap();
    match &d.rpc_command.id {
        JsonScalar::String(s) => assert_eq!(s, "3"),
        _ => panic!("should be string"),
    }
    assert_eq!(d.rpc_command.method, "method_name");

    let mut params = serde_json::Map::new();
    params.insert("param_1".to_string(), serde_json::Value::Array(vec![]));
    params.insert(
        "param_2".to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    params.insert(
        "param_n".to_string(),
        serde_json::Value::String("".to_string()),
    );
    assert_eq!(
        d.rpc_command.params,
        JsonObjectOrArray::Object(params.clone())
    );
    assert_serde_roundtrip!(d, RpcCommandEvent);

    let q = serde_json::json!({
        "replace": {
            "jsonrpc": "2.0",
            "id": "3",
            "method": "method_name",
            "params": {
                "param_1": [],
                "param_2": {},
                "param_n": "",
            }
        }
    });
    let e: RpcCommandAction = serde_json::from_value(q).unwrap();
    match &e.replace.as_ref().unwrap().id {
        JsonScalar::String(s) => assert_eq!(s, "3"),
        _ => panic!("should be string"),
    }
    assert_eq!(e.replace.as_ref().unwrap().method, "method_name");
    assert_eq!(
        e.replace.as_ref().unwrap().params,
        JsonObjectOrArray::Object(params)
    );
    assert_serde_roundtrip!(e, RpcCommandAction);

    let r = serde_json::json!({
        "rpc_command": {
            "id": 3,
            "method": "method_name",
            "params": {
                "param_1": [],
                "param_2": {},
                "param_n": "",
            }
        }
    });
    let d: RpcCommandEvent = serde_json::from_value(r).unwrap();
    match &d.rpc_command.id {
        JsonScalar::Number(number) => assert_eq!(number.as_u64().unwrap(), 3),
        _ => panic!("should be number"),
    }
    assert_eq!(d.rpc_command.method, "method_name");

    let mut params = serde_json::Map::new();
    params.insert("param_1".to_string(), serde_json::Value::Array(vec![]));
    params.insert(
        "param_2".to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    params.insert(
        "param_n".to_string(),
        serde_json::Value::String("".to_string()),
    );
    assert_eq!(
        d.rpc_command.params,
        JsonObjectOrArray::Object(params.clone())
    );
    assert_serde_roundtrip!(d, RpcCommandEvent);

    let q = serde_json::json!({
        "replace": {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "method_name",
            "params": {
                "param_1": [],
                "param_2": {},
                "param_n": "",
            }
        }
    });
    let e: RpcCommandAction = serde_json::from_value(q).unwrap();
    match &e.replace.as_ref().unwrap().id {
        JsonScalar::Number(number) => assert_eq!(number.as_u64().unwrap(), 3),
        _ => panic!("should be number"),
    }
    assert_eq!(e.replace.as_ref().unwrap().method, "method_name");
    assert_eq!(
        e.replace.as_ref().unwrap().params,
        JsonObjectOrArray::Object(params)
    );
    assert_serde_roundtrip!(e, RpcCommandAction);
}

#[test]
fn test_custommsg_hook() {
    let r = serde_json::json!({
        "peer_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
        "payload": "1337ffffffff"
    });
    let d: CustommsgHookEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.peer_id.to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(d.payload, "1337ffffffff");
    assert_serde_roundtrip!(d, CustommsgHookEvent);
}

#[test]
fn test_onionmessage_recv() {
    let r = serde_json::json!({
      "onion_message": {
        "reply_blindedpath": {
          "first_node_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
          "first_scid": "100x200x300",
          "first_scid_dir": 1,
          "first_path_key": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
          "hops": [
            {
              "blinded_node_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
              "encrypted_recipient_data": "0a020d0da"
            }
          ]
        },
        "invoice_request": "0a020d0db",
        "invoice": "0a020d0dc",
        "invoice_error": "0a020d0dd",
        "unknown_fields": [
          {
            "number": 12345,
            "value": "0a020d0de"
          }
        ]
      }
    });
    let d: OnionMessageRecvEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_node_id
            .as_ref()
            .unwrap()
            .to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_scid
            .as_ref()
            .unwrap()
            .to_string(),
        "100x200x300"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_scid_dir
            .as_ref()
            .unwrap(),
        &1
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_path_key
            .as_ref()
            .unwrap()
            .to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .hops
            .as_ref()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .hops
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .blinded_node_id
            .to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .hops
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .encrypted_recipient_data,
        "0a020d0da"
    );
    assert_eq!(
        d.onion_message.invoice_request.as_ref().unwrap(),
        "0a020d0db"
    );
    assert_eq!(d.onion_message.invoice.as_ref().unwrap(), "0a020d0dc");
    assert_eq!(d.onion_message.invoice_error.as_ref().unwrap(), "0a020d0dd");
    assert_eq!(d.onion_message.unknown_fields.as_ref().unwrap().len(), 1);
    assert_eq!(
        d.onion_message
            .unknown_fields
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .number,
        12345
    );
    assert_eq!(
        d.onion_message
            .unknown_fields
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .value,
        "0a020d0de"
    );
    assert_serde_roundtrip!(d, OnionMessageRecvEvent);
}

#[test]
fn test_onionmessage_recv_secret() {
    let r = serde_json::json!({
      "onion_message": {
        "pathsecret": "0000000000000000000000000000000000000000000000000000000000000000",
        "reply_blindedpath": {
          "first_node_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
          "first_scid": "100x200x300",
          "first_scid_dir": 1,
          "first_path_key": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
          "hops": [
            {
              "blinded_node_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
              "encrypted_recipient_data": "0a020d0da"
            }
          ]
        },
        "invoice_request": "0a020d0db",
        "invoice": "0a020d0dc",
        "invoice_error": "0a020d0dd",
        "unknown_fields": [
          {
            "number": 12345,
            "value": "0a020d0de"
          }
        ]
      }
    });
    let d: OnionMessageRecvSecretEvent = serde_json::from_value(r).unwrap();
    assert_eq!(
        hex::encode(d.onion_message.pathsecret.to_vec()),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_node_id
            .as_ref()
            .unwrap()
            .to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_scid
            .as_ref()
            .unwrap()
            .to_string(),
        "100x200x300"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_scid_dir
            .as_ref()
            .unwrap(),
        &1
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .first_path_key
            .as_ref()
            .unwrap()
            .to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .hops
            .as_ref()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .hops
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .blinded_node_id
            .to_string(),
        "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f"
    );
    assert_eq!(
        d.onion_message
            .reply_blindedpath
            .as_ref()
            .unwrap()
            .hops
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .encrypted_recipient_data,
        "0a020d0da"
    );
    assert_eq!(
        d.onion_message.invoice_request.as_ref().unwrap(),
        "0a020d0db"
    );
    assert_eq!(d.onion_message.invoice.as_ref().unwrap(), "0a020d0dc");
    assert_eq!(d.onion_message.invoice_error.as_ref().unwrap(), "0a020d0dd");
    assert_eq!(d.onion_message.unknown_fields.as_ref().unwrap().len(), 1);
    assert_eq!(
        d.onion_message
            .unknown_fields
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .number,
        12345
    );
    assert_eq!(
        d.onion_message
            .unknown_fields
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .value,
        "0a020d0de"
    );
    assert_serde_roundtrip!(d, OnionMessageRecvSecretEvent);
}
