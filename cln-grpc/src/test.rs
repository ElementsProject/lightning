use crate::pb::*;
use serde_json::json;

#[test]
fn test_listpeers() {
    let j: serde_json::Value = json!({
      "peers": [
        {
          "id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
          "connected": true,
          "netaddr": [
            "127.0.0.1:39152"
          ],
          "features": "8808226aa2",
          "num_channels": 0,
          "channels": [
            {
              "state": "CHANNELD_NORMAL",
              "scratch_txid": "fd4659658d235c20c81f96f7bc867c17abbfd20fcdd46c27eaad74ea52eaee90",
              "last_tx_fee_msat": "14257000msat",
              "feerate": {
                "perkw": 11000,
                "perkb": 44000
              },
              "owner": "channeld",
              "short_channel_id": "103x2x1",
              "direction": 0,
              "channel_id": "44b77a6d66ca54f0c365c84b13a95fbde462415a0549228baa25ee1bb1dfef66",
              "funding_txid": "67efdfb11bee25aa8b2249055a4162e4bd5fa9134bc865c3f054ca666d7ab744",
              "funding_outnum": 1,
              "close_to_addr": "bcrt1q9tc6q49l6wrrtp8ul45rj92hsleehwwxty32zu",
              "close_to": "00142af1a054bfd3863584fcfd6839155787f39bb9c6",
              "private": false,
              "opener": "remote",
              "features": [
                "option_static_remotekey",
                "option_anchor_outputs"
              ],
              "funding": {
                "local_msat": "0msat",
                "remote_msat": "1000000000msat",
                "pushed_msat": "0msat",
                "local_funds_msat": "0msat",
                "remote_funds_msat": "0msat"
              },
              "msatoshi_to_us": 0,
              "to_us_msat": "0msat",
              "msatoshi_to_us_min": 0,
              "min_to_us_msat": "0msat",
              "msatoshi_to_us_max": 0,
              "max_to_us_msat": "0msat",
              "msatoshi_total": 1000000000,
              "total_msat": "1000000000msat",
              "fee_base_msat": "1msat",
              "fee_proportional_millionths": 10,
              "dust_limit_satoshis": 546,
              "dust_limit_msat": "546000msat",
              "max_total_htlc_in_msat": "18446744073709551615msat",
              "their_channel_reserve_satoshis": 10000,
              "their_reserve_msat": "10000000msat",
              "our_channel_reserve_satoshis": 10000,
              "our_reserve_msat": "10000000msat",
              "spendable_msatoshi": 0,
              "spendable_msat": "0msat",
              "receivable_msatoshi": 853257998,
              "receivable_msat": "853257998msat",
              "htlc_minimum_msat": 0,
              "minimum_htlc_in_msat": "0msat",
              "their_to_self_delay": 5,
              "our_to_self_delay": 5,
              "max_accepted_htlcs": 483,
              "state_changes": [
                {
                  "timestamp": "2022-03-25T13:57:33.322Z",
                  "old_state": "CHANNELD_AWAITING_LOCKIN",
                  "new_state": "CHANNELD_NORMAL",
                  "cause": "remote",
                  "message": "Lockin complete"
                }
              ],
              "status": [
                "CHANNELD_NORMAL:Funding transaction locked. Channel announced."
              ],
              "in_payments_offered": 1,
              "in_msatoshi_offered": 100002002,
              "in_offered_msat": "100002002msat",
              "in_payments_fulfilled": 0,
              "in_msatoshi_fulfilled": 0,
              "in_fulfilled_msat": "0msat",
              "out_payments_offered": 0,
              "out_msatoshi_offered": 0,
              "out_offered_msat": "0msat",
              "out_payments_fulfilled": 0,
              "out_msatoshi_fulfilled": 0,
              "out_fulfilled_msat": "0msat",
              "htlcs": [
                {
                  "direction": "in",
                  "id": 0,
                  "msatoshi": 100002002,
                  "amount_msat": "100002002msat",
                  "expiry": 131,
                  "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
                  "state": "RCVD_ADD_ACK_REVOCATION"
                }
              ]
            }
          ]
        },
        {
          "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
          "connected": true,
          "netaddr": [
            "127.0.0.1:38321"
          ],
          "features": "8808226aa2",
          "num_channels": 0,
          "channels": [
            {
              "state": "CHANNELD_NORMAL",
              "scratch_txid": "30530d3f522862773100b7600d8ea8921a5ee84df17a2317326f9aa2c4829326",
              "last_tx_fee_msat": "16149000msat",
              "feerate": {
                "perkw": 11000,
                "perkb": 44000
              },
              "owner": "channeld",
              "short_channel_id": "103x1x0",
              "direction": 0,
              "channel_id": "006a2044fc72fa5c4a54c9fddbf208970a7b3b4fd2aaa70a96abba757c01769e",
              "funding_txid": "9e76017c75baab960aa7aad24f3b7b0a9708f2dbfdc9544a5cfa72fc44206a00",
              "funding_outnum": 0,
              "close_to_addr": "bcrt1qhfmyce4ujce2pyugew2435tlwft6p6w4s3py6d",
              "close_to": "0014ba764c66bc9632a09388cb9558d17f7257a0e9d5",
              "private": false,
              "opener": "local",
              "features": [
                "option_static_remotekey",
                "option_anchor_outputs"
              ],
              "funding": {
                "local_msat": "1000000000msat",
                "remote_msat": "0msat",
                "pushed_msat": "0msat",
                "local_funds_msat": "0msat",
                "remote_funds_msat": "0msat"
              },
              "msatoshi_to_us": 1000000000,
              "to_us_msat": "1000000000msat",
              "msatoshi_to_us_min": 1000000000,
              "min_to_us_msat": "1000000000msat",
              "msatoshi_to_us_max": 1000000000,
              "max_to_us_msat": "1000000000msat",
              "msatoshi_total": 1000000000,
              "total_msat": "1000000000msat",
              "fee_base_msat": "1msat",
              "fee_proportional_millionths": 10,
              "dust_limit_satoshis": 546,
              "dust_limit_msat": "546000msat",
              "max_total_htlc_in_msat": "18446744073709551615msat",
              "their_channel_reserve_satoshis": 10000,
              "their_reserve_msat": "10000000msat",
              "our_channel_reserve_satoshis": 10000,
              "our_reserve_msat": "10000000msat",
              "spendable_msatoshi": 749473998,
              "spendable_msat": "749473998msat",
              "receivable_msatoshi": 0,
              "receivable_msat": "0msat",
              "htlc_minimum_msat": 0,
              "minimum_htlc_in_msat": "0msat",
              "their_to_self_delay": 5,
              "our_to_self_delay": 5,
              "max_accepted_htlcs": 483,
              "state_changes": [
                {
                  "timestamp": "2022-03-25T13:57:33.325Z",
                  "old_state": "CHANNELD_AWAITING_LOCKIN",
                  "new_state": "CHANNELD_NORMAL",
                  "cause": "user",
                  "message": "Lockin complete"
                }
              ],
              "status": [
                "CHANNELD_NORMAL:Funding transaction locked. Channel announced."
              ],
              "in_payments_offered": 0,
              "in_msatoshi_offered": 0,
              "in_offered_msat": "0msat",
              "in_payments_fulfilled": 0,
              "in_msatoshi_fulfilled": 0,
              "in_fulfilled_msat": "0msat",
              "out_payments_offered": 2,
              "out_msatoshi_offered": 200002002,
              "out_offered_msat": "200002002msat",
              "out_payments_fulfilled": 0,
              "out_msatoshi_fulfilled": 0,
              "out_fulfilled_msat": "0msat",
              "htlcs": [
                {
                  "direction": "out",
                  "id": 1,
                  "msatoshi": 100001001,
                  "amount_msat": "100001001msat",
                  "expiry": 125,
                  "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
                  "state": "SENT_ADD_ACK_REVOCATION"
                },
                {
                  "direction": "out",
                  "id": 0,
                  "msatoshi": 100001001,
                  "amount_msat": "100001001msat",
                  "expiry": 124,
                  "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
                  "state": "SENT_ADD_ACK_REVOCATION"
                }
              ]
            }
          ]
        }
      ]
    });
    let u: cln_rpc::model::responses::ListpeersResponse =
        serde_json::from_value(j.clone()).unwrap();
    let _l: cln_rpc::model::responses::ListpeersResponse = u.into();
    //let u2: cln_rpc::model::ListpeersResponse = l.into();
    //let j2 = serde_json::to_value(u2).unwrap();
    println!("{}", j);
    //println!("{}", j2);
    // assert_eq!(j, j2); // TODO, still some differences to fix
}

#[test]
fn test_getinfo() {
    let j = json!({
	    "id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
	    "alias": "JUNIORBEAM-2-509-ged26651-modded",
	    "color": "0266e4",
	    "num_peers": 1,
	    "num_pending_channels": 0,
	    "num_active_channels": 1,
	    "num_inactive_channels": 0,
	    "address": [],
	    "binding": [{"type": "ipv4", "address": "127.0.0.1", "port": 34143}],
	    "version": "v0.10.2-509-ged26651-modded",
	    "blockheight": 103,
	    "network": "regtest",
	    "fees_collected_msat": "0msat", "lightning-dir": "/tmp/ltests-20irp76f/test_pay_variants_1/lightning-1/regtest",
	    "our_features": {"init": "8808226aa2", "node": "80008808226aa2", "channel": "", "invoice": "024200"}});
    let u: cln_rpc::model::responses::GetinfoResponse = serde_json::from_value(j.clone()).unwrap();
    let _g: GetinfoResponse = u.into();
    //let u2: cln_rpc::model::GetinfoResponse = g.into();
    //let j2 = serde_json::to_value(u2).unwrap();
    //assert_eq!(j, j2);
}

#[test]
fn test_keysend() {
    let g =
        KeysendRequest {
            destination: hex::decode(
                "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
            )
            .unwrap(),
            amount_msat: Some(Amount { msat: 10000 }),

            label: Some("hello".to_string()),
            exemptfee: None,
            maxdelay: None,
            retry_for: None,
            maxfeepercent: None,
            routehints: Some(RoutehintList {
                hints: vec![Routehint {
                    hops: vec![RouteHop {
                    id: hex::decode(
                        "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
                    )
                    .unwrap(),
                    scid: "12345x678x90".to_string(),
                    feebase: Some(Amount { msat: 123 }),
                    feeprop: 1234,
                    expirydelta: 9,
                },RouteHop {
                    id: hex::decode(
                        "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
                    )
                    .unwrap(),
                    scid: "12345x678x90".to_string(),
                    feebase: Some(Amount { msat: 123 }),
                    feeprop: 1234,
                    expirydelta: 9,
                }],
                }],
            }),
            extratlvs: None,
            maxfee: None,
        };

    let u: cln_rpc::model::requests::KeysendRequest = g.into();
    let _ser = serde_json::to_string(&u);

    let j = r#"{
	"destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
	"payment_hash": "e74b03a98453dcb5a7ed5406b97ec3566dde4be85ef71685110f4c0ebc600592",
	"created_at": 1648222556.498,
	"parts": 1,
	"msatoshi": 10000,
	"amount_msat": "10000msat",
	"msatoshi_sent": 10001,
	"amount_sent_msat": "10001msat",
	"payment_preimage": "e56c22b9ed85560b021e1577daad5742502d25c0c2f636b817f5c0c7580a66a8",
	"status": "complete"
    }"#;
    let u: cln_rpc::model::responses::KeysendResponse = serde_json::from_str(j).unwrap();
    let g: KeysendResponse = u.clone().into();
    println!("{:?}", g);

    let v: serde_json::Value = serde_json::to_value(u.clone()).unwrap();
    let g: cln_rpc::model::responses::KeysendResponse = u.into();
    let v2 = serde_json::to_value(g).unwrap();
    assert_eq!(v, v2);
}

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

#[test]
fn test_balance_snapshot() {
    let j: serde_json::Value = json!({
        "node_id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "blockheight": 103,
        "timestamp": 1648222556,
        "accounts": [
            {
                "account_id": "wallet",
                "balance_msat": "500000000msat",
                "coin_type": "bcrt"
            },
            {
                "account_id": "44b77a6d66ca54f0c365c84b13a95fbde462415a0549228baa25ee1bb1dfef66",
                "balance_msat": "1000000000msat",
                "coin_type": "bcrt"
            }
        ]
    });
    let u: cln_rpc::notifications::BalanceSnapshotNotification = serde_json::from_value(j).unwrap();
    assert_eq!(u.accounts.len(), 2);
    assert_eq!(u.accounts[0].account_id, "wallet");
    assert_eq!(u.blockheight, 103);
    assert_serde_roundtrip!(u, cln_rpc::notifications::BalanceSnapshotNotification);
    let _pb: crate::pb::BalanceSnapshotNotification = u.into();
}

#[test]
fn test_coin_movement() {
    let j: serde_json::Value = json!({
        "version": 2,
        "node_id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "coin_type": "bcrt",
        "type": "channel_mvt",
        "account_id": "44b77a6d66ca54f0c365c84b13a95fbde462415a0549228baa25ee1bb1dfef66",
        "created_index": 1,
        "credit_msat": "100000000msat",
        "debit_msat": "0msat",
        "timestamp": 1648222556,
        "primary_tag": "invoice",
        "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
        "part_id": 0,
        "group_id": 1,
        "fees_msat": "1001msat",
        "peer_id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
        "extra_tags": ["keysend"]
    });
    let u: cln_rpc::notifications::CoinMovementNotification = serde_json::from_value(j).unwrap();
    assert_eq!(u.version, 2);
    assert_eq!(
        u.item_type,
        cln_rpc::notifications::CoinMovementType::CHANNEL_MVT
    );
    assert_eq!(
        u.primary_tag,
        Some(cln_rpc::notifications::CoinMovementPrimaryTag::INVOICE)
    );
    assert_eq!(u.extra_tags, Some(vec!["keysend".to_string()]));
    let _pb: crate::pb::CoinMovementNotification = u.into();

    // Also test chain_mvt with utxo
    let j2: serde_json::Value = json!({
        "version": 2,
        "node_id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "coin_type": "bcrt",
        "type": "chain_mvt",
        "account_id": "wallet",
        "created_index": 2,
        "credit_msat": "0msat",
        "debit_msat": "50000000msat",
        "timestamp": 1648222600,
        "primary_tag": "withdrawal",
        "utxo": "9e76017c75baab960aa7aad24f3b7b0a9708f2dbfdc9544a5cfa72fc44206a00:0",
        "blockheight": 110,
        "spending_txid": "67efdfb11bee25aa8b2249055a4162e4bd5fa9134bc865c3f054ca666d7ab744",
        "output_msat": "49000000msat",
        "output_count": 2
    });
    let u2: cln_rpc::notifications::CoinMovementNotification = serde_json::from_value(j2).unwrap();
    assert_eq!(
        u2.item_type,
        cln_rpc::notifications::CoinMovementType::CHAIN_MVT
    );
    assert_eq!(
        u2.primary_tag,
        Some(cln_rpc::notifications::CoinMovementPrimaryTag::WITHDRAWAL)
    );
    assert!(u2.utxo.is_some());
    assert_eq!(u2.blockheight, Some(110));
    let _pb2: crate::pb::CoinMovementNotification = u2.into();
}

#[test]
fn test_channel_state_changed() {
    let j: serde_json::Value = json!({
        "peer_id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "channel_id": "44b77a6d66ca54f0c365c84b13a95fbde462415a0549228baa25ee1bb1dfef66",
        "short_channel_id": "103x2x1",
        "timestamp": "2022-03-25T13:57:33.322Z",
        "old_state": "CHANNELD_AWAITING_LOCKIN",
        "new_state": "CHANNELD_NORMAL",
        "cause": "remote",
        "message": "Lockin complete"
    });
    let u: cln_rpc::notifications::ChannelStateChangedNotification =
        serde_json::from_value(j).unwrap();
    assert_eq!(
        u.cause,
        cln_rpc::notifications::ChannelStateChangedCause::REMOTE
    );
    assert_eq!(u.message, Some("Lockin complete".to_string()));
    assert_serde_roundtrip!(u, cln_rpc::notifications::ChannelStateChangedNotification);
    let _pb: crate::pb::ChannelStateChangedNotification = u.into();

    // Also test without optional fields
    let j_minimal: serde_json::Value = json!({
        "peer_id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "channel_id": "44b77a6d66ca54f0c365c84b13a95fbde462415a0549228baa25ee1bb1dfef66",
        "timestamp": "2022-03-25T13:57:33.322Z",
        "new_state": "OPENINGD",
        "cause": "user"
    });
    let u_min: cln_rpc::notifications::ChannelStateChangedNotification =
        serde_json::from_value(j_minimal).unwrap();
    assert!(u_min.old_state.is_none());
    assert!(u_min.short_channel_id.is_none());
    assert!(u_min.message.is_none());
    let _pb_min: crate::pb::ChannelStateChangedNotification = u_min.into();
}

#[test]
fn test_forward_event() {
    // Settled forward with all fields
    let j: serde_json::Value = json!({
        "created_index": 1,
        "updated_index": 2,
        "status": "settled",
        "in_channel": "103x1x0",
        "in_htlc_id": 0,
        "in_msat": "100001001msat",
        "out_channel": "103x2x1",
        "out_htlc_id": 0,
        "out_msat": "100000000msat",
        "fee_msat": "1001msat",
        "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
        "received_time": 1648222556.498,
        "resolved_time": 1648222557.123,
        "style": "tlv"
    });
    let u: cln_rpc::notifications::ForwardEventNotification = serde_json::from_value(j).unwrap();
    assert_eq!(
        u.status,
        cln_rpc::notifications::ForwardEventStatus::SETTLED
    );
    assert_eq!(
        u.style,
        Some(cln_rpc::notifications::ForwardEventStyle::TLV)
    );
    assert!(u.out_channel.is_some());
    let _pb: crate::pb::ForwardEventNotification = u.into();

    // Failed forward with failure info
    let j_failed: serde_json::Value = json!({
        "created_index": 2,
        "status": "local_failed",
        "in_channel": "103x1x0",
        "in_htlc_id": 1,
        "in_msat": "50000000msat",
        "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
        "received_time": 1648222600.0,
        "failcode": 16399,
        "failreason": "WIRE_TEMPORARY_CHANNEL_FAILURE"
    });
    let u_failed: cln_rpc::notifications::ForwardEventNotification =
        serde_json::from_value(j_failed).unwrap();
    assert_eq!(
        u_failed.status,
        cln_rpc::notifications::ForwardEventStatus::LOCAL_FAILED
    );
    assert_eq!(u_failed.failcode, Some(16399));
    assert!(u_failed.out_channel.is_none());
    let _pb_failed: crate::pb::ForwardEventNotification = u_failed.into();
}

#[test]
fn test_sendpay_failure() {
    let j: serde_json::Value = json!({
        "code": 204,
        "message": "failed: WIRE_TEMPORARY_CHANNEL_FAILURE (reply from remote)",
        "data": {
            "created_index": 1,
            "id": 1,
            "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
            "groupid": 1,
            "updated_index": 1,
            "partid": 0,
            "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
            "amount_msat": "10000msat",
            "amount_sent_msat": "10001msat",
            "created_at": 1648222556,
            "completed_at": 1648222557,
            "status": "failed",
            "erring_index": 1,
            "failcode": 8195,
            "failcodename": "WIRE_TEMPORARY_CHANNEL_FAILURE",
            "erring_node": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
            "erring_channel": "103x2x1",
            "erring_direction": 0,
            "bolt11": "lnbcrt100n1p3...",
            "label": "test-payment-1"
        }
    });
    let u: cln_rpc::notifications::SendPayFailureNotification = serde_json::from_value(j).unwrap();
    assert_eq!(u.code, 204);
    assert_eq!(
        u.data.status,
        Some(cln_rpc::notifications::SendpayFailureDataStatus::FAILED)
    );
    assert_eq!(u.data.failcode, Some(8195));
    assert_eq!(u.data.erring_direction, Some(0));
    let _pb: crate::pb::SendPayFailureNotification = u.into();
}

#[test]
fn test_sendpay_success() {
    let j: serde_json::Value = json!({
        "created_index": 1,
        "id": 1,
        "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
        "groupid": 1,
        "updated_index": 1,
        "partid": 0,
        "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
        "amount_msat": "10000msat",
        "amount_sent_msat": "10001msat",
        "created_at": 1648222556,
        "completed_at": 1648222557,
        "status": "complete",
        "payment_preimage": "e56c22b9ed85560b021e1577daad5742502d25c0c2f636b817f5c0c7580a66a8",
        "bolt11": "lnbcrt100n1p3...",
        "label": "test-payment-1"
    });
    let u: cln_rpc::notifications::SendPaySuccessNotification = serde_json::from_value(j).unwrap();
    assert_eq!(
        u.status,
        cln_rpc::notifications::SendpaySuccessStatus::COMPLETE
    );
    assert_eq!(u.id, 1);
    assert_eq!(u.groupid, 1);
    assert!(u.payment_preimage.is_some());
    assert_serde_roundtrip!(u, cln_rpc::notifications::SendPaySuccessNotification);
    let _pb: crate::pb::SendPaySuccessNotification = u.into();
}

#[test]
fn test_warning() {
    let j: serde_json::Value = json!({
        "level": "warn",
        "time": "1648222556.498",
        "timestamp": "2022-03-25T13:57:33.322Z",
        "source": "lightningd(1234)",
        "log": "Something unexpected happened"
    });
    let u: cln_rpc::notifications::WarningNotification = serde_json::from_value(j).unwrap();
    assert_eq!(u.level, cln_rpc::notifications::WarningLevel::WARN);
    assert_eq!(u.source, "lightningd(1234)");
    assert_serde_roundtrip!(u, cln_rpc::notifications::WarningNotification);
    let _pb: crate::pb::WarningNotification = u.into();

    // Test error level
    let j_err: serde_json::Value = json!({
        "level": "error",
        "time": "1648222600.000",
        "timestamp": "2022-03-25T14:00:00.000Z",
        "source": "channeld(5678)",
        "log": "Fatal channel error"
    });
    let u_err: cln_rpc::notifications::WarningNotification = serde_json::from_value(j_err).unwrap();
    assert_eq!(u_err.level, cln_rpc::notifications::WarningLevel::ERROR);
    let _pb_err: crate::pb::WarningNotification = u_err.into();
}

#[test]
fn test_pay_part_end() {
    // Success case
    let j: serde_json::Value = json!({
        "status": "success",
        "duration": 1.234,
        "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
        "groupid": 1,
        "partid": 0
    });
    let u: cln_rpc::notifications::PayPartEndNotification = serde_json::from_value(j).unwrap();
    assert_eq!(u.status, cln_rpc::notifications::PayPartEndStatus::SUCCESS);
    assert!(u.failed_node_id.is_none());
    assert_serde_roundtrip!(u, cln_rpc::notifications::PayPartEndNotification);
    let _pb: crate::pb::PayPartEndNotification = u.into();

    // Failure case with error details
    let j_fail: serde_json::Value = json!({
        "status": "failure",
        "duration": 5.678,
        "payment_hash": "d17a42c4f7f49648064a0ce7ce848bd92c4c50f24d35fe5c3d1f3a7a9bf474b2",
        "groupid": 1,
        "partid": 1,
        "failed_node_id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
        "failed_short_channel_id": "103x2x1",
        "failed_direction": 0,
        "error_code": 8195,
        "error_message": "WIRE_TEMPORARY_CHANNEL_FAILURE",
        "failed_msg": "deadbeef"
    });
    let u_fail: cln_rpc::notifications::PayPartEndNotification =
        serde_json::from_value(j_fail).unwrap();
    assert_eq!(
        u_fail.status,
        cln_rpc::notifications::PayPartEndStatus::FAILURE
    );
    assert!(u_fail.failed_node_id.is_some());
    assert_eq!(u_fail.error_code, Some(8195));
    let _pb_fail: crate::pb::PayPartEndNotification = u_fail.into();
}
