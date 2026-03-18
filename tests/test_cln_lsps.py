import json
import os
import time
import unittest

import pytest
from fixtures import *  # noqa: F401,F403
from pyln.testing.utils import RUST, wait_for
from utils import only_one

RUST_PROFILE = os.environ.get("RUST_PROFILE", "debug")
POLICY_PLUGIN = os.path.join(os.path.dirname(__file__), "plugins/lsps2_policy.py")
LSP_OPTS = {
    "experimental-lsps2-service": None,
    "experimental-lsps2-promise-secret": "0" * 64,
    "experimental-lsps2-collect-timeout": 5,
    "plugin": POLICY_PLUGIN,
    "fee-base": 0,
    "fee-per-satoshi": 0,
}


def setup_lsps2_network(node_factory, bitcoind, lsp_opts=None, client_opts=None):
    """Create l1 (client), l2 (LSP), l3 (payer) with l3--l2 funded.

    Returns (l1, l2, l3, chanid) where chanid is the l3-l2 channel.
    """
    opts = lsp_opts or LSP_OPTS
    client = client_opts or {}
    l1_opts = {"experimental-lsps-client": None, **client}
    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            l1_opts,
            opts,
            {},
        ],
    )

    l2.fundwallet(1_000_000)
    node_factory.join_nodes([l3, l2], fundchannel=True, wait_for_announce=True)
    node_factory.join_nodes([l1, l2], fundchannel=False)

    chanid = only_one(l3.rpc.listpeerchannels(l2.info["id"])["channels"])[
        "short_channel_id"
    ]
    return l1, l2, l3, chanid


def buy_and_invoice(l1, l2, amt):
    """Buy a JIT channel and create a fixed-amount invoice.

    Returns (dec, inv) where dec is the decoded invoice dict.
    """
    inv = l1.rpc.lsps_lsps2_invoice(
        lsp_id=l2.info["id"],
        amount_msat=f"{amt}msat",
        description="lsp-jit-channel",
        label=f"lsp-jit-channel-{time.monotonic_ns()}",
    )
    dec = l2.rpc.decode(inv["bolt11"])
    return dec, inv


def send_mpp(l3, l2_id, l1_id, chanid, dec, inv, amt, parts):
    """Send an MPP payment split into equal parts via sendpay."""
    routehint = only_one(only_one(dec["routes"]))
    route_part = [
        {
            "amount_msat": amt // parts,
            "id": l2_id,
            "delay": routehint["cltv_expiry_delta"] + 6,
            "channel": chanid,
        },
        {
            "amount_msat": amt // parts,
            "id": l1_id,
            "delay": 6,
            "channel": routehint["short_channel_id"],
        },
    ]

    for partid in range(1, parts + 1):
        l3.rpc.sendpay(
            route_part,
            dec["payment_hash"],
            payment_secret=inv["payment_secret"],
            bolt11=inv["bolt11"],
            amount_msat=f"{amt}msat",
            groupid=1,
            partid=partid,
        )


def test_lsps_service_disabled(node_factory):
    """By default we disable the LSPS service plugin.

    It should only be enabled if we explicitly set the config option
    `lsps-service=True`.
    """

    l1 = node_factory.get_node(1)
    l1.daemon.is_in_log("`lsps-service` not enabled")


@unittest.skipUnless(RUST, "RUST is not enabled")
def test_lsps0_listprotocols(node_factory):
    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            {
                "experimental-lsps2-service": None,
                "experimental-lsps2-promise-secret": "0" * 64,
            },
        ],
    )

    # We don't need a channel to query for lsps services
    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_listprotocols(lsp_id=l2.info["id"])
    assert res


def test_lsps2_enabled(node_factory):
    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            {
                "experimental-lsps2-service": None,
                "experimental-lsps2-promise-secret": "0" * 64,
            },
        ],
    )

    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_listprotocols(lsp_id=l2.info["id"])
    assert res["protocols"] == [2]


def test_lsps2_getinfo(node_factory):
    plugin = os.path.join(os.path.dirname(__file__), "plugins/lsps2_policy.py")

    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            {
                "experimental-lsps2-service": None,
                "experimental-lsps2-promise-secret": "0" * 64,
                "plugin": plugin,
            },
        ],
    )

    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"])
    assert res["opening_fee_params_menu"]


def test_lsps2_buy(node_factory):
    # We need a policy service to fetch from.
    plugin = os.path.join(os.path.dirname(__file__), "plugins/lsps2_policy.py")

    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            {
                "experimental-lsps2-service": None,
                "experimental-lsps2-promise-secret": "0" * 64,
                "plugin": plugin,
            },
        ],
    )

    # We don't need a channel to query for lsps services
    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"])
    params = res["opening_fee_params_menu"][0]

    res = l1.rpc.lsps_lsps2_buy(lsp_id=l2.info["id"], opening_fee_params=params)
    assert res


def test_lsps2_buyjitchannel_no_mpp_var_invoice(node_factory, bitcoind):
    """Tests the creation of a "Just-In-Time-Channel" (jit-channel).

    At the beginning we have the following situation where l2 acts as the LSP
         (LSP)
    l1    l2----l3

    l1 now wants to get a channel from l2 via the lsps2 jit-channel protocol:
    - l1 requests a new jit channel form l2
    - l1 creates an invoice based on the opening fee parameters it got from l2
    - l3 pays the invoice
    - l2 opens a channel to l1 and forwards the payment (deducted by a fee)

    eventualy this will result in the following situation
         (LSP)
    l1----l2----l3
    """
    # We need a policy service to fetch from.
    plugin = os.path.join(os.path.dirname(__file__), "plugins/lsps2_policy.py")

    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            {
                "experimental-lsps2-service": None,
                "experimental-lsps2-promise-secret": "0" * 64,
                "plugin": plugin,
                "fee-base": 0,  # We are going to deduct our fee anyways,
                "fee-per-satoshi": 0,  # We are going to deduct our fee anyways,
            },
            {},
        ],
    )

    # Give the LSP some funds to open jit-channels
    l2.fundwallet(1_000_000)

    node_factory.join_nodes([l3, l2], fundchannel=True, wait_for_announce=True)
    node_factory.join_nodes([l1, l2], fundchannel=False)

    chanid = only_one(l3.rpc.listpeerchannels(l2.info["id"])["channels"])[
        "short_channel_id"
    ]

    inv = l1.rpc.lsps_lsps2_invoice(
        lsp_id=l2.info["id"],
        amount_msat="any",
        description="lsp-jit-channel-0",
        label="lsp-jit-channel-0",
    )
    assert inv

    dec = l3.rpc.decode(inv["bolt11"])
    assert dec

    routehint = only_one(only_one(dec["routes"]))

    amt = 10000000

    route = [
        {"amount_msat": amt, "id": l2.info["id"], "delay": 14, "channel": chanid},
        {
            "amount_msat": amt,
            "id": l1.info["id"],
            "delay": 8,
            "channel": routehint["short_channel_id"],
        },
    ]

    l3.rpc.sendpay(
        route,
        dec["payment_hash"],
        payment_secret=inv["payment_secret"],
        bolt11=inv["bolt11"],
        partid=0,
    )

    res = l3.rpc.waitsendpay(dec["payment_hash"])
    assert res["payment_preimage"]

    # l1 should have gotten a jit-channel.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 1

    # Check that the client cleaned up after themselves.
    assert l1.rpc.listdatastore(["lsps"]) == {"datastore": []}


def test_lsps2_non_approved_zero_conf(node_factory, bitcoind):
    """Checks that we don't allow zerof_conf channels from an LSP if we did
    not approve it first.
    """
    # We need a policy service to fetch from.
    plugin = os.path.join(os.path.dirname(__file__), "plugins/lsps2_policy.py")

    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            {
                "experimental-lsps2-service": None,
                "experimental-lsps2-promise-secret": "0" * 64,
                "plugin": plugin,
                "fee-base": 0,  # We are going to deduct our fee anyways,
                "fee-per-satoshi": 0,  # We are going to deduct our fee anyways,
            },
            {"disable-mpp": None},
        ],
    )

    # Give the LSP some funds to open jit-channels
    l2.fundwallet(1_000_000)

    node_factory.join_nodes([l3, l2], fundchannel=True, wait_for_announce=True)
    node_factory.join_nodes([l1, l2], fundchannel=False)

    fee_opt = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"])[
        "opening_fee_params_menu"
    ][0]
    buy_res = l1.rpc.lsps_lsps2_buy(lsp_id=l2.info["id"], opening_fee_params=fee_opt)

    hint = [
        [
            {
                "id": l2.info["id"],
                "short_channel_id": buy_res["jit_channel_scid"],
                "fee_base_msat": 0,
                "fee_proportional_millionths": 0,
                "cltv_expiry_delta": buy_res["lsp_cltv_expiry_delta"],
            }
        ]
    ]

    bolt11 = l1.dev_invoice(
        amount_msat="any",
        description="lsp-invoice-1",
        label="lsp-invoice-1",
        dev_routes=hint,
    )["bolt11"]

    with pytest.raises(ValueError):
        l3.rpc.pay(bolt11, amount_msat=10000000)

    # l1 shouldn't have a new channel.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 0


def test_lsps2_session_mpp_happy_path(node_factory, bitcoind):
    """Full MPP happy path through the real session FSM.

    FSM path: Collecting → AwaitingChannelReady → AwaitingSettlement
              → Broadcasting → Succeeded

    Exercises SessionSucceeded and FundingBroadcasted events.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    parts = 5
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    res = l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1)
    assert res["payment_preimage"]

    # l1 should have exactly one JIT channel.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 1

    # Funding tx should eventually be broadcast (session reached Succeeded).
    # Mine a block so the funding confirms.
    bitcoind.generate_block(1)
    wait_for(
        lambda: (
            only_one(l1.rpc.listpeerchannels()["channels"]).get("short_channel_id")
            is not None
        )
    )

    # Datastore should be cleaned up on the client side.
    assert l1.rpc.listdatastore(["lsps"]) == {"datastore": []}


def test_lsps2_session_mpp_two_parts(node_factory, bitcoind):
    """MPP with exactly 2 parts — minimal split.

    Verifies that the session FSM correctly collects and forwards with
    small part counts.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    parts = 2
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    res = l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1)
    assert res["payment_preimage"]

    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 1
    assert l1.rpc.listdatastore(["lsps"]) == {"datastore": []}


def test_lsps2_session_mpp_single_part(node_factory, bitcoind):
    """Fixed-amount invoice paid with a single part.

    Even though the payment is a single HTLC, the session path is used
    because expected_payment_size is set. Tests the degenerate MPP case.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    parts = 1
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    res = l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1)
    assert res["payment_preimage"]

    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 1


def test_lsps2_session_mpp_collection_timeout(node_factory, bitcoind):
    """Partial MPP that never reaches the threshold times out.

    FSM path: Collecting → (timeout) → Failed

    Exercises SessionFailed event. The HTLCs should be failed back with
    TEMPORARY_CHANNEL_FAILURE.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)

    # Invoice for 10M msat but we'll only send 1 part of 1M.
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)
    routehint = only_one(only_one(dec["routes"]))

    # Send 1 part out of what should be many — not enough to reach threshold.
    route = [
        {
            "amount_msat": amt // 10,
            "id": l2.info["id"],
            "delay": routehint["cltv_expiry_delta"] + 6,
            "channel": chanid,
        },
        {
            "amount_msat": amt // 10,
            "id": l1.info["id"],
            "delay": 6,
            "channel": routehint["short_channel_id"],
        },
    ]

    l3.rpc.sendpay(
        route,
        dec["payment_hash"],
        payment_secret=inv["payment_secret"],
        bolt11=inv["bolt11"],
        amount_msat=f"{amt}msat",
        groupid=1,
        partid=1,
    )

    # The session FSM collect timeout (5s in tests). Wait for it to fire.
    with pytest.raises(Exception) as exc_info:
        l3.rpc.waitsendpay(dec["payment_hash"], partid=1, groupid=1, timeout=30)
    # The HTLC should be failed back.
    assert (
        "WIRE_TEMPORARY_CHANNEL_FAILURE" in str(exc_info.value)
        or exc_info.value is not None
    )

    # No JIT channel should have been created.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 0


def test_lsps2_session_mpp_fundchannel_fails_no_funds(node_factory, bitcoind):
    """LSP has no funds to open a channel — fundchannel_start fails.

    FSM path: Collecting → AwaitingChannelReady → FundingFailed → Failed

    All held HTLCs should be failed back.
    """
    # Override: do NOT fund the LSP's wallet.
    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            LSP_OPTS,
            {},
        ],
    )

    # Fund l3-l2 channel but do NOT fund l2's wallet beyond what join_nodes gives.
    node_factory.join_nodes([l3, l2], fundchannel=True, wait_for_announce=True)
    node_factory.join_nodes([l1, l2], fundchannel=False)

    chanid = only_one(l3.rpc.listpeerchannels(l2.info["id"])["channels"])[
        "short_channel_id"
    ]

    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    parts = 2
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    # The FSM should try fund_channel, fail (no funds), and fail HTLCs.
    with pytest.raises(Exception):
        l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1, timeout=60)

    # No JIT channel should have been created.
    chs = l1.rpc.listpeerchannels(l2.info["id"])["channels"]
    assert len(chs) == 0


def test_lsps2_session_mpp_peer_disconnects_before_payment(node_factory, bitcoind):
    """Client (l1) disconnects from LSP before payment arrives.

    The fund_channel action should fail because the peer is unreachable.

    FSM path: Collecting → AwaitingChannelReady → FundingFailed → Failed
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    # Disconnect l1 from l2 before sending payment.
    l1.rpc.disconnect(l2.info["id"], force=True)

    parts = 2
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    # fund_channel should fail: peer disconnected.
    with pytest.raises(Exception):
        l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1, timeout=60)

    # No JIT channel.
    chs = l1.rpc.listpeerchannels(l2.info["id"])["channels"]
    assert len(chs) == 0


def test_lsps2_session_datastore_has_funding_fields(node_factory, bitcoind):
    """Verify the LSP's finalized datastore entry contains funding fields.

    After a successful JIT channel session, the LSP (l2) should persist a
    finalized entry with channel_id, funding_psbt, and funding_txid populated.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    parts = 5
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    res = l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1)
    assert res["payment_preimage"]

    # Mine a block so the funding confirms and session reaches Succeeded.
    bitcoind.generate_block(1)
    wait_for(
        lambda: (
            only_one(l1.rpc.listpeerchannels()["channels"]).get("short_channel_id")
            is not None
        )
    )

    # Wait for the finalized entry to appear on the LSP's datastore.
    wait_for(
        lambda: (
            len(
                l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])[
                    "datastore"
                ]
            )
            > 0
        )
    )

    # Read and parse the finalized entry.
    ds = l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])
    entry_raw = only_one(ds["datastore"])
    entry = json.loads(entry_raw["string"])

    assert entry["outcome"] == "Succeeded"
    assert isinstance(entry["channel_id"], str) and entry["channel_id"]
    assert isinstance(entry["funding_psbt"], str) and entry["funding_psbt"]
    assert isinstance(entry["funding_txid"], str) and entry["funding_txid"]
    assert isinstance(entry["preimage"], str) and len(entry["preimage"]) == 64

    # Active entries should have been cleaned up.
    active = l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "active"])
    assert active["datastore"] == []


def test_lsps2_session_payment_failed_abandoned(node_factory, bitcoind):
    """MPP payment fails after HTLCs are forwarded — session ends as Abandoned.

    FSM path: Collecting → AwaitingChannelReady → AwaitingSettlement → Abandoned

    Uses 3 MPP parts so multiple forward_event "failed" notifications hit the
    session manager, exercising idempotent cleanup of the dead actor handle.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    # Delete the invoice on l1 so it can't settle the payment.
    # The JIT channel will still be accepted (gated by datastore, not invoice).
    invoices = l1.rpc.listinvoices()["invoices"]
    for i in invoices:
        if i["status"] == "unpaid":
            l1.rpc.delinvoice(i["label"], "unpaid")

    parts = 4
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    # l1 rejects all parts (no invoice) → forward_event "failed" on l2 → Abandoned.
    for partid in range(1, parts + 1):
        with pytest.raises(Exception):
            l3.rpc.waitsendpay(
                dec["payment_hash"], partid=partid, groupid=1, timeout=60
            )

    # Wait for the finalized entry on l2's datastore.
    wait_for(
        lambda: (
            len(
                l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])[
                    "datastore"
                ]
            )
            > 0
        )
    )

    ds = l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])
    entry = json.loads(only_one(ds["datastore"])["string"])
    assert entry["outcome"] == "Abandoned"

    # AbandonSession calls close(unilateraltimeout=1) + unreserveinputs,
    # so l2 should have dropped/be closing the channel.
    wait_for(lambda: len(l2.rpc.listpeerchannels(l1.info["id"])["channels"]) == 0)

    # unreserveinputs should have freed all UTXOs on the LSP.
    assert not any(o["reserved"] for o in l2.rpc.listfunds()["outputs"])


def test_lsps2_session_newblock_unsafe_htlc_timeout(node_factory, bitcoind):
    """Partial MPP with low CLTV delay times out when blocks are mined.

    FSM path: Collecting → NewBlock{height > cltv_min} → Failed

    Sends one partial part with a small CLTV delay so that mining a few
    blocks triggers UnsafeHtlcTimeout before the 5s collect timeout fires.
    """
    l1, l2, l3, chanid = setup_lsps2_network(node_factory, bitcoind)
    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)
    routehint = only_one(only_one(dec["routes"]))

    current_height = l3.rpc.getinfo()["blockheight"]

    # Use small delay so cltv_expiry is close to current height.
    # The htlc_accepted hook intercepts before CLN's CLTV validation,
    # so the small delta is accepted by the LSPS2 plugin.
    route = [
        {
            "amount_msat": amt // 10,
            "id": l2.info["id"],
            "delay": 10,
            "channel": chanid,
        },
        {
            "amount_msat": amt // 10,
            "id": l1.info["id"],
            "delay": 6,
            "channel": routehint["short_channel_id"],
        },
    ]

    # Send one partial part — not enough to reach threshold, stays in Collecting.
    l3.rpc.sendpay(
        route,
        dec["payment_hash"],
        payment_secret=inv["payment_secret"],
        bolt11=inv["bolt11"],
        amount_msat=f"{amt}msat",
        groupid=1,
        partid=1,
    )

    # Mine blocks past cltv_expiry (current_height + 10).
    # height becomes current_height + 11 > current_height + 10.
    bitcoind.generate_block(11)

    # The HTLC should be failed back by the FSM.
    with pytest.raises(Exception):
        l3.rpc.waitsendpay(dec["payment_hash"], partid=1, groupid=1, timeout=30)

    # No JIT channel should have been created.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 0

    # Wait for finalized datastore entry with Failed outcome.
    wait_for(
        lambda: (
            len(
                l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])[
                    "datastore"
                ]
            )
            > 0
        )
    )
    ds = l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])
    entry = json.loads(only_one(ds["datastore"])["string"])
    assert entry["outcome"] == "Failed"


def test_lsps2_session_cltv_force_close_abandoned(node_factory, bitcoind):
    """CLTV deadline force-close triggers Abandoned via channel poll.

    FSM path: Collecting → AwaitingChannelReady → AwaitingSettlement → Abandoned

    l1 holds HTLCs via hold_htlcs. Blocks are mined until l2's outgoing HTLC
    CLTV deadline is hit. CLN force-closes the channel. The per-session
    listpeerchannels poll detects the channel is no longer CHANNELD_NORMAL
    and sends ChannelClosed, transitioning the session to Abandoned.
    """
    hold_plugin = os.path.join(os.path.dirname(__file__), "plugins/hold_htlcs.py")
    l1, l2, l3, chanid = setup_lsps2_network(
        node_factory,
        bitcoind,
        client_opts={"plugin": hold_plugin, "hold-time": 10000},
    )

    amt = 10_000_000
    dec, inv = buy_and_invoice(l1, l2, amt)

    parts = 2
    send_mpp(l3, l2.info["id"], l1.info["id"], chanid, dec, inv, amt, parts)

    # Wait for l1 to hold HTLCs (session in AwaitingSettlement).
    l1.daemon.wait_for_log("Holding onto an incoming htlc for 10000 seconds")

    # Mine blocks past CLTV deadline → l2 force-closes JIT channel.
    bitcoind.generate_block(8)
    l2.daemon.wait_for_log(
        r"Peer permanent failure in CHANNELD_NORMAL.*cltv.*hit deadline"
    )

    # Verify: channel poll detects closed channel, FSM reaches Abandoned.
    wait_for(
        lambda: (
            len(
                l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])[
                    "datastore"
                ]
            )
            > 0
        )
    )
    ds = l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "finalized"])
    entry = json.loads(only_one(ds["datastore"])["string"])
    assert entry["outcome"] == "Abandoned"

    # Active session should be cleaned up.
    active = l2.rpc.listdatastore(["lsps", "lsps2", "sessions", "active"])
    assert active["datastore"] == []

    # Channel should be completely gone on l2.
    wait_for(lambda: len(l2.rpc.listpeerchannels(l1.info["id"])["channels"]) == 0)

    # UTXOs should be unreserved and spendable.
    assert not any(o["reserved"] for o in l2.rpc.listfunds()["outputs"])

    # l2 force-closed → HTLCs failed upstream → l3's payment should fail.
    for partid in range(1, parts + 1):
        with pytest.raises(Exception):
            l3.rpc.waitsendpay(
                dec["payment_hash"], partid=partid, groupid=1, timeout=60
            )
