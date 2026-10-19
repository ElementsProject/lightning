from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.testing.utils import RUST
from utils import only_one, wait_for
import json
import os
import pytest
import unittest

RUST_PROFILE = os.environ.get("RUST_PROFILE", "debug")


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


def test_lsps2_buyjitchannel_mpp_fixed_invoice(node_factory, bitcoind):
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
    # A mock for lsps2 mpp payments, contains the policy plugin as well.
    plugin = os.path.join(os.path.dirname(__file__), "plugins/lsps2_service_mock.py")

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

    amt = 10_000_000
    inv = l1.rpc.lsps_lsps2_invoice(
        lsp_id=l2.info["id"],
        amount_msat=amt,
        description="lsp-jit-channel-0",
        label="lsp-jit-channel-0",
    )
    dec = l3.rpc.decode(inv["bolt11"])

    l2.rpc.setuplsps2service(
        peer_id=l1.info["id"], channel_cap=100_000, opening_fee_msat=1000_000
    )

    routehint = only_one(only_one(dec["routes"]))

    parts = 10
    route_part = [
        {
            "amount_msat": amt // parts,
            "id": l2.info["id"],
            "delay": routehint["cltv_expiry_delta"] + 6,
            "channel": chanid,
        },
        {
            "amount_msat": amt // parts,
            "id": l1.info["id"],
            "delay": 6,
            "channel": routehint["short_channel_id"],
        },
    ]

    # MPP-payment of fixed amount
    for partid in range(1, parts + 1):
        r = l3.rpc.sendpay(
            route_part,
            dec["payment_hash"],
            payment_secret=inv["payment_secret"],
            bolt11=inv["bolt11"],
            amount_msat=f"{amt}msat",
            groupid=1,
            partid=partid,
        )
        assert r

    res = l3.rpc.waitsendpay(dec["payment_hash"], partid=parts, groupid=1)
    assert res["payment_preimage"]

    # l1 should have gotten a jit-channel.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 1

    # Check that the client cleaned up after themselves.
    assert l1.rpc.listdatastore("lsps") == {"datastore": []}


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
        l3.rpc.xpay(bolt11, amount_msat=10000000)

    # l1 shouldn't have a new channel.
    chs = l1.rpc.listpeerchannels()["channels"]
    assert len(chs) == 0


LSPS2_MOCK = os.path.join(os.path.dirname(__file__), "plugins/lsps2_mock.py")


def lsps2_mock_nodes(node_factory):
    """Client l1, LSP l2 running the mock service, payer l3.

    l3 has a public channel to l2; l1 is only connected to l2.
    """
    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            {
                "plugin": LSPS2_MOCK,
                # The mock deducts the opening fee; no forwarding fee on top.
                "fee-base": 0,
                "fee-per-satoshi": 0,
            },
            {},
        ],
    )
    l2.fundwallet(1_000_000)
    node_factory.join_nodes([l3, l2], fundchannel=True, wait_for_announce=True)
    node_factory.join_nodes([l1, l2], fundchannel=False)
    return l1, l2, l3


def lsps2_mock_menu_entry(min_fee_msat):
    return {
        "min_fee_msat": str(min_fee_msat),
        "proportional": 0,
        "min_lifetime": 1008,
        "max_client_to_self_delay": 2016,
        "min_payment_size_msat": "1000",
        "max_payment_size_msat": "100000000",
    }


def lsps2_mock_events(lsp, kind):
    return [e for e in lsp.rpc.call("lsps2-mock-state")["events"] if e["type"] == kind]


def lsps2_mock_forwards(lsp):
    return [e for e in lsps2_mock_events(lsp, "htlc") if e["decision"] == "forward"]


def lsps2_mock_exchange(client, lsp, payload):
    """Send `payload` (str) from `client` to the mock on `lsp` as an LSPS0
    message and return the messages the mock sent in response, decoded if
    they are JSON."""
    seen = len(lsps2_mock_events(lsp, "rx"))
    sent = len(lsps2_mock_events(lsp, "tx"))
    msg = (37913).to_bytes(2, "big") + payload.encode()
    client.rpc.sendcustommsg(lsp.info["id"], msg.hex())
    # The mock answers while handling the message, so its answer is
    # recorded by the time the message shows up.
    wait_for(lambda: len(lsps2_mock_events(lsp, "rx")) > seen)
    return [decode_json(e["payload"]) for e in lsps2_mock_events(lsp, "tx")[sent:]]


def decode_json(s):
    try:
        return json.loads(s)
    except ValueError:
        return s


def lsps2_mock_request(client, lsp, method, params, req_id="1"):
    request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    return lsps2_mock_exchange(client, lsp, json.dumps(request))


def lsps2_mock_pay_var_invoice(l1, l2, l3, amt, label="lsp-jit-channel-0"):
    """l1 issues a variable-amount JIT invoice, l3 pays `amt` through l2.

    Returns the result of waitsendpay; raises if the payment failed."""
    inv = l1.rpc.lsps_lsps2_invoice(
        lsp_id=l2.info["id"], amount_msat="any", description=label, label=label
    )
    dec = l3.rpc.decode(inv["bolt11"])
    routehint = only_one(only_one(dec["routes"]))
    chanid = only_one(l3.rpc.listpeerchannels(l2.info["id"])["channels"])[
        "short_channel_id"
    ]
    route = [
        {
            "amount_msat": amt,
            "id": l2.info["id"],
            "delay": routehint["cltv_expiry_delta"] + 6,
            "channel": chanid,
        },
        {
            "amount_msat": amt,
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
    )
    return l3.rpc.waitsendpay(dec["payment_hash"])


def test_lsps2_mock_rejects_unknown_config(node_factory):
    l1 = node_factory.get_node(options={"plugin": LSPS2_MOCK})

    with pytest.raises(RpcError, match="unknown phase"):
        l1.rpc.call("lsps2-mock-configure", {"config": {"bogus": {}}})
    with pytest.raises(RpcError, match="unknown behavior"):
        l1.rpc.call("lsps2-mock-configure", {"config": {"buy": {"behavior": "bogus"}}})
    with pytest.raises(RpcError, match="unknown parameters"):
        l1.rpc.call(
            "lsps2-mock-configure",
            {"config": {"buy": {"lsp_cltv_expiry_deltaa": 1}}},
        )


def test_lsps2_mock_config_option(node_factory):
    """The mock can be configured at startup."""
    config = {"list_protocols": {"protocols": [1, 2]}}
    l1, l2 = node_factory.line_graph(
        2,
        fundchannel=False,
        opts=[{}, {"plugin": LSPS2_MOCK, "lsps2-mock-config": json.dumps(config)}],
    )

    res = only_one(lsps2_mock_request(l1, l2, "lsps0.list_protocols", {}))
    assert res["result"] == {"protocols": [1, 2]}


def test_lsps2_mock_protocol(node_factory):
    """The client can talk LSPS0 and LSPS2 to the mock."""
    l1, l2 = node_factory.line_graph(
        2,
        fundchannel=False,
        opts=[{"experimental-lsps-client": None}, {"plugin": LSPS2_MOCK}],
    )

    assert l1.rpc.lsps_listprotocols(lsp_id=l2.info["id"])["protocols"] == [2]

    menu = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"])["opening_fee_params_menu"]
    params = only_one(menu)
    res = l1.rpc.lsps_lsps2_buy(lsp_id=l2.info["id"], opening_fee_params=params)
    assert res["jit_channel_scid"] == "1000000x1x0"

    # The client echoed the promise and the params verbatim.
    buy = only_one(lsps2_mock_events(l2, "buy"))
    assert buy["opening_fee_params"] == params


def test_lsps2_mock_protocol_errors(node_factory):
    """The mock answers malformed and invalid requests as bLIP-50/52 say."""
    l1, l2 = node_factory.line_graph(
        2, fundchannel=False, opts=[{}, {"plugin": LSPS2_MOCK}]
    )

    res = only_one(lsps2_mock_exchange(l1, l2, "{"))
    assert res["id"] is None
    assert res["error"]["code"] == -32700

    res = only_one(lsps2_mock_request(l1, l2, "lsps9.nope", {}))
    assert res["error"]["code"] == -32601

    res = only_one(lsps2_mock_request(l1, l2, "lsps2.get_info", {"bogus": 1}))
    assert res["error"]["code"] == -32602
    assert res["error"]["data"] == {"unrecognized": ["bogus"]}

    res = only_one(lsps2_mock_request(l1, l2, "lsps2.get_info", {}))
    params = only_one(res["result"]["opening_fee_params_menu"])

    # Any change to the promised params invalidates the promise.
    tampered = {**params, "min_fee_msat": "0"}
    res = only_one(
        lsps2_mock_request(l1, l2, "lsps2.buy", {"opening_fee_params": tampered})
    )
    assert res["error"]["code"] == 201

    res = only_one(
        lsps2_mock_request(
            l1,
            l2,
            "lsps2.buy",
            {"opening_fee_params": params, "payment_size_msat": "999"},
        )
    )
    assert res["error"]["code"] == 202

    res = only_one(
        lsps2_mock_request(l1, l2, "lsps2.buy", {"opening_fee_params": params})
    )
    assert res["result"]["jit_channel_scid"] == "1000000x1x0"


def test_lsps2_mock_jit_channel_var_invoice(node_factory):
    """no-MPP+var-invoice: the mock opens a channel on the first HTLC and
    forwards it with the opening fee deducted."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    fee_msat = 1_000_000
    l2.rpc.call(
        "lsps2-mock-configure",
        {
            "config": {
                "get_info": {"menu": [lsps2_mock_menu_entry(fee_msat)]},
                "htlc": {"fee_msat": fee_msat},
            }
        },
    )

    amt = 10_000_000
    assert lsps2_mock_pay_var_invoice(l1, l2, l3, amt)["payment_preimage"]

    fwd = only_one(lsps2_mock_forwards(l2))
    assert fwd["forward_msat"] == amt - fee_msat
    assert fwd["extra_fee_msat"] == fee_msat

    only_one(l1.rpc.listpeerchannels()["channels"])
    paid = only_one(l1.rpc.listinvoices("lsp-jit-channel-0")["invoices"])
    assert paid["status"] == "paid"
    assert paid["amount_received_msat"] == amt - fee_msat


def test_lsps2_mock_jit_channel_mpp_fixed_invoice(node_factory):
    """MPP+fixed-invoice: the mock waits for all parts, then forwards them
    with the opening fee spread over the parts."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    fee_msat = 1_500_000
    l2.rpc.call(
        "lsps2-mock-configure",
        {
            "config": {
                "get_info": {"menu": [lsps2_mock_menu_entry(fee_msat)]},
                "htlc": {"fee_msat": fee_msat},
            }
        },
    )

    amt = 10_000_000
    inv = l1.rpc.lsps_lsps2_invoice(
        lsp_id=l2.info["id"],
        amount_msat=amt,
        description="lsp-jit-channel-0",
        label="lsp-jit-channel-0",
    )
    dec = l3.rpc.decode(inv["bolt11"])
    routehint = only_one(only_one(dec["routes"]))
    chanid = only_one(l3.rpc.listpeerchannels(l2.info["id"])["channels"])[
        "short_channel_id"
    ]

    parts = 10
    route_part = [
        {
            "amount_msat": amt // parts,
            "id": l2.info["id"],
            "delay": routehint["cltv_expiry_delta"] + 6,
            "channel": chanid,
        },
        {
            "amount_msat": amt // parts,
            "id": l1.info["id"],
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
            amount_msat=amt,
            groupid=1,
            partid=partid,
        )
    for partid in range(1, parts + 1):
        res = l3.rpc.waitsendpay(dec["payment_hash"], partid=partid, groupid=1)
        assert res["payment_preimage"]

    fwds = lsps2_mock_forwards(l2)
    assert len(fwds) == parts
    assert sum(f["extra_fee_msat"] or 0 for f in fwds) == fee_msat
    assert sum(f["forward_msat"] for f in fwds) == amt - fee_msat
    # A part without a deduction carries no extra_fee TLV.
    assert any(f["extra_fee_msat"] is None for f in fwds)

    only_one(l1.rpc.listpeerchannels()["channels"])
    paid = only_one(l1.rpc.listinvoices("lsp-jit-channel-0")["invoices"])
    assert paid["status"] == "paid"
