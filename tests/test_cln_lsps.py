from fixtures import *  # noqa: F401,F403
from lsps2_mock_helpers import (
    LSPS2_MOCK,
    lsps2_mock_events,
    lsps2_mock_exchange,
    lsps2_mock_forwards,
    lsps2_mock_menu_entry,
    lsps2_mock_nodes,
    lsps2_mock_pay_var_invoice,
    lsps2_mock_request,
)
from lsps2_oracles import (
    check_oracles,
    lsps2_mock_fee,
)
from pyln.client import RpcError
from pyln.testing.utils import RUST
from utils import only_one, wait_for
import json
import os
import pytest
import unittest

RUST_PROFILE = os.environ.get("RUST_PROFILE", "debug")

LSPS2_POLICY = os.path.join(os.path.dirname(__file__), "plugins/lsps2_policy.py")

# The opening fee menu of plugins/lsps2_policy.py, for the mock to serve the
# same.
LSPS2_POLICY_MENU = [
    {
        "min_fee_msat": "1000",
        "proportional": 1000,
        "min_lifetime": 2000,
        "max_client_to_self_delay": 2016,
        "min_payment_size_msat": "1000",
        "max_payment_size_msat": "100000000",
    },
    {
        "min_fee_msat": "1092000",
        "proportional": 2400,
        "min_lifetime": 1008,
        "max_client_to_self_delay": 2016,
        "min_payment_size_msat": "1000",
        "max_payment_size_msat": "1000000",
    },
]

# The client tests run against both the in-tree LSPS2 service and the mock
# service in plugins/lsps2_mock.py.
LSPS2_SERVICES = ["in-tree", "mock"]


def lsps2_service_opts(service, policy=False):
    """Options for an LSP node running `service`. The in-tree service gets
    the policy plugin if `policy`; the mock always serves its menu."""
    if service == "mock":
        config = {"get_info": {"menu": LSPS2_POLICY_MENU}}
        return {"plugin": LSPS2_MOCK, "lsps2-mock-config": json.dumps(config)}
    opts = {
        "experimental-lsps2-service": None,
        "experimental-lsps2-promise-secret": "0" * 64,
    }
    if policy:
        opts["plugin"] = LSPS2_POLICY
    return opts


def test_lsps_service_disabled(node_factory):
    """By default we disable the LSPS service plugin.

    It should only be enabled if we explicitly set the config option
    `lsps-service=True`.
    """

    l1 = node_factory.get_node(1)
    l1.daemon.is_in_log("`lsps-service` not enabled")


@unittest.skipUnless(RUST, "RUST is not enabled")
@pytest.mark.parametrize("service", LSPS2_SERVICES)
def test_lsps0_listprotocols(node_factory, service):
    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            lsps2_service_opts(service),
        ],
    )

    # We don't need a channel to query for lsps services
    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_listprotocols(lsp_id=l2.info["id"])
    assert res


@pytest.mark.parametrize("service", LSPS2_SERVICES)
def test_lsps2_enabled(node_factory, service):
    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            lsps2_service_opts(service),
        ],
    )

    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_listprotocols(lsp_id=l2.info["id"])
    assert res["protocols"] == [2]


@pytest.mark.parametrize("service", LSPS2_SERVICES)
def test_lsps2_getinfo(node_factory, service):
    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            lsps2_service_opts(service, policy=True),
        ],
    )

    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"])
    assert res["opening_fee_params_menu"]


@pytest.mark.parametrize("service", LSPS2_SERVICES)
def test_lsps2_buy(node_factory, service):
    # The in-tree service needs a policy service to fetch from.
    l1, l2 = node_factory.get_nodes(
        2,
        opts=[
            {"experimental-lsps-client": None},
            lsps2_service_opts(service, policy=True),
        ],
    )

    # We don't need a channel to query for lsps services
    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"])
    params = res["opening_fee_params_menu"][0]

    res = l1.rpc.lsps_lsps2_buy(lsp_id=l2.info["id"], opening_fee_params=params)
    assert res


@pytest.mark.parametrize("service", LSPS2_SERVICES)
def test_lsps2_buyjitchannel_no_mpp_var_invoice(node_factory, bitcoind, service):
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
    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            {
                # The in-tree service needs a policy service to fetch from.
                **lsps2_service_opts(service, policy=True),
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

    if service == "mock":
        check_oracles(l1, l2)


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

    The in-tree service does not support MPP, so l2 runs the mock service.
    """
    # 10% of the payment, the fee spreads over several parts.
    fee_msat = 1_000_000
    menu = [lsps2_mock_menu_entry(1000, proportional=100_000)]

    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            {
                "plugin": LSPS2_MOCK,
                "lsps2-mock-config": json.dumps({"get_info": {"menu": menu}}),
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

    # The fee is spread over the parts; a part without a deduction carries
    # no extra_fee TLV.
    assert lsps2_mock_fee.opening_fee(amt, 1000, 100_000) == fee_msat
    fwds = lsps2_mock_forwards(l2)
    assert len(fwds) == parts
    assert sum(f["extra_fee_msat"] or 0 for f in fwds) == fee_msat
    assert sum(f["forward_msat"] for f in fwds) == amt - fee_msat
    assert any(f["extra_fee_msat"] is None for f in fwds)

    paid = only_one(l1.rpc.listinvoices("lsp-jit-channel-0")["invoices"])
    assert paid["status"] == "paid"
    check_oracles(l1, l2)


@pytest.mark.parametrize("service", LSPS2_SERVICES)
def test_lsps2_non_approved_zero_conf(node_factory, bitcoind, service):
    """Checks that we don't allow zerof_conf channels from an LSP if we did
    not approve it first.
    """
    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None},
            {
                # The in-tree service needs a policy service to fetch from.
                **lsps2_service_opts(service, policy=True),
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

    if service == "mock":
        # The test made the invoice, not the client.
        check_oracles(l1, l2, waive={"params.invoice"})


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
    with pytest.raises(RpcError, match="transport.methods must be a list"):
        l1.rpc.call(
            "lsps2-mock-configure",
            {"config": {"transport": {"behavior": "drop", "methods": "lsps2.buy"}}},
        )
    with pytest.raises(RpcError, match="htlc.parts must be a list"):
        l1.rpc.call(
            "lsps2-mock-configure",
            {"config": {"htlc": {"behavior": "forward_subset", "parts": None}}},
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
    forwards it with the opening fee for its amount deducted."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    menu_entry = lsps2_mock_menu_entry(1000, proportional=10_000)
    l2.rpc.call(
        "lsps2-mock-configure", {"config": {"get_info": {"menu": [menu_entry]}}}
    )

    amt = 10_000_000
    fee_msat = lsps2_mock_fee.opening_fee(amt, 1000, 10_000)
    assert fee_msat == 100_000
    assert lsps2_mock_pay_var_invoice(l1, l2, l3, amt)["payment_preimage"]

    fwd = only_one(lsps2_mock_forwards(l2))
    assert fwd["forward_msat"] == amt - fee_msat
    assert fwd["extra_fee_msat"] == fee_msat

    only_one(l1.rpc.listpeerchannels()["channels"])
    paid = only_one(l1.rpc.listinvoices("lsp-jit-channel-0")["invoices"])
    assert paid["status"] == "paid"
    assert paid["amount_received_msat"] == amt - fee_msat
    check_oracles(l1, l2)


LIST_PROTOCOLS_RESULT = {"jsonrpc": "2.0", "result": {"protocols": [2]}, "id": "1"}


@pytest.mark.parametrize(
    "transport,expected",
    [
        ({"behavior": "honest"}, [LIST_PROTOCOLS_RESULT]),
        ({"behavior": "drop"}, []),
        ({"behavior": "wrong_id"}, [{**LIST_PROTOCOLS_RESULT, "id": "mock-wrong-id"}]),
        (
            {"behavior": "duplicate", "change": {"protocols": [1]}},
            [
                LIST_PROTOCOLS_RESULT,
                {**LIST_PROTOCOLS_RESULT, "result": {"protocols": [1]}},
            ],
        ),
        ({"behavior": "replace", "payload": "garbage"}, ["garbage"]),
        (
            {"behavior": "add_fields", "fields": {"unknown": 1}},
            [{**LIST_PROTOCOLS_RESULT, "result": {"protocols": [2], "unknown": 1}}],
        ),
        (
            {"behavior": "error", "error": {"code": -32603, "message": "boom"}},
            [
                {
                    "jsonrpc": "2.0",
                    "id": "1",
                    "error": {"code": -32603, "message": "boom"},
                }
            ],
        ),
        # Limited to other methods: honest.
        (
            {"behavior": "drop", "methods": ["lsps2.buy"]},
            [LIST_PROTOCOLS_RESULT],
        ),
    ],
)
def test_lsps2_mock_transport_behaviors(node_factory, transport, expected):
    l1, l2 = node_factory.line_graph(
        2, fundchannel=False, opts=[{}, {"plugin": LSPS2_MOCK}]
    )
    l2.rpc.call("lsps2-mock-configure", {"config": {"transport": transport}})

    assert lsps2_mock_request(l1, l2, "lsps0.list_protocols", {}) == expected


def test_lsps2_mock_rejects_missing_parameters(node_factory):
    l1 = node_factory.get_node(options={"plugin": LSPS2_MOCK})

    with pytest.raises(RpcError, match="missing parameters"):
        l1.rpc.call(
            "lsps2-mock-configure", {"config": {"transport": {"behavior": "replace"}}}
        )


def test_lsps2_mock_buy_result(node_factory):
    """The buy result fields are fixtures."""
    l1, l2 = node_factory.line_graph(
        2, fundchannel=False, opts=[{}, {"plugin": LSPS2_MOCK}]
    )
    fields = {
        "jit_channel_scid": "1x2x3",
        "lsp_cltv_expiry_delta": 400,
        "client_trusts_lsp": True,
    }
    l2.rpc.call("lsps2-mock-configure", {"config": {"buy": fields}})

    res = only_one(lsps2_mock_request(l1, l2, "lsps2.get_info", {}))
    params = only_one(res["result"]["opening_fee_params_menu"])
    res = only_one(
        lsps2_mock_request(l1, l2, "lsps2.buy", {"opening_fee_params": params})
    )
    assert res["result"] == fields


def test_lsps2_mock_htlc_deduct(node_factory):
    """`deduct` sets the deduction and the extra_fee TLV per part."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    fee_msat = 1_000_000
    l2.rpc.call(
        "lsps2-mock-configure",
        {
            "config": {
                "get_info": {"menu": [lsps2_mock_menu_entry(fee_msat)]},
                "htlc": {
                    "behavior": "deduct",
                    "deductions": [fee_msat],
                    "extra_fees": [fee_msat],
                },
            }
        },
    )

    amt = 10_000_000
    assert lsps2_mock_pay_var_invoice(l1, l2, l3, amt)["payment_preimage"]

    fwd = only_one(lsps2_mock_forwards(l2))
    assert fwd["forward_msat"] == amt - fee_msat
    assert fwd["extra_fee_msat"] == fee_msat


def test_lsps2_mock_open_never(node_factory):
    """With `open.never` the mock fails the payment instead of opening."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    l2.rpc.call("lsps2-mock-configure", {"config": {"open": {"behavior": "never"}}})

    with pytest.raises(RpcError):
        lsps2_mock_pay_var_invoice(l1, l2, l3, 10_000_000)

    only_one(lsps2_mock_events(l2, "open_skipped"))
    assert l1.rpc.listpeerchannels()["channels"] == []


def test_lsps2_mock_open_failed(node_factory):
    """If the open fails, the mock fails the payment instead of holding it."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    # More than the LSP's wallet holds.
    l2.rpc.call(
        "lsps2-mock-configure", {"config": {"open": {"capacity_sat": 10_000_000}}}
    )

    with pytest.raises(RpcError):
        lsps2_mock_pay_var_invoice(l1, l2, l3, 10_000_000)

    assert only_one(lsps2_mock_events(l2, "open_failed"))["connected"]
    assert only_one(lsps2_mock_events(l2, "htlc"))["decision"] == "fail"
    assert l1.rpc.listpeerchannels()["channels"] == []


def test_lsps2_mock_open_disconnect(node_factory):
    """If the client disconnects before funding_signed, the mock fails the
    payment with temporary_channel_failure (bLIP-52)."""
    l1, l2, l3 = lsps2_mock_nodes(
        node_factory, client_opts={"disconnect": ["-WIRE_FUNDING_SIGNED"]}
    )

    with pytest.raises(RpcError) as err:
        lsps2_mock_pay_var_invoice(l1, l2, l3, 10_000_000)
    assert err.value.error["data"]["failcode"] == 0x1007

    assert not only_one(lsps2_mock_events(l2, "open_failed"))["connected"]


def test_lsps2_mock_request_error(node_factory):
    """An exception in a request handler is answered as an internal error and
    logged as BROKEN, without taking the node down."""
    config = {"get_info": {"menu": [{**lsps2_mock_menu_entry(1000), "valid_until": "x"}]}}
    l1, l2 = node_factory.line_graph(
        2,
        fundchannel=False,
        opts=[
            {},
            {
                "plugin": LSPS2_MOCK,
                "lsps2-mock-config": json.dumps(config),
                "broken_log": "lsps2.buy failed",
            },
        ],
    )

    res = only_one(lsps2_mock_request(l1, l2, "lsps2.get_info", {}))
    params = only_one(res["result"]["opening_fee_params_menu"])
    res = only_one(
        lsps2_mock_request(l1, l2, "lsps2.buy", {"opening_fee_params": params})
    )
    assert res["error"] == {"code": -32603, "message": "Internal error"}
    assert only_one(lsps2_mock_events(l2, "error"))["where"] == "lsps2.buy"
    assert l2.rpc.call("lsps2-mock-state")


def test_lsps2_mock_htlc_error(node_factory):
    """An exception while forwarding fails the held parts instead of
    leaving them unanswered."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    l2.broken_log = "release failed"
    amt = 10_000_000
    # A deduction above the amount cannot be encoded.
    l2.rpc.call(
        "lsps2-mock-configure",
        {"config": {"htlc": {"behavior": "deduct", "deductions": [amt + 1]}}},
    )

    with pytest.raises(RpcError) as err:
        lsps2_mock_pay_var_invoice(l1, l2, l3, amt)
    assert err.value.error["data"]["failcode"] == 0x2002

    assert only_one(lsps2_mock_events(l2, "error"))["where"] == "release"
    assert only_one(lsps2_mock_events(l2, "htlc"))["decision"] == "fail"


def test_lsps2_mock_fee():
    """The mock's opening fee, against values worked out by hand from the
    bLIP-52 formula."""
    fee = lsps2_mock_fee.opening_fee
    u64_max = lsps2_mock_fee.U64_MAX

    # The proportional part rounds up to the next msat.
    assert fee(1_000_000, 0, 7) == 7
    assert fee(1_000_001, 0, 7) == 8
    assert fee(999_999, 0, 1) == 1
    assert fee(0, 0, 1000) == 0

    # min_fee_msat is a floor.
    assert fee(10_000_000, 1000, 99) == 1000
    assert fee(10_000_000, 1000, 101) == 1010
    assert fee(1, u64_max, 0) == u64_max

    # Every multiplication and addition stays within unsigned 64 bits.
    largest_product = u64_max - 999_999
    assert fee(largest_product, 0, 1) == u64_max // 1_000_000
    with pytest.raises(lsps2_mock_fee.FeeOverflow):
        fee(largest_product + 1, 0, 1)
    with pytest.raises(lsps2_mock_fee.FeeOverflow):
        fee(2**32, 0, 2**32)
    with pytest.raises(ValueError):
        fee(-1, 0, 0)


def test_lsps2_mock_buy_fee_checks(node_factory):
    """buy fails with 202 when the opening fee eats the payment and with 203
    when computing it overflows."""
    l1, l2 = node_factory.line_graph(
        2, fundchannel=False, opts=[{}, {"plugin": LSPS2_MOCK}]
    )
    u64_max = str(lsps2_mock_fee.U64_MAX)
    menu = [
        {**lsps2_mock_menu_entry(1_000_000), "max_payment_size_msat": u64_max},
        {
            **lsps2_mock_menu_entry(0, proportional=2**32 - 1),
            "max_payment_size_msat": u64_max,
        },
    ]
    l2.rpc.call("lsps2-mock-configure", {"config": {"get_info": {"menu": menu}}})
    res = only_one(lsps2_mock_request(l1, l2, "lsps2.get_info", {}))
    min_fee, proportional = res["result"]["opening_fee_params_menu"]

    def buy(params, payment_size_msat):
        return only_one(
            lsps2_mock_request(
                l1,
                l2,
                "lsps2.buy",
                {
                    "opening_fee_params": params,
                    "payment_size_msat": str(payment_size_msat),
                },
            )
        )

    assert buy(min_fee, 1_000_000)["error"]["code"] == 202
    assert "result" in buy(min_fee, 1_000_001)
    with pytest.raises(lsps2_mock_fee.FeeOverflow):
        lsps2_mock_fee.opening_fee(2**33, 0, 2**32 - 1)
    assert buy(proportional, 2**33)["error"]["code"] == 203

    sessions = l2.rpc.call("lsps2-mock-state")["sessions"]
    assert only_one(sessions)["opening_fee_msat"] == 1_000_000


def test_lsps2_mock_expired_session(node_factory):
    """The mock fails a JIT payment that arrives once the params expired,
    without opening a channel."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    # Past the default validity of an hour.
    l2.rpc.call(
        "lsps2-mock-configure", {"config": {"htlc": {"clock_offset_seconds": 7200}}}
    )

    with pytest.raises(RpcError) as err:
        lsps2_mock_pay_var_invoice(l1, l2, l3, 10_000_000)
    # unknown_next_peer
    assert err.value.error["data"]["failcode"] == 0x400A

    fail = only_one(lsps2_mock_events(l2, "htlc"))
    assert fail["reason"] == "expired"
    assert lsps2_mock_events(l2, "open") == []
    check_oracles(l1, l2)


def test_lsps2_mock_expired_held_parts(node_factory):
    """MPP+fixed-invoice: parts still held when the params expire are failed,
    without another part arriving."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
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
    # Half of the payment, so the mock holds it.
    route = [
        {
            "amount_msat": amt // 2,
            "id": l2.info["id"],
            "delay": routehint["cltv_expiry_delta"] + 6,
            "channel": chanid,
        },
        {
            "amount_msat": amt // 2,
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
        amount_msat=amt,
        groupid=1,
        partid=1,
    )
    wait_for(
        lambda: only_one(l2.rpc.call("lsps2-mock-state")["sessions"])["held_parts"]
        == 1
    )

    # Past the default validity of an hour.
    l2.rpc.call(
        "lsps2-mock-configure", {"config": {"htlc": {"clock_offset_seconds": 7200}}}
    )
    with pytest.raises(RpcError) as err:
        l3.rpc.waitsendpay(dec["payment_hash"], partid=1, groupid=1)
    # unknown_next_peer
    assert err.value.error["data"]["failcode"] == 0x400A

    fail = only_one(lsps2_mock_events(l2, "htlc"))
    assert fail["reason"] == "expired"
    assert lsps2_mock_events(l2, "open") == []


@pytest.mark.parametrize("amt", [1000, 10_000_001])
def test_lsps2_mock_var_invoice_payment_size(node_factory, amt):
    """no-MPP+var-invoice: the mock fails a payment outside the size limits
    or too small to carry the opening fee, without opening a channel."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    menu_entry = {
        **lsps2_mock_menu_entry(1000),
        "max_payment_size_msat": "10000000",
    }
    l2.rpc.call(
        "lsps2-mock-configure", {"config": {"get_info": {"menu": [menu_entry]}}}
    )

    with pytest.raises(RpcError) as err:
        lsps2_mock_pay_var_invoice(l1, l2, l3, amt)
    # unknown_next_peer
    assert err.value.error["data"]["failcode"] == 0x400A

    fail = only_one(lsps2_mock_events(l2, "htlc"))
    assert fail["decision"] == "fail"
    assert fail["reason"] == "payment_size"
    assert lsps2_mock_events(l2, "open") == []
    assert l1.rpc.listpeerchannels()["channels"] == []
