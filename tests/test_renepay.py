from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError, Millisatoshi
from utils import (
    only_one,
    wait_for,
    mine_funding_to_announce,
    sync_blockheight,
    TEST_NETWORK,
)
import pytest
import random
import time
import json
import subprocess
import os


def test_simple(node_factory):
    """Testing simply paying a peer."""
    l1, l2 = node_factory.line_graph(2)
    inv = l2.rpc.invoice(123000, "test_renepay", "description")["bolt11"]
    details = l1.rpc.call("renepay", {"invstring": inv})
    assert details["status"] == "complete"
    assert details["amount_msat"] == Millisatoshi(123000)
    assert details["destination"] == l2.info["id"]


def test_direction_matters(node_factory):
    """Make sure we use correct delay and fees for the direction we're going."""
    l1, l2, l3 = node_factory.line_graph(
        3,
        wait_for_announce=True,
        opts=[
            {},
            {"fee-base": 2000, "fee-per-satoshi": 20, "cltv-delta": 20},
            {"fee-base": 3000, "fee-per-satoshi": 30, "cltv-delta": 30},
        ],
    )
    inv = l3.rpc.invoice(123000, "test_renepay", "description")["bolt11"]
    details = l1.rpc.call("renepay", {"invstring": inv})
    assert details["status"] == "complete"
    assert details["amount_msat"] == Millisatoshi(123000)
    assert details["destination"] == l3.info["id"]


def test_shadow_routing(node_factory):
    """
    Test the value randomization through shadow routing

    Note there is a very low (0.5**10) probability that it fails.
    """
    # We need l3 for random walk
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    amount = 10000
    total_amount = 0
    n_payments = 10
    for i in range(n_payments):
        inv = l3.rpc.invoice(amount, "{}".format(i), "test")["bolt11"]
        total_amount += l1.rpc.call(
            "renepay", {"invstring": inv, "dev_use_shadow": True}
        )["amount_sent_msat"]

    assert total_amount > n_payments * amount
    # Test that the added amount isn't absurd
    assert total_amount < int((n_payments * amount) * (1 + 0.01))


def test_mpp(node_factory):
    """Test paying a remote node using two routes.
    1----2----4
    |         |
    3----5----6
    Try paying 1.2M sats from 1 to 6.
    """
    opts = [
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
    ]
    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=opts * 6)
    node_factory.join_nodes(
        [l1, l2, l4, l6], wait_for_announce=True, fundamount=1000000
    )
    node_factory.join_nodes(
        [l1, l3, l5, l6], wait_for_announce=True, fundamount=1000000
    )

    send_amount = Millisatoshi("1200000sat")
    inv = l6.rpc.invoice(send_amount, "test_renepay", "description")["bolt11"]
    details = l1.rpc.call("renepay", {"invstring": inv})
    assert details["status"] == "complete"
    assert details["amount_msat"] == send_amount
    assert details["destination"] == l6.info["id"]


def test_errors(node_factory, bitcoind):
    opts = [
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
    ]
    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=opts * 6)
    send_amount = Millisatoshi("21sat")
    inv = l6.rpc.invoice(send_amount, "test_renepay", "description")["bolt11"]
    inv_deleted = l6.rpc.invoice(send_amount, "test_renepay2", "description2")["bolt11"]
    l6.rpc.delinvoice("test_renepay2", "unpaid")

    failmsg = r"We don\'t have any channels"
    with pytest.raises(RpcError, match=failmsg):
        l1.rpc.call("renepay", {"invstring": inv})
    node_factory.join_nodes([l1, l2, l4], wait_for_announce=True, fundamount=1000000)
    node_factory.join_nodes([l1, l3, l5], wait_for_announce=True, fundamount=1000000)

    failmsg = r"Destination is unknown in the network gossip."
    with pytest.raises(RpcError, match=failmsg):
        l1.rpc.call("renepay", {"invstring": inv})

    l4.rpc.connect(l6.info["id"], "localhost", l6.port)
    l5.rpc.connect(l6.info["id"], "localhost", l6.port)

    scid46, _ = l4.fundchannel(l6, 10**6, wait_for_active=False)
    scid56, _ = l5.fundchannel(l6, 10**6, wait_for_active=False)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5, l6])

    l1.daemon.wait_for_logs(
        [
            r"update for channel {}/0 now ACTIVE".format(scid46),
            r"update for channel {}/1 now ACTIVE".format(scid46),
            r"update for channel {}/0 now ACTIVE".format(scid56),
            r"update for channel {}/1 now ACTIVE".format(scid56),
        ]
    )
    details = l1.rpc.call("renepay", {"invstring": inv})
    assert details["status"] == "complete"
    assert details["amount_msat"] == send_amount
    assert details["destination"] == l6.info["id"]

    # Test error from final node.
    with pytest.raises(RpcError) as err:
        l1.rpc.call("renepay", {"invstring": inv_deleted})

    PAY_DESTINATION_PERM_FAIL = 203
    assert err.value.error["code"] == PAY_DESTINATION_PERM_FAIL
    assert "WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS" in err.value.error["message"]


@pytest.mark.openchannel("v1")
@pytest.mark.openchannel("v2")
def test_pay(node_factory):
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(123000, "test_pay", "description")["bolt11"]
    before = int(time.time())
    details = l1.rpc.call("renepay", {"invstring": inv, "dev_use_shadow": False})
    after = time.time()
    preimage = details["payment_preimage"]
    assert details["status"] == "complete"
    assert details["amount_msat"] == Millisatoshi(123000)
    assert details["destination"] == l2.info["id"]
    assert details["created_at"] >= before
    assert details["created_at"] <= after

    invoices = l2.rpc.listinvoices("test_pay")["invoices"]
    assert len(invoices) == 1
    invoice = invoices[0]
    assert (
        invoice["status"] == "paid"
        and invoice["paid_at"] >= before
        and invoice["paid_at"] <= after
    )

    # Repeat payments are NOPs (if valid): we can hand null.
    l1.rpc.call("renepay", {"invstring": inv, "dev_use_shadow": False})
    # This won't work: can't provide an amount (even if correct!)
    with pytest.raises(RpcError):
        l1.rpc.call("renepay", {"invstring": inv, "amount_msat": 123000})
    with pytest.raises(RpcError):
        l1.rpc.call("renepay", {"invstring": inv, "amount_msat": 122000})

    # Check pay_index is not null
    outputs = l2.db_query(
        'SELECT pay_index IS NOT NULL AS q FROM invoices WHERE label="label";'
    )
    assert len(outputs) == 1 and outputs[0]["q"] != 0

    # Check payment of any-amount invoice.
    for i in range(5):
        label = "any{}".format(i)
        inv2 = l2.rpc.invoice("any", label, "description")["bolt11"]
        # Must provide an amount!
        with pytest.raises(RpcError):
            l1.rpc.call("renepay", {"invstring": inv2, "dev_use_shadow": False})

        l1.rpc.call(
            "renepay",
            {
                "invstring": inv2,
                "dev_use_shadow": False,
                "amount_msat": random.randint(1000, 999999),
            },
        )

    # Should see 6 completed payments
    assert len(l1.rpc.listsendpays()["payments"]) == 6

    # Test listsendpays indexed by bolt11.
    payments = l1.rpc.listsendpays(inv)["payments"]
    assert len(payments) == 1 and payments[0]["payment_preimage"] == preimage

    # Make sure they're completely settled, so accounting correct.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()["channels"])["htlcs"] == [])

    # Check channels apy summary view of channel activity
    apys_1 = l1.rpc.bkpr_channelsapy()["channels_apy"]
    apys_2 = l2.rpc.bkpr_channelsapy()["channels_apy"]

    assert (
        apys_1[0]["channel_start_balance_msat"]
        == apys_2[0]["channel_start_balance_msat"]
    )
    assert (
        apys_1[0]["channel_start_balance_msat"] == apys_1[0]["our_start_balance_msat"]
    )
    assert apys_2[0]["our_start_balance_msat"] == Millisatoshi(0)
    assert apys_1[0]["routed_out_msat"] == apys_2[0]["routed_in_msat"]
    assert apys_1[0]["routed_in_msat"] == apys_2[0]["routed_out_msat"]


def test_amounts(node_factory):
    """
    Check that the amount received matches the amount requested in the invoice.
    """
    l1, l2 = node_factory.line_graph(2)
    inv = l2.rpc.invoice(Millisatoshi(123456), "test_pay_amounts", "description")[
        "bolt11"
    ]

    invoice = only_one(l2.rpc.listinvoices("test_pay_amounts")["invoices"])

    assert invoice["amount_msat"] == Millisatoshi(123456)

    l1.rpc.call("renepay", {"invstring": inv, "dev_use_shadow": False})

    invoice = only_one(l2.rpc.listinvoices("test_pay_amounts")["invoices"])
    assert invoice["amount_received_msat"] >= Millisatoshi(123456)


def test_limits(node_factory):
    """
    Topology:
    1----2----4
    |         |
    3----5----6
    Try the error messages when paying when:
    - the fees are too high,
    - CLTV delay is too high,
    - probability of success is too low.
    """
    opts = [
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 100},
    ]
    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=opts * 6)
    node_factory.join_nodes(
        [l1, l2, l4, l6], wait_for_announce=True, fundamount=1000000
    )
    node_factory.join_nodes(
        [l1, l3, l5, l6], wait_for_announce=True, fundamount=1000000
    )

    inv = l4.rpc.invoice("any", "any", "description")
    l2.rpc.call("pay", {"bolt11": inv["bolt11"], "amount_msat": 500000000})
    inv = l5.rpc.invoice("any", "any", "description")
    l3.rpc.call("pay", {"bolt11": inv["bolt11"], "amount_msat": 500000000})

    # FIXME: pylightning should define these!
    # PAY_STOPPED_RETRYING = 210
    PAY_ROUTE_TOO_EXPENSIVE = 206

    inv = l6.rpc.invoice("any", "any", "description")

    # Fee too high.
    failmsg = r"Fee exceeds our fee budget"
    with pytest.raises(RpcError, match=failmsg) as err:
        l1.rpc.call(
            "renepay", {"invstring": inv["bolt11"], "amount_msat": 1000000, "maxfee": 1}
        )
    assert err.value.error["code"] == PAY_ROUTE_TOO_EXPENSIVE
    # TODO(eduardo): which error code shall we use here?

    # TODO(eduardo): shall we list attempts in renepay?
    # status = l1.rpc.call('renepaystatus', {'invstring':inv['bolt11']})['paystatus'][0]['attempts']

    failmsg = r"CLTV delay exceeds our CLTV budget"
    # Delay too high.
    with pytest.raises(RpcError, match=failmsg) as err:
        l1.rpc.call(
            "renepay",
            {"invstring": inv["bolt11"], "amount_msat": 1000000, "maxdelay": 0},
        )
    assert err.value.error["code"] == PAY_ROUTE_TOO_EXPENSIVE

    inv2 = l6.rpc.invoice("800000sat", "inv2", "description")
    l1.rpc.call("renepay", {"invstring": inv2["bolt11"]})
    invoice = only_one(l6.rpc.listinvoices("inv2")["invoices"])
    assert invoice["amount_received_msat"] >= Millisatoshi("800000sat")


def start_channels(connections):
    nodes = list()
    for src, dst, fundamount in connections:
        nodes.append(src)
        nodes.append(dst)
        src.rpc.connect(dst.info["id"], "localhost", dst.port)

    bitcoind = nodes[0].bitcoin
    # If we got here, we want to fund channels
    for src, dst, fundamount in connections:
        addr = src.rpc.newaddr()["bech32"]
        bitcoind.rpc.sendtoaddress(addr, (fundamount + 1000000) / 10**8)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, nodes)
    txids = []
    for src, dst, fundamount in connections:
        txids.append(
            src.rpc.fundchannel(dst.info["id"], fundamount, announce=True)["txid"]
        )

    # Confirm all channels and wait for them to become usable
    bitcoind.generate_block(1, wait_for_mempool=txids)
    scids = []
    for src, dst, fundamount in connections:
        wait_for(lambda: src.channel_state(dst) == "CHANNELD_NORMAL")
        scid = src.get_channel_scid(dst)
        scids.append(scid)

    # Make sure they have all seen block so they don't complain about
    # the coming gossip messages
    sync_blockheight(bitcoind, nodes)

    bitcoind.generate_block(5)

    # Make sure everyone sees all channels, all other nodes
    for n in nodes:
        for scid in scids:
            n.wait_channel_active(scid)

    # Make sure we have all node announcements, too
    for n in nodes:
        for n2 in nodes:
            wait_for(
                lambda: "alias" in only_one(n.rpc.listnodes(n2.info["id"])["nodes"])
            )


def test_hardmpp(node_factory):
    """
    Topology:
    1----2----4
    |         |
    3----5----6
    This a payment that fails if pending HTLCs are not taken into account when
    we build the network capacities.
    """
    opts = [
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
    ]
    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=opts * 6)
    start_channels(
        [
            (l1, l2, 10000000),
            (l2, l4, 3000000),
            (l4, l6, 10000000),
            (l1, l3, 10000000),
            (l3, l5, 1000000),
            (l5, l6, 10000000),
        ]
    )

    with open("/tmp/l1-chans.txt", "w") as f:
        print(json.dumps(l1.rpc.listchannels()), file=f)

    inv = l4.rpc.invoice("any", "any", "description")
    l2.rpc.call("pay", {"bolt11": inv["bolt11"], "amount_msat": 2000000000})
    l2.wait_for_htlcs()
    assert l4.rpc.listinvoices()["invoices"][0]["amount_received_msat"] == 2000000000

    with open("/tmp/l2-peerchan.txt", "w") as f:
        print(json.dumps(l2.rpc.listpeerchannels()), file=f)
    with open("/tmp/l3-peerchan.txt", "w") as f:
        print(json.dumps(l3.rpc.listpeerchannels()), file=f)

    inv2 = l6.rpc.invoice("1800000sat", "inv2", "description")

    out = subprocess.check_output(
        [
            "cli/lightning-cli",
            "--network={}".format(TEST_NETWORK),
            "--lightning-dir={}".format(l1.daemon.lightning_dir),
            "-k",
            "renepay",
            "invstring={}".format(inv2["bolt11"]),
        ]
    ).decode("utf-8")
    lines = out.split("\n")
    # First comes commentry
    assert any([l.startswith("#") for l in lines])

    # Now comes JSON
    json.loads("".join([l for l in lines if not l.startswith("#")]))
    l1.wait_for_htlcs()
    invoice = only_one(l6.rpc.listinvoices("inv2")["invoices"])
    assert invoice["amount_received_msat"] >= Millisatoshi("1800000sat")


def test_self_pay(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    inv = l1.rpc.invoice(10000, "test", "test")["bolt11"]
    l1.rpc.call("renepay", {"invstring": inv})

    # We can pay twice, no problem!
    l1.rpc.call("renepay", {"invstring": inv})

    inv2 = l1.rpc.invoice(10000, "test2", "test2")["bolt11"]
    l1.rpc.delinvoice("test2", "unpaid")

    with pytest.raises(RpcError, match=r"Unknown invoice") as excinfo:
        l1.rpc.call("renepay", {"invstring": inv2})
    assert excinfo.value.error["code"] == 203


def test_fee_allocation(node_factory):
    """
    Topology:
    1----2
    |    |
    3----4
    This a payment that fails if fee is not allocated as part of the flow
    constraints.
    """
    # High fees at 3%
    opts = [
        {"disable-mpp": None, "fee-base": 1000, "fee-per-satoshi": 30000},
    ]
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts * 4)
    start_channels(
        [(l1, l2, 1000000), (l2, l4, 2000000), (l1, l3, 1000000), (l3, l4, 2000000)]
    )

    inv = l4.rpc.invoice("1500000sat", "inv", "description")
    l1.rpc.call("renepay", {"invstring": inv["bolt11"], "maxfee": "75000sat"})
    l1.wait_for_htlcs()
    invoice = only_one(l4.rpc.listinvoices("inv")["invoices"])
    assert invoice["amount_received_msat"] >= Millisatoshi("1500000sat")


def test_htlc_max(node_factory):
    """
    Topology:
    1----2----4
    |         |
    3----5----6
    """
    opts = [
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
        {
            "disable-mpp": None,
            "fee-base": 0,
            "fee-per-satoshi": 0,
            "htlc-maximum-msat": 500000000,
        },
        {
            "disable-mpp": None,
            "fee-base": 0,
            "fee-per-satoshi": 0,
            "htlc-maximum-msat": 500000000,
        },
        {"disable-mpp": None, "fee-base": 0, "fee-per-satoshi": 0},
    ]
    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=opts)
    start_channels(
        [
            (l1, l2, 10000000),
            (l2, l4, 1000000),
            (l4, l6, 2000000),
            (l1, l3, 10000000),
            (l3, l5, 1000000),
            (l5, l6, 2000000),
        ]
    )

    inv = l6.rpc.invoice("1800000sat", "inv", "description")

    l1.rpc.call("renepay", {"invstring": inv["bolt11"]})
    l1.wait_for_htlcs()
    invoice = only_one(l6.rpc.listinvoices("inv")["invoices"])
    assert invoice["amount_received_msat"] >= Millisatoshi("1800000sat")


def test_previous_sendpays(node_factory, bitcoind):
    """
    Check that renepay can complete a payment that already started
    """
    opts = [
        {"disable-mpp": None, "fee-base": 1000, "fee-per-satoshi": 1000},
    ]
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True, opts=opts * 4)

    # First case, do not overpay a pending MPP payment
    invstr = l3.rpc.invoice("100000sat", "inv1", "description")["bolt11"]
    inv = l1.rpc.decode(invstr)
    route = l1.rpc.call(
        "getroute", {"id": inv["payee"], "amount_msat": "50000sat", "riskfactor": 10}
    )
    # we start a MPP payment
    l1.rpc.call(
        "sendpay",
        {
            "route": route["route"],
            "payment_hash": inv["payment_hash"],
            "payment_secret": inv["payment_secret"],
            "amount_msat": "100000sat",
            "groupid": 1,
            "partid": 1,
        },
    )
    # while it is pending, we try to complete it with renepay
    l1.rpc.call("renepay", {"invstring": invstr})
    invoice = only_one(l3.rpc.listinvoices("inv1")["invoices"])
    # the receive amount should be exact
    assert invoice["amount_received_msat"] == Millisatoshi("100000sat")

    # Second case, do not collide with failed sendpays
    invstr = l3.rpc.invoice("100000sat", "inv2", "description")["bolt11"]
    inv = l1.rpc.decode(invstr)
    route = l1.rpc.call(
        "getroute", {"id": inv["payee"], "amount_msat": "50000sat", "riskfactor": 10}
    )

    # load a plugin that fails all HTLCs
    l2.rpc.call(
        "plugin",
        {
            "subcommand": "start",
            "plugin": os.path.join(os.getcwd(), "tests/plugins/fail_htlcs.py"),
        },
    )
    l2.daemon.wait_for_log(r"^(?=.*plugin-manager.*fail_htlcs.py).*")

    # start a MPP payment that will fail at l2
    l1.rpc.call(
        "sendpay",
        {
            "route": route["route"],
            "payment_hash": inv["payment_hash"],
            "payment_secret": inv["payment_secret"],
            "amount_msat": "100000sat",
            "groupid": 1,
            "partid": 1,
        },
    )
    l2.daemon.wait_for_log(r"Failing htlc on purpose")
    l1.wait_for_htlcs()

    # another payment that fails
    l1.rpc.call(
        "sendpay",
        {
            "route": route["route"],
            "payment_hash": inv["payment_hash"],
            "payment_secret": inv["payment_secret"],
            "amount_msat": "100000sat",
            "groupid": 2,
            "partid": 1,
        },
    )
    l2.daemon.wait_for_log(r"Failing htlc on purpose")
    l1.wait_for_htlcs()

    # unload the fail_htlcs plugin
    l2.rpc.call("plugin", {"subcommand": "stop", "plugin": "fail_htlcs.py"})
    l2.daemon.wait_for_log(
        r"plugin-fail_htlcs.py: Killing plugin: stopped by lightningd via RPC"
    )

    # now renepay should be able to construct new sendpays that do not collide
    # with the previously failed sendpays
    l1.rpc.call("renepay", {"invstring": invstr, "dev_use_shadow": False})
    invoice = only_one(l3.rpc.listinvoices("inv2")["invoices"])
    assert invoice["amount_received_msat"] == Millisatoshi("100000sat")


def test_fees(node_factory):
    """
    Check that fees are correctly computed.
    """
    # made up some random fees for every node
    opts = [
        {"disable-mpp": None, "fee-base": 1000, "fee-per-satoshi": 100},
        {"disable-mpp": None, "fee-base": 2222, "fee-per-satoshi": 203},
        {"disable-mpp": None, "fee-base": 3333, "fee-per-satoshi": 300},
        {"disable-mpp": None, "fee-base": 2012, "fee-per-satoshi": 200},
        {"disable-mpp": None, "fee-base": 1010, "fee-per-satoshi": 100},
        {"disable-mpp": None, "fee-base": 1050, "fee-per-satoshi": 100},
    ]
    nodes = node_factory.line_graph(len(opts), wait_for_announce=True, opts=opts)
    source = nodes[0]
    dest = nodes[-1]

    # check that once gossip is in sync, fees are paid correctly
    invstr = dest.rpc.invoice("100000sat", "inv1", "description")["bolt11"]
    source.rpc.call("renepay", {"invstring": invstr})
    invoice = only_one(dest.rpc.listinvoices("inv1")["invoices"])
    assert invoice["amount_received_msat"] == Millisatoshi("100000sat")

    # if we update fee policy but gossip is not updated ...
    nodes[2].rpc.dev_suppress_gossip()
    nodes[2].rpc.setchannel(nodes[3].info["id"], 4000, 300, enforcedelay=0)

    nodes[3].rpc.dev_suppress_gossip()
    nodes[3].rpc.setchannel(nodes[4].info["id"], 3000, 350, enforcedelay=0)

    invstr = dest.rpc.invoice("150000sat", "inv2", "description")["bolt11"]
    source.rpc.call("renepay", {"invstring": invstr})
    invoice = only_one(dest.rpc.listinvoices("inv2")["invoices"])
    assert invoice["amount_received_msat"] == Millisatoshi("150000sat")


def test_local_htlcmax0(node_factory):
    """Testing a simple pay route when local channels have htlcmax=0."""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)
    l1.rpc.setchannel(l2.info["id"], htlcmax=0)
    inv = l3.rpc.invoice(123000, "test_renepay", "description")["bolt11"]
    details = l1.rpc.call("renepay", {"invstring": inv})
    assert details["status"] == "complete"
    assert details["amount_msat"] == Millisatoshi(123000)
    assert details["destination"] == l3.info["id"]
