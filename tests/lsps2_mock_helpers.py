"""Helpers for tests against the mock LSPS2 service (plugins/lsps2_mock.py)."""

from pyln.client import RpcError
from utils import only_one, wait_for
import json
import os

LSPS2_MOCK = os.path.join(os.path.dirname(__file__), "plugins/lsps2_mock.py")


def lsps2_mock_nodes(node_factory, client_opts=None):
    """Client l1, LSP l2 running the mock service, payer l3.

    l3 has a public channel to l2; l1 is only connected to l2.
    `client_opts` are added to l1's options.
    """
    l1, l2, l3 = node_factory.get_nodes(
        3,
        opts=[
            {"experimental-lsps-client": None, **(client_opts or {})},
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


def lsps2_mock_menu_entry(min_fee_msat, proportional=0):
    return {
        "min_fee_msat": str(min_fee_msat),
        "proportional": proportional,
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


def lsps2_mock_configure(lsp, **config):
    """Replace the config of the mock on `lsp`, one keyword per phase."""
    lsp.rpc.call("lsps2-mock-configure", {"config": config})


def lsps2_mock_pay_parts(l1, l2, l3, inv, part_amounts, scid=None, cltv_delta=144):
    """l3 pays `inv` (as returned by l1's invoice commands) to l1 through
    l2, in one part per amount in `part_amounts`, over the invoice's single
    route hint or over `scid` with `cltv_delta`.

    Returns per part the result of waitsendpay or the RpcError it raised."""
    dec = l3.rpc.decode(inv["bolt11"])
    if scid is None:
        routehint = only_one(only_one(dec["routes"]))
        scid = routehint["short_channel_id"]
        cltv_delta = routehint["cltv_expiry_delta"]
    chanid = only_one(l3.rpc.listpeerchannels(l2.info["id"])["channels"])[
        "short_channel_id"
    ]
    for partid, amt in enumerate(part_amounts, start=1):
        route = [
            {
                "amount_msat": amt,
                "id": l2.info["id"],
                "delay": cltv_delta + 6,
                "channel": chanid,
            },
            {"amount_msat": amt, "id": l1.info["id"], "delay": 6, "channel": scid},
        ]
        l3.rpc.sendpay(
            route,
            dec["payment_hash"],
            payment_secret=inv["payment_secret"],
            bolt11=inv["bolt11"],
            amount_msat=sum(part_amounts),
            groupid=1,
            partid=partid,
        )
    results = []
    for partid in range(1, len(part_amounts) + 1):
        try:
            results.append(
                l3.rpc.waitsendpay(dec["payment_hash"], partid=partid, groupid=1)
            )
        except RpcError as e:
            results.append(e)
    return results
