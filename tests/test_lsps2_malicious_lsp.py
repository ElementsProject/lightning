"""Tests of the LSPS2 client against a misbehaving LSP.

In each case the mock service on the LSP misbehaves in one way; the test
checks how the client reacts and then the oracles in lsps2_oracles.py.
"""

from fixtures import *  # noqa: F401,F403
from lsps2_mock_helpers import (
    LSPS2_MOCK,
    lsps2_mock_configure,
    lsps2_mock_events,
    lsps2_mock_forwards,
    lsps2_mock_menu_entry,
    lsps2_mock_nodes,
    lsps2_mock_pay_parts,
)
from lsps2_oracles import check_oracles, lsps2_mock_fee
from pyln.client import RpcError
from utils import only_one
import json
import pytest


# A 1% opening fee, well above the minimum fee for the payment below.
MENU = [lsps2_mock_menu_entry(1000, proportional=10_000)]
AMT = 10_000_000
FEE = 100_000
assert lsps2_mock_fee.opening_fee(AMT, 1000, 10_000) == FEE

LABEL = "lsp-jit-channel-0"


def jit_invoice(l1, l2, amount_msat="any", label=LABEL):
    return l1.rpc.lsps_lsps2_invoice(
        lsp_id=l2.info["id"], amount_msat=amount_msat, description=label, label=label
    )


def invoice(l1, label=LABEL):
    return only_one(l1.rpc.listinvoices(label)["invoices"])


def assert_paid(l1, results):
    assert all("payment_preimage" in r for r in results), results
    assert invoice(l1)["status"] == "paid"


def assert_failed(l1, results):
    assert all(isinstance(r, RpcError) for r in results), results
    assert invoice(l1)["status"] == "unpaid"


def scenario(name, slow=False, **fields):
    """A test case named `name`; `slow` marks it slow_test."""
    marks = []
    if slow:
        marks.append(pytest.mark.slow_test)
    return pytest.param(fields, id=name, marks=marks)


# --- JSON-RPC and transport -----------------------------------------------


def client_and_lsp(node_factory):
    """Client l1 connected to l2 running the mock, without a channel."""
    return node_factory.line_graph(
        2,
        fundchannel=False,
        opts=[{"experimental-lsps-client": None}, {"plugin": LSPS2_MOCK}],
    )


def honest_menu(res):
    return len(res["opening_fee_params_menu"]) == 1


def timed_out(err):
    return err is not None and "Timeout" in err.error["message"]


# A response for no request.
UNSOLICITED = {
    "jsonrpc": "2.0",
    "id": "mock-unsolicited",
    "result": {"opening_fee_params_menu": []},
}

# The largest LSPS0 message (BOLT 8 payload minus the message type).
MAX_PAYLOAD = 65533
NESTED_JSON = "[" * (MAX_PAYLOAD // 2) + "]" * (MAX_PAYLOAD // 2) + " "
GARBAGE = ("not json: {[" * MAX_PAYLOAD)[:MAX_PAYLOAD]


def menu_entry_with(**fields):
    return {"get_info": {"menu": [{**lsps2_mock_menu_entry(1000), **fields}]}}


def error_config(code, message):
    return {"transport": {"behavior": "error", "error": {"code": code, "message": message}}}


# Each scenario: the mock sends each of `send` unsolicited, then the client
# calls lsps-lsps2-getinfo with the mock configured by `config`;
# `check(l1, result, error)` judges the outcome. Afterwards the client must
# still get an honest menu.
TRANSPORT_CASES = [
    # A response with another request's id: the request times out.
    scenario(
        "wrong-id",
        slow=True,
        config={"transport": {"behavior": "wrong_id"}},
        check=lambda l1, res, err: timed_out(err),
    ),
    # A response to no request is ignored and creates no session.
    scenario(
        "unsolicited",
        send=[json.dumps(UNSOLICITED)],
        check=lambda l1, res, err: (
            honest_menu(res) and l1.rpc.listdatastore(["lsps"])["datastore"] == []
        ),
    ),
    # Only the first of two responses counts.
    scenario(
        "duplicate",
        config={
            "transport": {
                "behavior": "duplicate",
                "change": {"opening_fee_params_menu": []},
            }
        },
        check=lambda l1, res, err: honest_menu(res),
    ),
    # A negative msat, or one above u64: a clean error.
    scenario(
        "msat-negative",
        config=menu_entry_with(min_fee_msat="-1000"),
        check=lambda l1, res, err: err is not None and not timed_out(err),
    ),
    scenario(
        "msat-overflow",
        config=menu_entry_with(min_fee_msat="18446744073709551616"),
        check=lambda l1, res, err: err is not None and not timed_out(err),
    ),
    # Unknown keys in a result are ignored (bLIP-50).
    scenario(
        "unknown-fields",
        config={
            "transport": {
                "behavior": "add_fields",
                "fields": {"x-mock-extension": {"nested": [1, 2]}},
            }
        },
        check=lambda l1, res, err: honest_menu(res),
    ),
    # A full-size message of garbage or deeply nested JSON is ignored.
    scenario(
        "garbage",
        send=[GARBAGE],
        check=lambda l1, res, err: honest_menu(res),
    ),
    scenario(
        "nested-json",
        send=[NESTED_JSON],
        check=lambda l1, res, err: honest_menu(res),
    ),
    # No response: the request times out.
    scenario(
        "no-response",
        slow=True,
        config={"transport": {"behavior": "drop"}},
        check=lambda l1, res, err: timed_out(err),
    ),
    # An error with a huge message does not fill the log.
    scenario(
        "huge-error-log",
        config=error_config(-32603, "x" * 60_000),
        check=lambda l1, res, err: not l1.daemon.is_in_log("x" * 10_000),
    ),
]


@pytest.mark.parametrize("case", TRANSPORT_CASES)
def test_lsps2_bad_transport(node_factory, case):
    l1, l2 = client_and_lsp(node_factory)
    for payload in case.get("send", []):
        l2.rpc.call("lsps2-mock-send", {"peer_id": l1.info["id"], "payload": payload})
    lsps2_mock_configure(l2, **case.get("config", {}))
    try:
        res, err = l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"]), None
    except RpcError as e:
        res, err = None, e

    # lightningd hands the client one message from a peer at a time, so the
    # mock's messages above were handled once this request is answered.
    lsps2_mock_configure(l2)
    assert honest_menu(l1.rpc.lsps_lsps2_getinfo(lsp_id=l2.info["id"]))
    check_oracles(l1, l2)
    assert case["check"](l1, res, err), (res, err)


# --- fee deduction and HTLC amounts ----------------------------------------


def deduct(deductions, extra_fees=None):
    return {"behavior": "deduct", "deductions": deductions, "extra_fees": extra_fees}


# 10_000_001 msat at 1000 ppm is 10_000.001 msat; the fee rounds up.
ROUNDING_MENU = [lsps2_mock_menu_entry(1000, proportional=1000)]
ROUNDING_AMT = 10_000_001
ROUNDING_FEE = 10_001
assert lsps2_mock_fee.opening_fee(ROUNDING_AMT, 1000, 1000) == ROUNDING_FEE

# Each scenario is a payment of `amt` through the mock with the htlc phase
# `htlc`: a variable-amount invoice paid in one part, or with `parts` a
# fixed invoice paid in those parts. `paid` is whether the client must
# accept it; `check(l1, l2)` checks more.
FEE_DEDUCTION_CASES = [
    # 1 msat more than the fee, with a matching extra_fee, on a fixed
    # invoice: the parts fall 1 msat short of the invoice amount minus the
    # fee and time out.
    scenario(
        "fee-plus-one-fixed-invoice",
        slow=True,
        htlc=deduct([FEE + 1]),
        parts=[AMT // 2] * 2,
    ),
    # A fee that rounds up is accepted exactly.
    scenario(
        "fee-rounded-up",
        htlc={"behavior": "honest"},
        menu=ROUNDING_MENU,
        amt=ROUNDING_AMT,
        paid=True,
        check=lambda l1, l2: (
            only_one(lsps2_mock_forwards(l2))["extra_fee_msat"] == ROUNDING_FEE
            and invoice(l1)["amount_received_msat"] == ROUNDING_AMT - ROUNDING_FEE
        ),
    ),
    # The fee spread evenly over four parts, each with its extra_fee.
    scenario(
        "fee-over-parts",
        htlc=deduct([FEE // 4] * 4),
        parts=[AMT // 4] * 4,
        paid=True,
        check=lambda l1, l2: (
            [f["extra_fee_msat"] for f in lsps2_mock_forwards(l2)] == [FEE // 4] * 4
        ),
    ),
    # Deductions over the parts adding up to 1 msat more than the fee.
    scenario(
        "fee-over-parts-plus-one",
        slow=True,
        htlc=deduct([FEE // 2, FEE // 2 + 1]),
        parts=[AMT // 4] * 4,
    ),
    # Only two of four parts forwarded; the client times them out.
    scenario(
        "forward-subset",
        slow=True,
        htlc={"behavior": "forward_subset", "parts": [0, 1]},
        parts=[AMT // 4] * 4,
        check=lambda l1, l2: len(lsps2_mock_forwards(l2)) == 2,
    ),
    # The fee taken again on a later payment takes two payments; see
    # test_lsps2_fee_deducted_again.

    # The payer sends 4% more than the fixed invoice asks; the fee is the
    # one for the payment size.
    scenario(
        "overpaid",
        htlc={"behavior": "honest"},
        parts=[AMT // 4 + AMT // 100] * 4,
        paid=True,
        check=lambda l1, l2: (
            invoice(l1)["amount_received_msat"] == AMT + AMT // 25 - FEE
        ),
    ),
]


@pytest.mark.parametrize("case", FEE_DEDUCTION_CASES)
def test_lsps2_bad_fee_deduction(node_factory, case):
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    lsps2_mock_configure(
        l2, get_info={"menu": case.get("menu", MENU)}, htlc=case["htlc"]
    )
    amt = case.get("amt", AMT)
    if "parts" in case:
        inv, parts = jit_invoice(l1, l2, amt), case["parts"]
    else:
        inv, parts = jit_invoice(l1, l2), [amt]
    results = lsps2_mock_pay_parts(l1, l2, l3, inv, parts)

    check_oracles(l1, l2)
    if case.get("paid", False):
        assert_paid(l1, results)
    else:
        assert_failed(l1, results)
    assert case.get("check", lambda l1, l2: True)(l1, l2)


def test_lsps2_fee_deducted_again(node_factory):
    """After the JIT payment, the LSP deducts the fee again from a
    payment over the same jit_channel_scid. The client fails it."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    lsps2_mock_configure(l2, get_info={"menu": MENU})
    assert_paid(l1, lsps2_mock_pay_parts(l1, l2, l3, jit_invoice(l1, l2), [AMT]))

    lsps2_mock_configure(l2, get_info={"menu": MENU}, htlc={"behavior": "deduct_again"})
    scid = only_one(lsps2_mock_events(l2, "buy"))["jit_channel_scid"]
    inv = l1.rpc.invoice(AMT // 2, "second", "second")
    results = lsps2_mock_pay_parts(l1, l2, l3, inv, [AMT // 2], scid=scid)

    check_oracles(l1, l2)
    assert all(isinstance(r, RpcError) for r in results), results
    assert invoice(l1, "second")["status"] == "unpaid"
    assert lsps2_mock_forwards(l2)[-1]["extra_fee_msat"] == FEE
