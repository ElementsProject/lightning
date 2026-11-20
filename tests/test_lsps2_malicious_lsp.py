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
from concurrent import futures
from utils import only_one, wait_for
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


# --- get_info and opening fee params ---------------------------------------


def menu(*entries):
    """A menu of `entries`, each overriding fields of a usable entry; entry i
    has the promise "entry-i" unless it sets its own."""
    return [
        {**lsps2_mock_menu_entry(1000), "promise": f"entry-{i}", **entry}
        for i, entry in enumerate(entries)
    ]


def without(entry, field):
    return {k: v for k, v in entry.items() if k != field}


def buy_requests(l2):
    requests = [json.loads(e["payload"]) for e in lsps2_mock_events(l2, "rx")]
    return [r["params"] for r in requests if r.get("method") == "lsps2.buy"]


PAST = "2020-01-01T00:00:00.000Z"
U64_MAX = str(2**64 - 1)

# The largest menu that fits one LSPS0 message: all but the last entry
# expired, so the client has to read to the end.
FULL_MENU_ENTRIES = 1
while len(json.dumps(
    {
        "jsonrpc": "2.0",
        "id": "x" * 64,
        "result": {"opening_fee_params_menu": menu(*[{"valid_until": PAST}] * (FULL_MENU_ENTRIES + 1))},
    }
)) <= MAX_PAYLOAD:
    FULL_MENU_ENTRIES += 1
FULL_MENU = menu(*[{"valid_until": PAST}] * (FULL_MENU_ENTRIES - 1), {})

# Every printable ASCII character but '"' and '\'.
PRINTABLE_PROMISE = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) not in '"\\')

# The mock answers at once, so an invoice call that takes this long hangs.
INVOICE_TIMEOUT_SECS = 30

# Each scenario: the mock serves `menu`, with `get_info` config on top, and
# the client asks for a JIT invoice of `amount`. `buy` is the index of the
# entry the client must buy, or None if it must abort before buying.
FEE_PARAMS_CASES = [
    # An expired entry is not used.
    scenario("expired", menu=menu({"valid_until": PAST}), buy=None),
    scenario("expired-then-valid", menu=menu({"valid_until": PAST}, {}), buy=1),
    # An entry expiring within the client's margin of a minute, so it could
    # expire before buy.
    scenario("expiring-soon", menu=menu({}), get_info={"valid_for_seconds": 30}, buy=None),
    # A minimum payment size above the maximum.
    scenario("inverted-limits", menu=menu({"min_payment_size_msat": "100000001"}), buy=None),
    scenario(
        "inverted-then-valid",
        menu=menu({"min_payment_size_msat": "100000001"}, {}),
        buy=1,
    ),
    # A fee that is all of the payment.
    scenario("fee-is-payment", menu=menu({"proportional": 1_000_000}), amount=AMT, buy=None),
    # A fee that overflows u64.
    scenario(
        "fee-overflow",
        menu=menu(
            {
                "min_fee_msat": "0",
                "proportional": 2**32 - 1,
                "max_payment_size_msat": U64_MAX,
            }
        ),
        amount=2**33,
        buy=None,
    ),
    # A large max_client_to_self_delay is fine: it only lengthens the
    # client's punishment window.
    scenario("large-self-delay", menu=menu({"max_client_to_self_delay": 50_000}), buy=0),
    # A min_lifetime of 0 is a commercial term; accept.
    scenario("zero-min-lifetime", menu=menu({"min_lifetime": 0}), buy=0),
    # A menu filling a whole message.
    scenario("full-message-menu", menu=FULL_MENU, buy=FULL_MENU_ENTRIES - 1),
    # A promise over 512 bytes aborts the flow, even in an entry the client
    # would not pick; 512 bytes are fine.
    scenario("long-promise", menu=menu({"promise": "x" * 513}), buy=None),
    scenario("long-promise-unpicked", menu=menu({}, {"promise": "x" * 513}), buy=None),
    scenario("promise-512-bytes", menu=menu({"promise": "x" * 512}), buy=0),
    # A promise with a character outside 0x20-0x7E, '"' or '\' aborts the
    # flow; any other is echoed as it is.
    scenario("promise-quote", menu=menu({"promise": 'a"b'}), buy=None),
    scenario("promise-backslash", menu=menu({"promise": "a\\b"}), buy=None),
    scenario("promise-non-ascii", menu=menu({"promise": "caf\u00e9"}), buy=None),
    scenario("promise-control", menu=menu({"promise": "a\x7fb"}), buy=None),
    scenario("promise-printable", menu=menu({"promise": PRINTABLE_PROMISE}), buy=0),
    # Two entries alike but for the promise.
    scenario("duplicate-entries", menu=menu({}, {}), buy=0),
    # An entry missing a field, or with a field bLIP-52 does not define, is
    # not used.
    scenario("missing-field", menu=[without(menu({})[0], "min_lifetime")], buy=None),
    scenario("extra-field", menu=menu({"x-extra": 1}), buy=None),
]


@pytest.mark.parametrize("case", FEE_PARAMS_CASES)
def test_lsps2_bad_fee_params(node_factory, executor, case):
    l1, l2 = client_and_lsp(node_factory)
    entries = case["menu"]
    lsps2_mock_configure(l2, get_info={"menu": entries, **case.get("get_info", {})})
    fut = executor.submit(jit_invoice, l1, l2, case.get("amount", "any"))
    try:
        fut.result(INVOICE_TIMEOUT_SECS)
        err = None
    except RpcError as e:
        err = e
    except futures.TimeoutError:
        err = "no answer"

    check_oracles(l1, l2)
    buys = buy_requests(l2)
    if case["buy"] is None:
        assert isinstance(err, RpcError) and buys == [], (err, buys)
    else:
        assert err is None, err
        promise = only_one(buys)["opening_fee_params"]["promise"]
        assert promise == entries[case["buy"]]["promise"]


# --- buy, SCID and identity ------------------------------------------------


def no_invoice(l1, err):
    return isinstance(err, RpcError) and l1.rpc.listinvoices(LABEL)["invoices"] == []


def hint_scid(l1):
    routes = l1.rpc.decode(invoice(l1)["bolt11"])["routes"]
    return only_one(only_one(routes))["short_channel_id"]


def buy_transport(**transport):
    return {"transport": {**transport, "methods": ["lsps2.buy"]}}


# Each scenario: the client asks for a JIT invoice from the mock configured
# by `config`; `invoice` is whether it must get one, and `check(l1, l2)`
# checks more.
BUY_RESULT_CASES = [
    # A jit_channel_scid that is no SCID.
    scenario("scid-text", config={"buy": {"jit_channel_scid": "not-an-scid"}}, invoice=False),
    scenario("scid-short", config={"buy": {"jit_channel_scid": "1x2"}}, invoice=False),
    scenario(
        "scid-block-too-large",
        config={"buy": {"jit_channel_scid": "16777216x0x0"}},
        invoice=False,
    ),
    # An lsp_cltv_expiry_delta of 0 is fine.
    scenario("zero-cltv-delta", config={"buy": {"lsp_cltv_expiry_delta": 0}}, invoice=True),
    # "Invalid promise" for an unchanged promise: fail once, no retries.
    scenario(
        "invalid-promise-error",
        config=buy_transport(
            behavior="error",
            error={"code": 201, "message": "invalid_opening_fee_params"},
        ),
        invoice=False,
        check=lambda l1, l2: len(buy_requests(l2)) == 1,
    ),
    # A second buy result with another SCID: the first one counts.
    scenario(
        "second-buy-result",
        config=buy_transport(behavior="duplicate", change={"jit_channel_scid": "1x1x1"}),
        invoice=True,
        check=lambda l1, l2: (
            hint_scid(l1) == only_one(lsps2_mock_events(l2, "buy"))["jit_channel_scid"]
        ),
    ),
]


@pytest.mark.parametrize("case", BUY_RESULT_CASES)
def test_lsps2_bad_buy_result(node_factory, case):
    l1, l2 = client_and_lsp(node_factory)
    lsps2_mock_configure(l2, **case["config"])
    try:
        jit_invoice(l1, l2)
        err = None
    except RpcError as e:
        err = e

    check_oracles(l1, l2)
    if case["invoice"]:
        assert err is None, err
    else:
        assert no_invoice(l1, err), err
    assert case.get("check", lambda l1, l2: True)(l1, l2)


def unconfirmed_channels(l1, peer):
    return [
        c
        for c in l1.rpc.listpeerchannels(peer.info["id"])["channels"]
        if c["state"] == "CHANNELD_NORMAL" and "short_channel_id" not in c
    ]


@pytest.mark.parametrize("when", ["before", "after"])
def test_lsps2_open_outside_session(node_factory, when):
    """The LSP opens a zero-conf channel to the client outside a
    session, before any buy or after the session's channel. The client
    rejects it."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    if when == "after":
        lsps2_mock_configure(l2, get_info={"menu": MENU})
        results = lsps2_mock_pay_parts(l1, l2, l3, jit_invoice(l1, l2), [AMT])
        assert_paid(l1, results)

    with pytest.raises(RpcError):
        l2.rpc.call("lsps2-mock-open", {"peer_id": l1.info["id"]})
    check_oracles(l1, l2)
    assert len(unconfirmed_channels(l1, l2)) == (1 if when == "after" else 0)


def test_lsps2_second_open(node_factory):
    """The LSP opens a second zero-conf channel for the session. The
    client takes only the first."""
    l1, l2, l3 = lsps2_mock_nodes(node_factory)
    lsps2_mock_configure(l2, get_info={"menu": MENU}, open={"behavior": "twice"})
    assert_paid(l1, lsps2_mock_pay_parts(l1, l2, l3, jit_invoice(l1, l2), [AMT]))

    wait_for(lambda: lsps2_mock_events(l2, "open_failed"))
    check_oracles(l1, l2)
    assert len(unconfirmed_channels(l1, l2)) == 1


def test_lsps2_open_from_other_node(node_factory):
    """While the client has a session with the LSP, another node opens
    a zero-conf channel to it. The client rejects it."""
    l1, l2 = client_and_lsp(node_factory)
    l4 = node_factory.get_node()
    l4.fundwallet(1_000_000)
    l4.connect(l1)
    jit_invoice(l1, l2)

    with pytest.raises(RpcError):
        l4.rpc.fundchannel(
            l1.info["id"], 100_000, announce=False, mindepth=0, channel_type=[12, 46, 50]
        )
    check_oracles(l1, l2)
    assert unconfirmed_channels(l1, l4) == []


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
