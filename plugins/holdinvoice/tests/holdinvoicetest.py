#!/usr/bin/python

from pyln.testing.fixtures import *
from pyln.testing.utils import only_one, mine_funding_to_announce
import secrets
import threading
import time
import os
from util import generate_random_label
from util import generate_random_number
from util import pay_with_thread


def test_inputs(node_factory):
    node = node_factory.get_node(
        options={
            'important-plugin': os.path.join(
                os.getcwd(), '../../target/release/holdinvoice'
            )
        }
    )
    result = node.rpc.call("holdinvoice", {
        "amount_msat": 1000000,
        "description": "Valid invoice description",
        "label": generate_random_label()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    assert "payment_hash" in result

    result = node.rpc.call("holdinvoice", {
        "amount_msat": 1000000,
        "description": "",
        "label": generate_random_label()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    assert "payment_hash" in result

    result = node.rpc.call("holdinvoice", {
        "amount_msat": 1000000,
        "description": "Numbers only as label",
        "label": generate_random_number()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    assert "payment_hash" in result

    result = node.rpc.call("holdinvoice", {
        "description": "Missing amount",
        "label": generate_random_label()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    expected_message = ("missing required parameter: amount_msat|msatoshi")
    assert result["message"] == expected_message

    result = node.rpc.call("holdinvoice", {
        "amount_msat": 1000000,
        "description": "Missing label", }
    )
    assert result is not None
    assert isinstance(result, dict) is True
    assert result["message"] == "missing required parameter: label"

    result = node.rpc.call("holdinvoice", {
        "amount_msat": 1000000,
        "label": generate_random_label()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    assert result["message"] == "missing required parameter: description"

    random_hex = secrets.token_hex(32)
    result = node.rpc.call("holdinvoice", {
        "amount_msat": 2000000,
        "description": "Invoice with optional fields",
        "label": generate_random_label(),
        "expiry": 3600,
        "fallbacks": ["bcrt1qcpw242j4xsjth7ueq9dgmrqtxjyutuvmraeryr",
                      "bcrt1qdwydlys0f8khnp87mx688vq4kskjyr68nrx58j"],
        "preimage": random_hex,
        "cltv": 144,
        "deschashonly": True}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    assert "payment_hash" in result

    # Negative amount_msat
    result = node.rpc.call("holdinvoice", {
        "amount_msat": -1000,
        "description": "Invalid amount negative",
        "label": generate_random_label()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    expected_message = ("amount_msat|msatoshi: should be an unsigned "
                        "64 bit integer: invalid token '-1000'")
    assert result["message"] == expected_message

    # 0 amount_msat
    result = node.rpc.call("holdinvoice", {
        "amount_msat": 0,
        "description": "Invalid amount 0",
        "label": generate_random_label()}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    expected_message = ("amount_msat|msatoshi: should be positive msat"
                        " or 'any': invalid token '\"0msat\"'")
    assert result["message"] == expected_message

    # Negative expiry value
    result = node.rpc.call("holdinvoice", {
        "amount_msat": 500000,
        "description": "Invalid expiry",
        "label": generate_random_label(),
        "expiry": -3600}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    expected_message = ("expiry: should be an unsigned "
                        "64 bit integer: invalid token '-3600'")
    assert result["message"] == expected_message

    # Fallbacks not as a list of strings
    result = node.rpc.call("holdinvoice", {
        "amount_msat": 800000,
        "description": "Invalid fallbacks",
        "label": generate_random_label(),
        "fallbacks": "invalid_fallback"}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    expected_message = ("fallbacks: should be an array: "
                        "invalid token '\"invalid_fallback\"'")
    assert result["message"] == expected_message

    # Negative cltv value
    result = node.rpc.call("holdinvoice", {
        "amount_msat": 1200000,
        "description": "Invalid cltv",
        "label": generate_random_label(),
        "cltv": -144}
    )
    assert result is not None
    assert isinstance(result, dict) is True
    expected_message = ("cltv: should be an integer: "
                        "invalid token '-144'")
    assert result["message"] == expected_message


def test_valid_hold_then_settle(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2,
                                    opts={
                                        'important-plugin': os.path.join(
                                            os.getcwd(),
                                            '../../target/release/holdinvoice'
                                        )
                                    }
                                    )
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    cl1, _ = l1.fundchannel(l2, 1_000_000)
    cl2, _ = l1.fundchannel(l2, 1_000_000)

    l1.wait_local_channel_active(cl1)
    l1.wait_local_channel_active(cl2)

    invoice = l2.rpc.call("holdinvoice", {
        "amount_msat": 1_000_100_000,
        "description": "test_valid_hold_then_settle",
        "label": generate_random_label(),
        "cltv": 144}
    )
    assert invoice is not None
    assert isinstance(invoice, dict) is True
    assert "payment_hash" in invoice

    result_lookup = l2.rpc.call("holdinvoicelookup", {
        "payment_hash": invoice["payment_hash"]})
    assert result_lookup is not None
    assert isinstance(result_lookup, dict) is True
    assert "state" in result_lookup
    assert result_lookup["state"] == "open"
    assert "htlc_expiry" not in result_lookup

    # test that it won't settle if it's still open
    result_settle = l2.rpc.call("holdinvoicesettle", {
        "payment_hash": invoice["payment_hash"]})
    assert result_settle is not None
    assert isinstance(result_settle, dict) is True
    expected_message = ("Holdinvoice is in wrong state: 'open'")
    assert result_settle["message"] == expected_message

    threading.Thread(target=pay_with_thread, args=(
        l1.rpc, invoice["bolt11"])).start()

    timeout = 10
    start_time = time.time()

    while time.time() - start_time < timeout:
        result_lookup = l2.rpc.call("holdinvoicelookup", {
            "payment_hash": invoice["payment_hash"]})
        assert result_lookup is not None
        assert isinstance(result_lookup, dict) is True

        if result_lookup["state"] == "accepted":
            break
        else:
            time.sleep(1)

    assert result_lookup["state"] == "accepted"
    assert "htlc_expiry" in result_lookup

    # test that it's actually holding the htlcs
    # and not letting them through
    doublecheck = only_one(l2.rpc.call("listinvoices", {
        "payment_hash": invoice["payment_hash"]})["invoices"])
    assert doublecheck["status"] == "unpaid"

    result_settle = l2.rpc.call("holdinvoicesettle", {
        "payment_hash": invoice["payment_hash"]})
    assert result_settle is not None
    assert isinstance(result_settle, dict) is True
    assert result_settle["state"] == "settled"

    result_lookup = l2.rpc.call("holdinvoicelookup", {
        "payment_hash": invoice["payment_hash"]})
    assert result_lookup is not None
    assert isinstance(result_lookup, dict) is True
    assert result_lookup["state"] == "settled"
    assert "htlc_expiry" not in result_lookup

    # ask cln if the invoice is actually paid
    # should not be necessary because lookup does this aswell
    doublecheck = only_one(l2.rpc.call("listinvoices", {
        "payment_hash": invoice["payment_hash"]})["invoices"])
    assert doublecheck["status"] == "paid"

    result_cancel_settled = l2.rpc.call("holdinvoicecancel", {
        "payment_hash": invoice["payment_hash"]})
    assert result_cancel_settled is not None
    assert isinstance(result_cancel_settled, dict) is True
    expected_message = ("Holdinvoice is in wrong "
                        "state: 'settled'")
    assert result_cancel_settled["message"] == expected_message


def test_valid_hold_then_cancel(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2,
                                    opts={
                                        'important-plugin': os.path.join(
                                            os.getcwd(),
                                            '../../target/release/holdinvoice'
                                        )
                                    }
                                    )
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    cl1, _ = l1.fundchannel(l2, 1_000_000)
    cl2, _ = l1.fundchannel(l2, 1_000_000)

    l1.wait_local_channel_active(cl1)
    l1.wait_local_channel_active(cl2)

    invoice = l2.rpc.call("holdinvoice", {
        "amount_msat": 1_000_100_000,
        "description": "test_valid_hold_then_cancel",
        "label": generate_random_label(),
        "cltv": 144}
    )
    assert invoice is not None
    assert isinstance(invoice, dict) is True
    assert "payment_hash" in invoice

    result_lookup = l2.rpc.call("holdinvoicelookup", {
        "payment_hash": invoice["payment_hash"]})
    assert result_lookup is not None
    assert isinstance(result_lookup, dict) is True
    assert "state" in result_lookup
    assert result_lookup["state"] == "open"
    assert "htlc_expiry" not in result_lookup

    threading.Thread(target=pay_with_thread, args=(
        l1.rpc, invoice["bolt11"])).start()

    timeout = 10
    start_time = time.time()

    while time.time() - start_time < timeout:
        result_lookup = l2.rpc.call("holdinvoicelookup", {
            "payment_hash": invoice["payment_hash"]})
        assert result_lookup is not None
        assert isinstance(result_lookup, dict) is True

        if result_lookup["state"] == "accepted":
            break
        else:
            time.sleep(1)

    assert result_lookup["state"] == "accepted"
    assert "htlc_expiry" in result_lookup

    result_cancel = l2.rpc.call("holdinvoicecancel", {
        "payment_hash": invoice["payment_hash"]})
    assert result_cancel is not None
    assert isinstance(result_cancel, dict) is True
    assert result_cancel["state"] == "canceled"

    result_lookup = l2.rpc.call("holdinvoicelookup", {
        "payment_hash": invoice["payment_hash"]})
    assert result_lookup is not None
    assert isinstance(result_lookup, dict) is True
    assert result_lookup["state"] == "canceled"
    assert "htlc_expiry" not in result_lookup

    doublecheck = only_one(l2.rpc.call("listinvoices", {
        "payment_hash": invoice["payment_hash"]})["invoices"])
    assert doublecheck["status"] == "unpaid"

    # if we cancel we cannot settle after
    result_settle_canceled = l2.rpc.call("holdinvoicesettle", {
        "payment_hash": invoice["payment_hash"]})
    assert result_settle_canceled is not None
    assert isinstance(result_settle_canceled, dict) is True
    expected_message = ("Holdinvoice is in wrong "
                        "state: 'canceled'")
    result_settle_canceled["message"] == expected_message
