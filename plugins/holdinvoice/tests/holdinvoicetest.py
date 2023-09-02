#!/usr/bin/python

from pyln.client import LightningRpc
import unittest
import secrets
import threading
import time
from util import generate_random_label
from util import generate_random_number
from util import pay_with_thread

# need 2 nodes with sufficient liquidity on rpc1 side
# this is the node with holdinvoice
rpc2 = LightningRpc("/tmp/l2-regtest/regtest/lightning-rpc")
# this node pays the invoices
rpc1 = LightningRpc("/tmp/l1-regtest/regtest/lightning-rpc")


class TestStringMethods(unittest.TestCase):

    def test_valid_input(self):
        result = rpc2.holdinvoice(
            amount_msat=1000000,
            description="Valid invoice description",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertIn("payment_hash", result)

        result = rpc2.holdinvoice(
            amount_msat=1000000,
            description="",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertIn("payment_hash", result)

        result = rpc2.holdinvoice(
            amount_msat=1000000,
            description="Numbers only as label",
            label=generate_random_number()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertIn("payment_hash", result)

    def test_missing_required_fields(self):
        result = rpc2.holdinvoice(
            description="Missing amount",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(result["message"],
                         "missing required parameter: amount_msat|msatoshi")

        result = rpc2.holdinvoice(
            amount_msat=1000000,
            description="Missing label",
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(result["message"],
                         "missing required parameter: label")

        result = rpc2.holdinvoice(
            amount_msat=1000000,
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(result["message"],
                         "missing required parameter: description")

    def test_optional_fields(self):
        random_hex = secrets.token_hex(32)
        result = rpc2.holdinvoice(
            amount_msat=2000000,
            description="Invoice with optional fields",
            label=generate_random_label(),
            expiry=3600,
            fallbacks=["bcrt1qcpw242j4xsjth7ueq9dgmrqtxjyutuvmraeryr",
                       "bcrt1qdwydlys0f8khnp87mx688vq4kskjyr68nrx58j"],
            preimage=random_hex,
            cltv=144,
            deschashonly=True
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertIn("payment_hash", result)

    def test_invalid_amount_msat(self):
        # Negative amount_msat
        result = rpc2.holdinvoice(
            amount_msat=-1000,
            description="Invalid amount negative",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(
            result["message"], "amount_msat|msatoshi: should be an unsigned "
            "64 bit integer: invalid token '-1000'")

        # 0 amount_msat
        result = rpc2.holdinvoice(
            amount_msat=0,
            description="Invalid amount 0",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(
            result["message"], "amount_msat|msatoshi: should be positive msat"
            " or 'any': invalid token '\"0msat\"'")

    def test_invalid_expiry(self):
        # Negative expiry value
        result = rpc2.holdinvoice(
            amount_msat=500000,
            description="Invalid expiry",
            label=generate_random_label(),
            expiry=-3600
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(result["message"], "expiry: should be an unsigned "
                         "64 bit integer: invalid token '-3600'")

    def test_invalid_fallbacks(self):
        # Fallbacks not as a list of strings
        result = rpc2.holdinvoice(
            amount_msat=800000,
            description="Invalid fallbacks",
            label=generate_random_label(),
            fallbacks="invalid_fallback"
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(result["message"], "fallbacks: should be an array: "
                         "invalid token '\"invalid_fallback\"'")

    def test_invalid_cltv(self):
        # Negative cltv value
        result = rpc2.holdinvoice(
            amount_msat=1200000,
            description="Invalid cltv",
            label=generate_random_label(),
            cltv=-144
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertEqual(result["message"], "cltv: should be an integer: "
                         "invalid token '-144'")

    def test_valid_hold_then_settle(self):
        result = rpc2.holdinvoice(
            amount_msat=1_000_100_000,
            description="test_valid_hold_then_settle",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertIn("payment_hash", result)

        result_lookup = rpc2.holdinvoicelookup(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_lookup)
        self.assertTrue(isinstance(result_lookup, dict))
        self.assertIn("state", result_lookup)
        self.assertEqual(result_lookup["state"], "open")
        self.assertNotIn("htlc_expiry", result_lookup)

        # test that it won't settle if it's still open
        result_settle = rpc2.holdinvoicesettle(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_settle)
        self.assertTrue(isinstance(result_settle, dict))
        self.assertEqual(result_settle["message"],
                         "Holdinvoice is in wrong state: 'open'")

        threading.Thread(target=pay_with_thread, args=(
            rpc1, result["bolt11"])).start()

        timeout = 10
        start_time = time.time()

        while time.time() - start_time < timeout:
            result_lookup = rpc2.holdinvoicelookup(
                payment_hash=result["payment_hash"])
            self.assertIsNotNone(result_lookup)
            self.assertTrue(isinstance(result_lookup, dict))

            if result_lookup["state"] == "accepted":
                break
            else:
                time.sleep(1)

        self.assertEqual(result_lookup["state"], "accepted")
        self.assertIn("htlc_expiry", result_lookup)

        # test that it's actually holding the htlcs
        # and not letting them through
        doublecheck = rpc2.listinvoices(
            payment_hash=result["payment_hash"])["invoices"]
        self.assertEqual(doublecheck[0]["status"], "unpaid")

        result_settle = rpc2.holdinvoicesettle(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_settle)
        self.assertTrue(isinstance(result_settle, dict))
        self.assertEqual(result_settle["state"], "settled")

        result_lookup = rpc2.holdinvoicelookup(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_lookup)
        self.assertTrue(isinstance(result_lookup, dict))
        self.assertEqual(result_lookup["state"], "settled")
        self.assertNotIn("htlc_expiry", result_lookup)

        # ask cln if the invoice is actually paid
        # should not be necessary because lookup does this aswell
        doublecheck = rpc2.listinvoices(
            payment_hash=result["payment_hash"])["invoices"]
        self.assertEqual(doublecheck[0]["status"], "paid")

        result_cancel_settled = rpc2.holdinvoicecancel(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_cancel_settled)
        self.assertTrue(isinstance(result_cancel_settled, dict))
        self.assertEqual(
            result_cancel_settled["message"], "Holdinvoice is in wrong "
            "state: 'settled'")

    def test_valid_hold_then_cancel(self):
        result = rpc2.holdinvoice(
            amount_msat=1_000_100_000,
            description="test_valid_hold_then_cancel",
            label=generate_random_label()
        )
        self.assertIsNotNone(result)
        self.assertTrue(isinstance(result, dict))
        self.assertIn("payment_hash", result)

        result_lookup = rpc2.holdinvoicelookup(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_lookup)
        self.assertTrue(isinstance(result_lookup, dict))
        self.assertIn("state", result_lookup)
        self.assertEqual(result_lookup["state"], "open")
        self.assertNotIn("htlc_expiry", result_lookup)

        threading.Thread(target=pay_with_thread, args=(
            rpc1, result["bolt11"])).start()

        timeout = 10
        start_time = time.time()

        while time.time() - start_time < timeout:
            result_lookup = rpc2.holdinvoicelookup(
                payment_hash=result["payment_hash"])
            self.assertIsNotNone(result_lookup)
            self.assertTrue(isinstance(result_lookup, dict))

            if result_lookup["state"] == "accepted":
                break
            else:
                time.sleep(1)

        self.assertEqual(result_lookup["state"], "accepted")
        self.assertIn("htlc_expiry", result_lookup)

        result_cancel = rpc2.holdinvoicecancel(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_cancel)
        self.assertTrue(isinstance(result_cancel, dict))
        self.assertEqual(result_cancel["state"], "canceled")

        result_lookup = rpc2.holdinvoicelookup(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_lookup)
        self.assertTrue(isinstance(result_lookup, dict))
        self.assertEqual(result_lookup["state"], "canceled")
        self.assertNotIn("htlc_expiry", result_lookup)

        doublecheck = rpc2.listinvoices(
            payment_hash=result["payment_hash"])["invoices"]
        self.assertEqual(doublecheck[0]["status"], "unpaid")

        # if we cancel we cannot settle after
        result_settle_canceled = rpc2.holdinvoicesettle(
            payment_hash=result["payment_hash"])
        self.assertIsNotNone(result_settle_canceled)
        self.assertTrue(isinstance(result_settle_canceled, dict))
        self.assertEqual(
            result_settle_canceled["message"], "Holdinvoice is in wrong "
            "state: 'canceled'")


if __name__ == '__main__':
    unittest.main()
