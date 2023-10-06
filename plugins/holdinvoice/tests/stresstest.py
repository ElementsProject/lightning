#!/usr/bin/python

from pyln.testing.fixtures import *
from pyln.testing.utils import wait_for, mine_funding_to_announce
import time
import threading
import os
import logging
from util import generate_random_label, pay_with_thread


# number of invoices to create, pay, hold and then cancel
num_iterations = 100
# seconds to hold the invoices with inflight htlcs
delay_seconds = 120
# amount to be used in msat
amount_msat = 1_000_100_000


def lookup_stats(rpc, payment_hashes):
    LOGGER = logging.getLogger(__name__)
    state_counts = {'open': 0, 'settled': 0, 'canceled': 0, 'accepted': 0}
    for payment_hash in payment_hashes:
        try:
            invoice_info = rpc.holdinvoicelookup(payment_hash)
            state = invoice_info['state']
            state_counts[state] = state_counts.get(state, 0) + 1
        except Exception as e:
            LOGGER.error(
                f"holdinvoice: Error looking up payment hash {payment_hash}:",
                e)
    return state_counts


def test_stress(node_factory, bitcoind):
    LOGGER = logging.getLogger(__name__)
    l1, l2 = node_factory.get_nodes(2,
                                    opts={
                                        'important-plugin': os.path.join(
                                            os.getcwd(),
                                            'target/release/holdinvoice'
                                        )
                                    }
                                    )
    l1.fundwallet((amount_msat/1000)*num_iterations*20)
    LOGGER.info("holdinvoice: Funding secured")
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    for _ in range(int(num_iterations/7)+1):
        for _ in range(10):
            res = l1.rpc.fundchannel(l2.info['id'], int(
                (amount_msat*0.95)/1000), minconf=0)
        blockid = bitcoind.generate_block(1, wait_for_mempool=res['txid'])[0]

        for i, txid in enumerate(bitcoind.rpc.getblock(blockid)['tx']):
            if txid == res['txid']:
                txnum = i

        scid = '{}x{}x{}'.format(
            bitcoind.rpc.getblockcount(), txnum, res['outnum'])
        mine_funding_to_announce(bitcoind, [l1])
        LOGGER.info("holdinvoice: Funded 10 channels")

    l1.wait_channel_active(scid)
    wait_for(lambda: all(channel['state'] == 'CHANNELD_NORMAL'
                         for channel in
                         l1.rpc.listpeerchannels(l2.info['id'])['channels']))

    payment_hashes = []

    LOGGER.info(
        f"holdinvoice: Creating and paying {num_iterations} invoices...")
    for _ in range(num_iterations):
        label = generate_random_label()

        try:
            invoice = l2.rpc.call("holdinvoice", {
                "amount_msat": amount_msat,
                "label": label,
                "description": "masstest",
                "cltv": 144,
                "expiry": 3600}
            )
            payment_hash = invoice['payment_hash']
            payment_hashes.append(payment_hash)

            # Pay the invoice using a separate thread
            threading.Thread(target=pay_with_thread, args=(
                l1, invoice["bolt11"])).start()
            time.sleep(1)
        except Exception as e:
            LOGGER.error("holdinvoice: Error executing command:", e)

    LOGGER.info(f"holdinvoice: Done paying {num_iterations} invoices!")
    # wait a little more for payments to arrive
    wait_for(lambda: lookup_stats(l2.rpc, payment_hashes)
             ["accepted"] == num_iterations)

    stats = lookup_stats(l2.rpc, payment_hashes)
    LOGGER.info(stats)
    assert stats["accepted"] == num_iterations

    LOGGER.info(f"holdinvoice: Holding htlcs for {delay_seconds} seconds...")

    time.sleep(delay_seconds)

    stats = lookup_stats(l2.rpc, payment_hashes)
    LOGGER.info(stats)
    assert stats["accepted"] == num_iterations

    LOGGER.info(f"holdinvoice: Cancelling all {num_iterations} invoices...")
    for payment_hash in payment_hashes:
        try:
            l2.rpc.call("holdinvoicecancel", {
                "payment_hash": payment_hash})
        except Exception as e:
            LOGGER.error(
                f"holdinvoice: holdinvoice:Error cancelling "
                f"payment hash {payment_hash}:", e)

    wait_for(lambda: lookup_stats(l2.rpc, payment_hashes)
             ["canceled"] == num_iterations)

    stats = lookup_stats(l2.rpc, payment_hashes)
    LOGGER.info(stats)
    assert stats["canceled"] == num_iterations
