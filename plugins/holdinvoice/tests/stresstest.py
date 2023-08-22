#!/usr/bin/python

from pyln.client import LightningRpc
import time
import threading
import pickle
from util import generate_random_label, pay_with_thread


# number of invoices to create, pay, hold and then cancel
num_iterations = 80
# seconds to hold the invoices with inflight htlcs
delay_seconds = 120
# amount to be used in msat
amount_msat = 1_000_100_000

# need 2 nodes with sufficient liquidity on rpc1 side
# this is the node with holdinvoice
rpc2 = LightningRpc("/tmp/l2-regtest/regtest/lightning-rpc")
# this node pays the invoices
rpc1 = LightningRpc("/tmp/l1-regtest/regtest/lightning-rpc")


def lookup_stats(rpc, payment_hashes):
    state_counts = {'open': 0, 'settled': 0, 'canceled': 0, 'accepted': 0}
    for payment_hash in payment_hashes:
        try:
            invoice_info = rpc.holdinvoicelookup(payment_hash)
            state = invoice_info['state']
            state_counts[state] = state_counts.get(state, 0) + 1
        except Exception as e:
            print(f"Error looking up payment hash {payment_hash}:", e)
    print(state_counts)


payment_hashes = []


for _ in range(num_iterations):
    label = generate_random_label()

    try:
        result = rpc2.holdinvoice(
            amount_msat=amount_msat,
            label=label,
            description="masstest",
            expiry=3600
        )
        payment_hash = result['payment_hash']
        payment_hashes.append(payment_hash)

        # Pay the invoice using a separate thread
        threading.Thread(target=pay_with_thread, args=(
            rpc1, result["bolt11"])).start()
        time.sleep(1)
    except Exception as e:
        print("Error executing command:", e)

# Save payment hashes to disk incase something breaks
# and we want to do some manual cleanup
with open('payment_hashes.pkl', 'wb') as f:
    pickle.dump(payment_hashes, f)
    print("Saved payment hashes to disk.")

# wait a little more for payments to arrive
time.sleep(5)

lookup_stats(rpc2, payment_hashes)

print(f"Waiting for {delay_seconds} seconds...")

time.sleep(delay_seconds)

lookup_stats(rpc2, payment_hashes)

for payment_hash in payment_hashes:
    try:
        rpc2.holdinvoicecancel(payment_hash)
    except Exception as e:
        print(f"Error cancelling payment hash {payment_hash}:", e)

lookup_stats(rpc2, payment_hashes)
