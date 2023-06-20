#!/usr/bin/env python3

import os
import grpc
import secrets
import hashlib
import string
import random
import sys
import time
import statistics


import node_pb2 as noderpc
import node_pb2_grpc as nodestub
import primitives_pb2 as primitives__pb2

with open("/tmp/l2-regtest/regtest/client.pem", "rb") as f:
    client_cert = f.read()
with open("/tmp/l2-regtest/regtest/client-key.pem", "rb") as f:
    client_key = f.read()

with open("/tmp/l2-regtest/regtest/server.pem", "rb") as f:
    server_cert = f.read()

creds = grpc.ssl_channel_credentials(
    root_certificates=server_cert,
    private_key=client_key,
    certificate_chain=client_cert,
)
channel = grpc.secure_channel("localhost:59998", creds)

stub = nodestub.NodeStub(channel)

# initializing size of string
N = 7

# using random.choices()
# generating random strings
res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=N))
b11 = sys.argv[1]
expiry_height = 0
request = noderpc.HoldInvoiceLookupRequest(payment_hash=bytes.fromhex(b11))
times = []
# for i in range(1000):
t0 = time.time()
try:
    response = stub.HoldInvoiceLookup(request)
# try saving expiry height
    if hasattr(response, "htlc_expiry"):
        try:
            expiry_height = response.htlc_expiry
        except Exception:
            pass
    if response.state == noderpc.HoldInvoiceLookupResponse.Holdstate.OPEN:
        print("OPEN")
    if response.state == noderpc.HoldInvoiceLookupResponse.Holdstate.SETTLED:
        print("SETTLED")
    if response.state == noderpc.HoldInvoiceLookupResponse.Holdstate.CANCELED:
        print("CANCELED")
    if response.state == noderpc.HoldInvoiceLookupResponse.Holdstate.ACCEPTED:
        print("ACCEPTED")

    print(str(response.state))
except Exception as e:
    # If it fails at finding the invoice: it has been expired for more than an hour (and could be paid or just expired).
    # In RoboSats DB we make a distinction between cancelled and returned
    #  (cln-grpc-hold has separate state for hold-invoices, which it forgets after an invoice expired more than an hour ago)
    if "empty result for listdatastore_state" in str(e):
        print(str(e))
        request2 = noderpc.ListinvoicesRequest(
            payment_hash=bytes.fromhex(b11)
        )
        try:
            response2 = stub.ListInvoices(request2).invoices
        except Exception as e:
            print(str(e))

        if response2[0].status == "paid":
            print("except: paid")
        elif response2[0].status == "expired":
            print("except: expired")
        else:
            print(str(e))

    # Other write to logs
    else:
        print(str(e))
times.append((time.time() - t0)*1000)
# print(f"min: {min(times)}")
# print(f"max: {max(times)}")
# print(f"avg: {sum(times) / len(times)}")
# print(f"median: {statistics.median(times)}")
