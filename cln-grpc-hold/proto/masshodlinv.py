#!/usr/bin/env python3

# import os
import grpc
# import secrets
# import hashlib
import string
import random
# import sys
import time


import node_pb2 as noderpc
import node_pb2_grpc as nodestub
import hold_pb2 as holdrpc
import hold_pb2_grpc as holdstub
import primitives_pb2 as primitives__pb2


# Load the client's certificate and key
with open("/tmp/l2-regtest/regtest/client.pem", "rb") as f:
    client_cert_l2 = f.read()
with open("/tmp/l2-regtest/regtest/client-key.pem", "rb") as f:
    client_key_l2 = f.read()

# Load the server's certificate
with open("/tmp/l2-regtest/regtest/server.pem", "rb") as f:
    server_cert_l2 = f.read()

creds_l2 = grpc.ssl_channel_credentials(
    root_certificates=server_cert_l2,
    private_key=client_key_l2,
    certificate_chain=client_cert_l2,
)
# Create the gRPC channel using the SSL credentials
hold_channel_l2 = grpc.secure_channel("localhost:59998", creds_l2)

# Create the gRPC stub
hold_stub_l2 = holdstub.HoldStub(hold_channel_l2)

# Load the client's certificate and key
with open("/tmp/l1-regtest/regtest/client.pem", "rb") as f:
    client_cert_l1 = f.read()
with open("/tmp/l1-regtest/regtest/client-key.pem", "rb") as f:
    client_key_l1 = f.read()

# Load the server's certificate
with open("/tmp/l1-regtest/regtest/server.pem", "rb") as f:
    server_cert_l1 = f.read()

creds_l1 = grpc.ssl_channel_credentials(
    root_certificates=server_cert_l1,
    private_key=client_key_l1,
    certificate_chain=client_cert_l1,
)
# Create the gRPC channel using the SSL credentials
hold_channel_l1 = grpc.secure_channel("localhost:59999", creds_l1)
cln_channel_l1 = grpc.secure_channel("localhost:49999", creds_l1)

# Create the gRPC stub
hold_stub_l1 = holdstub.HoldStub(hold_channel_l1)
clnstub_l1 = nodestub.NodeStub(cln_channel_l1)

# initializing size of string
N = 7

state_counts = {
    holdrpc.HoldndvoiceLookupResponse.Holdstate.OPEN: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.SETTLED: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.CANCELED: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.ACCEPTED: 0
}

amt = 51000  # int(sys.argv[1])
invoice_hashes = []
for _ in range(1):
    res = ''.join(random.choices(string.ascii_uppercase +
                                 string.digits, k=N))
    request = noderpc.InvoiceRequest(
        amount_msat=primitives__pb2.AmountOrAny(
            amount=primitives__pb2.Amount(msat=amt*1000)),
        description="", label=res, cltv=20, expiry=15000)

    response = hold_stub_l2.HoldInvoice(request)
    invoice_hashes.append(response.payment_hash)
    if random.random() < 0.9:
        requestpay = noderpc.PayRequest(bolt11=response.bolt11)
        responsepay = clnstub_l1.Pay.future(requestpay)
        time.sleep(1)
print("pays pending")
time.sleep(120)
for hash in invoice_hashes:
    reqlook = holdrpc.HoldInvoiceLookupRequest(payment_hash=hash)
    resplook = hold_stub_l2.HoldInvoiceLookup(reqlook)
    state = resplook.state
    if state in state_counts:
        state_counts[state] += 1

print(state_counts)
state_counts = {
    holdrpc.HoldInvoiceLookupResponse.Holdstate.OPEN: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.SETTLED: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.CANCELED: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.ACCEPTED: 0
}
time.sleep(60)
for hash in invoice_hashes:
    if random.random() < 0.33:
        reqlook = holdrpc.HoldInvoiceCancelRequest(payment_hash=hash)
        resplook = hold_stub_l2.HoldInvoiceCancel(reqlook)
print("randomly canceled")
time.sleep(60)
for hash in invoice_hashes:
    reqlook = holdrpc.HoldInvoiceLookupRequest(payment_hash=hash)
    resplook = hold_stub_l2.HoldInvoiceLookup(reqlook)
    state = resplook.state
    if state in state_counts:
        state_counts[state] += 1
print(state_counts)
state_counts = {
    holdrpc.HoldInvoiceLookupResponse.Holdstate.OPEN: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.SETTLED: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.CANCELED: 0,
    holdrpc.HoldInvoiceLookupResponse.Holdstate.ACCEPTED: 0
}
for hash in invoice_hashes:
    reqcanc = holdrpc.HoldInvoiceCancelRequest(payment_hash=hash)
    respcanc = hold_stub_l2.HoldInvoiceCancel(reqcanc)
for hash in invoice_hashes:
    reqlook = holdrpc.HoldInvoiceLookupRequest(payment_hash=hash)
    resplook = hold_stub_l2.HoldInvoiceLookup(reqlook)
    state = resplook.state
    if state in state_counts:
        state_counts[state] += 1
print(state_counts)
