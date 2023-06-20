#!/usr/bin/env python3

import os
import grpc
import secrets
import hashlib
import string
import random
import sys


import node_pb2 as noderpc
import node_pb2_grpc as nodestub
import hold_pb2 as holdrpc
import hold_pb2_grpc as holdstub
import primitives_pb2


# Load the client's certificate and key
with open("/tmp/l2-regtest/regtest/client.pem", "rb") as f:
    client_cert = f.read()
with open("/tmp/l2-regtest/regtest/client-key.pem", "rb") as f:
    client_key = f.read()

# Load the server's certificate
with open("/tmp/l2-regtest/regtest/server.pem", "rb") as f:
    server_cert = f.read()

creds = grpc.ssl_channel_credentials(
    root_certificates=server_cert,
    private_key=client_key,
    certificate_chain=client_cert,
)
# Create the gRPC channel using the SSL credentials
channel = grpc.secure_channel("localhost:59998", creds)

# Create the gRPC stub
stub = holdstub.HoldStub(channel)

# initializing size of string
N = 7

# using random.choices()
# generating random strings
res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=N))
amt = int(sys.argv[1])
request = noderpc.InvoiceRequest(amount_msat=primitives_pb2.AmountOrAny(amount=primitives_pb2.Amount(msat=amt*1000)), description="", label=res, cltv=1, expiry=15000)

response = stub.HoldInvoice(request)
print(response.bolt11 + "\n" + response.payment_hash.hex())
