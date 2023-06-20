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
import primitives_pb2 as primitives__pb2


# Load the client's certificate and key
with open("/tmp/l1-regtest/regtest/client.pem", "rb") as f:
    client_cert = f.read()
with open("/tmp/l1-regtest/regtest/client-key.pem", "rb") as f:
    client_key = f.read()

# Load the server's certificate
with open("/tmp/l1-regtest/regtest/server.pem", "rb") as f:
    server_cert = f.read()

creds = grpc.ssl_channel_credentials(
    root_certificates=server_cert,
    private_key=client_key,
    certificate_chain=client_cert,
)
# Create the gRPC channel using the SSL credentials
channel = grpc.secure_channel("localhost:59999", creds)
channelcln = grpc.secure_channel("localhost:49999", creds)

# Create the gRPC stub
stub = holdstub.HoldStub(channel)
clnstub = nodestub.NodeStub(channelcln)

# initializing size of string
N = 7

# using random.choices()
# generating random strings
res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=N))
b11 = sys.argv[1]
r = holdrpc.DecodeBolt11Request(bolt11=b11)
a = stub.DecodeBolt11(r)
hash = a.payment_hash
request = noderpc.PayRequest(bolt11=b11)
try:
    response = clnstub.Pay(request)
except grpc._channel._InactiveRpcError as e:
    if "code: Some" in str(e):
        status_code = int(e.details().split("code: Some(")[1].split(")")[0])
        if (
            status_code == 201
        ):  # Already paid with this hash using different amount or destination
            # i don't think this can happen really, since we don't use the amount_msat in request
            # and if you just try 'pay' 2x where the first time it succeeds you get the same
            # non-error result the 2nd time.
            print(f"Order:  ALREADY PAID using different amount or destination THIS SHOULD NEVER HAPPEN! Hash: .")

        # Permanent failure at destination. or Unable to find a route. or Route too expensive.
        elif status_code == 203 or status_code == 205 or status_code == 206 or status_code == 210:

            print(
                f"Order:  FAILED. Hash:  Reason: {status_code}"
            )
        elif status_code == 207:  # invoice expired
            print(f"Order: . INVOICE EXPIRED. Hash:")
            print(hash.hex())
            request_listpays = noderpc.ListpaysRequest(payment_hash=hash)
            response_listpays = clnstub.ListPays(request_listpays)
            print(str(len(response_listpays.pays)))
            still_inflight = False
        #         PENDING = 0;
		#        FAILED = 1;
		#       COMPLETE = 2;
            for pay in response_listpays.pays:
                print(str(pay.status))
                if pay.status == 0:
                    still_inflight = True
                elif pay.status == 2:
                    print("shoit")
            print(still_inflight)
            results = {
                "succeded": False,
                "context": "The payout invoice has expired",
            }
            print(results)
        else:  # -1 (general error)
            print(str(e))
    else:
        print(str(e))
