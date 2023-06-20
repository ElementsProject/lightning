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
import primitives_pb2 as primitives__pb2


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
stub = nodestub.NodeStub(channel)

# initializing size of string
N = 7

# using random.choices()
# generating random strings
res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=N))

request = noderpc.GetrouteRequest(id=bytes.fromhex("027e07001d9de115f315f8d5ff7a714fe6e4a41e355f20c4c6d5be96cf3d8fdeef"), amount_msat=primitives__pb2.Amount(msat=100004000), riskfactor=5)
response = stub.GetRoute(request)
preimage = hashlib.sha256(secrets.token_bytes(nbytes=32)).digest()
payment_hash = hashlib.sha256(preimage).digest()
route = []
# message SendpayRoute {
# 	Amount amount_msat = 5;
# 	bytes id = 2;
# 	uint32 delay = 3;
# 	string channel = 4;
# }

# message GetrouteRoute {
# 	// GetRoute.route[].style
# 	enum GetrouteRouteStyle {
# 		TLV = 0;
# 	}
# 	bytes id = 1;
# 	string channel = 2;
# 	uint32 direction = 3;
# 	Amount amount_msat = 4;
# 	uint32 delay = 5;
# 	GetrouteRouteStyle style = 6;
# }
for hop in response.route:
    route.append(noderpc.SendpayRoute(amount_msat=hop.amount_msat, id=hop.id, delay=hop.delay, channel=hop.channel))
reqsend = noderpc.SendpayRequest(route=route, payment_hash=payment_hash)
respsend = stub.SendPay(reqsend)

print(response)
print(respsend)
