# GRPC hodl-plugin for Core Lightning

This plugin exposes the Hold-Invoice related JSON-RPC interface through grpc over the
network. It listens on a configurable port, authenticates clients
using mTLS certificates, and will forward any Hold-Invoice related request to the JSON-RPC
interface, performing translations from protobuf to JSON and back.


## Getting started

The plugin only runs when `lightningd` is configured with the option
`--grpc-hodl-port`. Upon starting the plugin generates a number of files,
if they don't already exist:

 - `ca.pem` and `ca-key.pem`: These are the certificate and private
   key for your own certificate authority. The plugin will only accept
   incoming connections using certificates that are signed by theis
   CA.
 - `server.pem` and `server-key.pem`: this is the identity
   (certificate and private key) used by the plugin to authenticate
   itself. It is signed by the CA, and the client will verify its
   identity.
 - `client.pem` and `client-key.pem`: this is an example identity that
   can be used by a client to connect to the plugin, and issue
   requests. It is also signed by the CA.
   
These files are generated with sane defaults, however you can generate
custom certificates should you require some changes (see below for
details).

## Connecting

The client needs a valid mTLS identity in order to connect to the
plugin, so copy over the `ca.pem`, `client.pem` and `client-key.pem`
files from the node. The RPC interface is described in the [protobuf
file][proto], and we'll first need to generate language specific
bindings.

In this example we walk through the steps for python, however they are
mostly the same for other languages.

We start by downloading the dependencies and `protoc` compiler:

```bash
pip install grpcio-tools
```

Next we generate the bindings in the current directory:

```bash
python -m grpc_tools.protoc \
  -I path/to/cln-grpc/proto \
  path/to/cln-grpc/proto/node.proto \
  --python_out=. \
  --grpc_python_out=. \
  --experimental_allow_proto3_optional
```
```bash
python -m grpc_tools.protoc \
  -I path/to/cln-grpc/proto \
  path/to/cln-grpc/proto/hodl.proto \
  --python_out=. \
  --grpc_python_out=. \
  --experimental_allow_proto3_optional
```
```bash
python -m grpc_tools.protoc \
  -I path/to/cln-grpc/proto \
  path/to/cln-grpc/proto/primitives.proto \
  --python_out=. \
  --grpc_python_out=. \
  --experimental_allow_proto3_optional
```

This will generate 6 files in the current directory:

 - `node_pb2.py`: the description of the protobuf messages we'll be
   exchanging with the server.
 - `node_pb2_grpc.py`: the service and method stubs representing the
   server-side methods as local objects and associated methods.
 - `hodl_pb2.py`: the description of the hold-invoice related protobuf messages we'll be
   exchanging with the server.
 - `hodl_pb2_grpc.py`: the service and method stubs representing the
   server-side hold-invoice related methods as local objects and associated methods.
 - `primitives_pb2.py`: the description of the primitives protobuf messages we'll be
   exchanging with the server.
 - `primitives_pb2_grpc.py`: the service and method stubs representing the
   server-side primitives methods as local objects and associated methods.
   
And finally we can use the generated stubs and mTLS identity to
connect to the node:

```python
from pathlib import Path
from node_pb2_grpc import NodeStub
import node_pb2
from hodl_pb2_grpc import HodlStub
import hodl_pb2
import primitives_pb2

p = Path(".")
cert_path = p / "client.pem"
key_path = p / "client-key.pem"
ca_cert_path = p / "ca.pem"

creds = grpc.ssl_channel_credentials(
    root_certificates=ca_cert_path.open('rb').read(),
    private_key=key_path.open('rb').read(),
    certificate_chain=cert_path.open('rb').read()
)

channel = grpc.secure_channel(
	f"localhost:{grpc_port}",
	creds,
	options=(('grpc.ssl_target_name_override', 'cln'),)
)
channel = grpc.secure_channel(
	f"localhost:{grpc_hodl_port}",
	creds,
	options=(('grpc.ssl_target_name_override', 'cln'),)
)
hodlstub = HodlStub(channel)

request = node_pb2.InvoiceRequest(amount_msat=primitives_pb2.AmountOrAny(amount=primitives_pb2.Amount(msat=10_000)), description="test", label="test", cltv=500)

print(hodlstub.HodlInvoice(request))

print(stub.Getinfo(node_pb2.GetinfoRequest()))
```

In this example we first local the client identity, as well as the CA
certificate so we can verify the server's identity against it. We then
create a `creds` instance using those details. Next we open a secure
channel, i.e., a channel over TLS with verification of identities.

Notice that we override the expected SSL name with `cln`. This is
required because the plugin does not know the domain under which it
will be reachable, and will therefore use `cln` as a standin. See
custom certificate generation for how this could be changed.

We then use the channel to instantiate the `NodeStub` representing the
normal cln service and its methods aswell as the `HodlStub` representing
the hodl service and its methods. Then we create an `InvoiceRequest` and call
`HodlInvoice` with it. Finally we call the `Getinfo` method
with default arguments.

## Generating custom certificates

The automatically generated mTLS certificate will not know about
potential domains that it'll be served under, and will chose a number
of other parameters by default. If you'd like to generate a server
certificate with a custom domain you can use the following:


```bash
openssl genrsa -out server-key.pem 2048
```

This generates the private key. Next we create a Certificate Signature Request (CSR) that we can then process using our CA identity:

```bash
openssl req -key server-key.pem -new -out server.csr
```

You will be asked a number of questions, the most important of which
is the _Common Name_, which you should set to the domain name you'll
be serving the interface under. Next we can generate the actual
certificate by processing the request with the CA identity:

```bash
openssl x509 -req -CA ca.pem -CAkey ca-key.pem \
  -in server.csr \
  -out server.pem \
  -days 365 -CAcreateserial
```

This will finally create the `server.pem` file, signed by the CA,
allowing you to access the node through its real domain name. You can
now move `server.pem` and `server-key.pem` into the lightning
directory, and they should be picked up during the start.

[proto]: https://github.com/ElementsProject/lightning/blob/master/cln-grpc/proto/node.proto
