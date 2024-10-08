---
title: "gRPC APIs"
slug: "grpc"
hidden: false
createdAt: "2023-02-07T12:52:39.665Z"
updatedAt: "2023-02-08T09:56:41.158Z"
---
> 📘
>
> Used for applications that want to connect to CLN over the network in a secure manner.

Since v0.11.0, Core Lightning provides a new interface: `cln-grpc`, a Rust-based plugin that provides a standardized API that apps, plugins, and other tools could use to interact with Core Lightning securely.

We always had a JSON-RPC, with a very exhaustive API, but it was exposed only locally over a Unix-domain socket. Some plugins chose to re-expose the API over a variety of protocols, ranging from REST to gRPC, but it was additional work to install them. The gRPC API is automatically generated from our existing JSON-RPC API, so it has the same low-level and high-level access that app devs are accustomed to but uses a more efficient binary encoding where possible and is secured via mutual TLS authentication.

To use it, just add the `--grpc-port` option, and it’ll automatically start alongside Core Lightning and generate the appropriate mTLS certificates. It will listen on the configured port, authenticate clients using mTLS certificates, and will forward any request to the JSON-RPC interface, performing translations from protobuf to JSON and back.

## Tutorial

### Generating the certificates

The plugin only runs when `lightningd` is configured with the option `--grpc-port`. Upon starting, the plugin generates a number of files, if they don't already exist:

- `ca.pem` and `ca-key.pem`: These are the certificate and private key for your own certificate authority. The plugin will only accept incoming connections using certificates that are signed by this CA.
- `server.pem` and `server-key.pem`: this is the identity (certificate and private key) used by the plugin to authenticate itself. It is signed by the CA, and the client will verify its identity.
- `client.pem` and `client-key.pem`: this is an example identity that can be used by a client to connect to the plugin, and issue requests. It is also signed by the CA.

These files are generated with sane defaults, however you can generate custom certificates should you require some changes (see [below](doc:grpc#generating-custom-certificates) for details).

The client needs a valid mTLS identity in order to connect to the plugin, so copy over the `ca.pem`, `client.pem` and `client-key.pem` files from the node to your project directory.

### Generating language-specific bindings

The gRPC interface is described in the [protobuf file](https://github.com/ElementsProject/lightning/blob/master/cln-grpc/proto/node.proto), and we'll first need to generate language specific bindings.

In this tutorial, we walk through the steps for Python, however they are mostly the same for other languages. For instance, if you're developing in Rust, use [`tonic-build`](https://docs.rs/tonic-build/latest/tonic_build/) to generate the bindings. For other languages, see the official [gRPC docs](https://grpc.io/docs/languages/) on how to generate gRPC client library for your specific language using the protobuf file.

We start by downloading the dependencies and `protoc` compiler:

```shell
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

This will generate two files in the current directory:

- `node_pb2.py`: the description of the protobuf messages we'll be exchanging with the server.
- `node_pb2_grpc.py`: the service and method stubs representing the server-side methods as local objects and associated methods.

Finally, we generate the file `primitives_pb2.py` that contains
protobuf messages imported in `node_pb2.py` file by running the
following command:

```bash
python -m grpc_tools.protoc \
  -I lightning/cln-grpc/proto \
  path/to/cln-grpc/proto/primitives.proto \
  --python_out=. \
  --experimental_allow_proto3_optional
```

### Connecting to the node

Finally we can use the generated stubs and mTLS identity to connect to the node:

```python
from pathlib import Path
from node_pb2_grpc import NodeStub
import node_pb2
import grpc

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
	"localhost:<GRPC-PORT>",
	creds,
	options=(('grpc.ssl_target_name_override', 'cln'),)
)
stub = NodeStub(channel)

print(stub.Getinfo(node_pb2.GetinfoRequest()))
```

Note that we must replace `<GRPC-PORT>` by the corresponding port we
used as `--grpc-port` option when we started our node.

In this example, we first load the client identity as well as the CA certificate so we can verify the server's identity against it. We then create a `creds` instance using those details. Next we open a secure channel, i.e., a channel over TLS with verification of identities.

Notice that we override the expected SSL name with `cln`. This is required because the plugin does not know the domain under which it will be reachable, and will therefore use `cln` as a standin. See [custom certificate generation](doc:grpc#generating-custom-certificates) for how this could be changed.

We then use the channel to instantiate the `NodeStub` representing the service and its methods, so we can finally call the `Getinfo` method with default arguments.

### Generating custom certificates (optional)

The automatically generated mTLS certificate will not know about potential domains that it'll be served under, and will chose a number of other parameters by default. If you'd like to generate a server certificate with a custom domain, you can use the following:

```shell
openssl genrsa -out server-key.pem 2048
```



This generates the private key. Next we create a Certificate Signature Request (CSR) that we can then process using our CA identity:

```shell
openssl req -key server-key.pem -new -out server.csr
```



You will be asked a number of questions, the most important of which is the _Common Name_, which you should set to the domain name you'll be serving the interface under. Next we can generate the actual certificate by processing the request with the CA identity:

```shell
openssl x509 -req -CA ca.pem -CAkey ca-key.pem \
  -in server.csr \
  -out server.pem \
  -days 365 -CAcreateserial
```



This will finally create the `server.pem` file, signed by the CA, allowing you to access the node through its real domain name. You can now move `server.pem` and `server-key.pem` into the lightning directory (ex. `<lightning-dir>/bitcoin` for `mainnet`), and they should be picked up during the start.

#### Generating custom certificates using SANs (Subject Alternative Names)

To add additional domain names to the custom certificate, you can use a variation of the above commands. This is helpful, for example, if you are exposing the API over Tor, or experiencing errors due to client SSL verification asking for verification via a `SAN` instead of `CN`.

```shell
openssl genrsa -out server-key.pem 2048
```



As above, generate a new server key.

Then, create an openssl CSR configuration file name `cln-csr.conf` that looks something like the following:

```
[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext

[req_distinguished_name]
CN = "cln rest server"

[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1  = 127.0.0.1
DNS.1 = localhost
DNS.2 = cln
DNS.3 = <put your custom DNS name here and add more if desired>
```


Consult the `openssl` [documentation ](https://docs.openssl.org/master/man1/openssl-req/#configuration-file-format) for your version for additional customization.

```shell
openssl req -new -key server-key.pem -out server.csr -config cln-csr.conf
```



This example configuration suggests the generated default for _Common Name_, but can be changed when prompted.

```shell
openssl x509 -req -CA ca.pem -CAkey ca-key.pem -in server.csr -out server.pem -days 365 -CAcreateserial -extensions req_ext -extfile cln-csr.conf
```



As above, generate the new server certificate, but this time with the `SAN` configuration. Copy `server.pem` and `server-key.pem` into the certificates location (ex. `<lightning-dir>/bitcoin` for `mainnet`) and restart the service to take effect.
