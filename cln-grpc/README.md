# cln-grpc - Secure Networked RPC Interface

This plugin provides a standardized API that apps, plugins, and other tools could use to interact with Core Lightning. We always had a JSON-RPC, with a very exhaustive API, but it was exposed only locally over a Unix-domain socket. Some plugins chose to re-expose the API over a variety of protocols, ranging from REST to gRPC, but it was additional work to install them.

So with v0.11.0, we released a new interface: `cln-grpc`, a Rust-based plugin that exposes the existing interface over the network in a secure manner. The gRPC API is automatically generated from our existing JSON-RPC API, so it has the same low-level and high-level access that app devs are accustomed to but uses a more efficient binary encoding where possible and is secured via mutual TLS authentication.

To use it, just add the `--grpc-port` option, and it’ll automatically start alongside Core Lightning and generate the appropriate mTLS certificates. To use the gRPC interface, copy the client key and certificate, generate your client bindings from the protobuf definition and connect to the port you specified earlier.

While all previous built-in plugins were written in C, the `cln-grpc` plugin is written in Rust, a language that will be much more prominent in the project going forward. In order to kick off the use of Rust, we also built a number of crates:

- [cln-rpc](https://crates.io/crates/cln-rpc): native bindings to the JSON-RPC interface, used for things running on the same system as CLN.
- [cln-plugin](https://crates.io/crates/cln-plugin): a library that facilitates the creation of plugins in Rust, with async/await support, for low-footprint plugins.
- [cln-grpc](https://crates.io/crates/cln-grpc): of course, the library used to create the gRPC plugin can also be used directly as a client library.

All of these crates are published on crates.io and will be maintained as part of the project moving forward.
