---
title: "JSON-RPC commands"
slug: "json-rpc"
hidden: false
createdAt: "2023-02-07T12:53:11.917Z"
updatedAt: "2023-02-21T13:50:10.086Z"
---
> 📘 
> 
> Used for applications running on the same system as CLN.

## Using `lightning-cli`

Core Lightning exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification) interface over a Unix Domain socket; the [`lightning-cli`](ref:lightning-cli) tool can be used to access it, or there is a [python client library](???).

You can use `[lightning-cli](ref:lightning-cli) help` to print a table of RPC methods; `[lightning-cli](lightning-cli) help <command>` will offer specific information on that command.

Useful commands:

- [lightning-newaddr](ref:lightning-newaddr): get a bitcoin address to deposit funds into your lightning node.
- [lightning-listfunds](ref:lightning-listfunds): see where your funds are.
- [lightning-connect](ref:lightning-connect): connect to another lightning node.
- [lightning-fundchannel](ref:lightning-fundchannel): create a channel to another connected node.
- [lightning-invoice](ref:lightning-invoice): create an invoice to get paid by another node.
- [lightning-pay](ref:lightning-pay): pay someone else's invoice.
- [lightning-plugin](ref:lightning-plugin): commands to control extensions.

A complete list of all JSON-RPC commands is available at [API Reference](doc:api-reference).

## Using Python

[pyln-client](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-client) is a python client library for lightningd, that implements the Unix socket based JSON-RPC protocol. It can be used to call arbitrary functions on the RPC interface, and serves as a basis for applications or plugins written in python.

### Installation

`pyln-client` is available on `pip`:

```shell
pip install pyln-client
```



Alternatively you can also install the development version to get access to currently unreleased features by checking out the Core Lightning source code and installing into your python3 environment:

```shell
git clone https://github.com/ElementsProject/lightning.git
cd lightning/contrib/pyln-client
poetry install
```



This will add links to the library into your environment so changing the checked out source code will also result in the environment picking up these changes. Notice however that unreleased versions may change API without warning, so test thoroughly with the released version.

### Tutorials

Check out the following recipes to learn how to use pyln-client in your applications.


[block:tutorial-tile]
{
  "backgroundColor": "#dfb316",
  "emoji": "🦉",
  "id": "63dbbcd59880f6000e329079",
  "link": "https://docs.corelightning.org/v1.0/recipes/write-a-program-in-python-to-interact-with-lightningd",
  "slug": "write-a-program-in-python-to-interact-with-lightningd",
  "title": "Write a program in Python to interact with lightningd"
}
[/block]





[block:tutorial-tile]
{
  "backgroundColor": "#dfb316",
  "emoji": "🦉",
  "id": "63dbd6993ef79b07b8f399be",
  "link": "https://docs.corelightning.org/v1.0/recipes/write-a-hello-world-plugin-in-python",
  "slug": "write-a-hello-world-plugin-in-python",
  "title": "Write a hello-world plugin in Python"
}
[/block]




## Using Rust

[cln-rpc](https://crates.io/crates/cln-rpc) is a Rust-based crate for lightningd, that implements the Unix socket based JSON-RPC protocol. It can be used to call arbitrary functions on the RPC interface, and serves as a basis for applications or plugins written in Rust.

### Installation

Run the following Cargo command in your project directory:

```shell
cargo add cln-rpc
```



Or add the following line to your Cargo.toml:

```Text Cargo.toml
cln-rpc = "0.1.2"
```



Documentation for the `cln-rpc` crate is available at <https://docs.rs/cln-rpc/>.