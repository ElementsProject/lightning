---
title: "Running your node"
slug: "beginners-guide"
excerpt: "A guide to all the basics you need to get up and running immediately."
hidden: false
createdAt: "2022-11-18T14:27:50.098Z"
updatedAt: "2023-02-21T13:49:20.132Z"
---
## Starting `lightningd`

#### Regtest (local, fast-start) option

If you want to experiment with `lightningd`, there's a script to set up a `bitcoind` regtest test network of two local lightning nodes, which provides a convenient `start_ln` helper. See the notes at the top of the `startup_regtest.sh` file for details on how to use it.

```bash
. contrib/startup_regtest.sh
```

#### Mainnet Option

To test with real bitcoin,  you will need to have a local `bitcoind` node running:

```bash
bitcoind -daemon
```

Wait until `bitcoind` has synchronized with the network.

Make sure that you do not have `walletbroadcast=0` in your `~/.bitcoin/bitcoin.conf`, or you may run into trouble.  
Notice that running `lightningd` against a pruned node may cause some issues if not managed carefully, see [pruning](doc:bitcoin-core##using-a-pruned-bitcoin-core-node) for more information.

You can start `lightningd` with the following command:

```bash
lightningd --network=bitcoin --log-level=debug
```

This creates a `.lightning/` subdirectory in your home directory: see `man -l doc/lightningd.8` (or [???](???)) for more runtime options.

## Using The JSON-RPC Interface

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

## Care And Feeding Of Your New Lightning Node

Once you've started for the first time, there's a script called `contrib/bootstrap-node.sh` which will connect you to other nodes on the lightning network.

There are also numerous plugins available for Core Lightning which add capabilities: see the [Plugins](doc:plugins) guide, and check out the plugin collection at: <https://github.com/lightningd/plugins>, including [helpme](https://github.com/lightningd/plugins/tree/master/helpme) which guides you through setting up your first channels and customising your node.

For a less reckless experience, you can encrypt the HD wallet seed: see [HD wallet encryption](doc:backup-and-recovery#hsm-secret-backup).
