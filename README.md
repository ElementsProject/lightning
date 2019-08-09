# c-lightning: A specification compliant Lightning Network implementation in C

c-lightning is a lighweight, highly customizable and [standard compliant][std] implementation of the Lightning Network protocol.


## Project Status

[![Build Status][travis-ci]][travis-ci-link]
[![Pull Requests Welcome][prs]][prs-link]
[![Irc][IRC]][IRC-link]
[![Documentation Status](https://readthedocs.org/projects/lightning/badge/?version=docs)][docs]

This implementation has been in production use on the Bitcoin mainnet since early 2018, with the launch of the [Blockstream Store][blockstream-store-blog].
We recommend getting started by experimenting on `testnet`, but the implementation is considered stable and can be safely used on mainnet.

Any help testing the implementation, reporting bugs, or helping with outstanding issues is very welcome.
Don't hesitate to reach out to us on IRC at [#lightning-dev @ freenode.net][irc1], [#c-lightning @ freenode.net][irc2], or on the implementation-specific mailing list [c-lightning@lists.ozlabs.org][ml1], or on the Lightning Network-wide mailing list [lightning-dev@lists.linuxfoundation.org][ml2].

## Getting Started

c-lightning only works on Linux and Mac OS, and requires a locally (or remotely) running `bitcoind` (version 0.16 or above) that is fully caught up with the network you're testing on.
Pruning (`prune=n` option in `bitcoin.conf`) is partially supported, see [here](#pruning) for more details.

### Installation

There are 4 supported installation options:

 - Installation from the [Ubuntu PPA][ppa]
 - Installation of a pre-compiled binary from the [release page][releases] on Github
 - Using one of the [provided docker images][dockerhub] on the Docker Hub
 - Compiling the source code yourself (suggested mainly for developers or if you need one of the still [unreleased features][changelog-unreleased])

Please refer to the [PPA release page][ppa] and the [installation documentation](doc/INSTALL.md) for detailed instructions.

For the impatient here's the gist of it for Ubuntu:

```bash
sudo apt-get install -y software-properties-common
sudo add-apt-repository -u ppa:bitcoin/bitcoin
sudo add-apt-repository -u ppa:lightningnetwork/ppa
sudo apt-get install bitcoind lightningd
```

### Starting `lightningd`

In order to start `lightningd` you will need to have a local `bitcoind` node running (in this case we start `testnet`):

```bash
bitcoind -daemon -testnet
```

Wait until `bitcoind` has synchronized with the testnet network.

Make sure that you do not have `walletbroadcast=0` in your `~/.bitcoin/bitcoin.conf`, or you may run into trouble.
Notice that running `lightningd` against a pruned node may cause some issues if not managed carefully, see [below](#pruning) for more information.

You can start `lightningd` with the following command:

```bash
lightningd --network=testnet --log-level=debug
```

Please refer to `lightningd --help` for all other command line options.

### JSON-RPC Interface

c-lightning exposes a [JSON-RPC 2.0][jsonrpcspec] interface over a Unix Domain socket located in its home directory (default: `$HOME/.lightning`).
The Unix Domain Socket has the advantage of not being exposed over the network by default, allowing users to add their own authentication and authorization mechanism, while still providing a fully functional RPC interface out of the box.

You can use `lightning-cli help` to print a table of the available RPC methods that can be called.
The JSON-RPC interface is also documented in the following manual pages:

* [invoice](doc/lightning-invoice.7.txt)
* [listinvoices](doc/lightning-listinvoices.7.txt)
* [waitinvoice](doc/lightning-waitinvoice.7.txt)
* [waitanyinvoice](doc/lightning-waitanyinvoice.7.txt)
* [delinvoice](doc/lightning-delinvoice.7.txt)
* [getroute](doc/lightning-getroute.7.txt)
* [sendpay](doc/lightning-sendpay.7.txt)
* [pay](doc/lightning-pay.7.txt)
* [listpays](doc/lightning-listpays.7.txt)
* [decodepay](doc/lightning-decodepay.7.txt)

For simple access to the JSON-RPC interface you can use the `lightning-cli` tool, or the [python API client](contrib/pylightning).

### Opening a channel on the Bitcoin testnet

First you need to transfer some funds to `lightningd` so that it can
open a channel:

```bash
# Returns an address <address>
lightning-cli newaddr

# Returns a transaction id <txid>
bitcoin-cli -testnet sendtoaddress <address> <amount_in_bitcoins>
```

`lightningd` will register the funds once the transaction is confirmed.

You may need to generate a p2sh-segwit address if the faucet does not support bech32:

```bash
# Return a p2sh-segwit address
lightning-cli newaddr p2sh-segwit
```

Confirm `lightningd` got funds by:

```bash
# Returns an array of on-chain funds.
lightning-cli listfunds
```

Once `lightningd` has funds, we can connect to a node and open a channel.
Let's assume the **remote** node is accepting connections at `<ip>`
(and optional `<port>`, if not 9735) and has the node ID `<node_id>`:

```bash
lightning-cli connect <node_id> <ip> [<port>]
lightning-cli fundchannel <node_id> <amount_in_satoshis>
```

This opens a connection and, on top of that connection, then opens
a channel.
The funding transaction needs 3 confirmation in order for the channel to be usable, and 6 to be announced for others to use.
You can check the status of the channel using `lightning-cli listpeers`, which after 3 confirmations (1 on testnet) should say that `state` is `CHANNELD_NORMAL`; after 6 confirmations you can use `lightning-cli listchannels` to verify that the `public` field is now `true`.

### Sending and receiving payments

Payments in Lightning are invoice based.
The recipient creates an invoice with the expected `<amount>` in
millisatoshi (or `"any"` for a donation), a unique `<label>` and a
`<description>` the payer will see:

```bash
lightning-cli invoice <amount> <label> <description>
```

This returns some internal details, and a standard invoice string called `bolt11` (named after the [BOLT #11 lightning spec][BOLT11]).

[BOLT11]: https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md

The sender can feed this `bolt11` string to the `decodepay` command to see what it is, and pay it simply using the `pay` command:

```bash
lightning-cli pay <bolt11>
```

Note that there are lower-level interfaces (and more options to these
interfaces) for more sophisticated use.

## Configuration File

`lightningd` can be configured either by passing options via the command line, or via a configuration file.
Command line options will always override the values in the configuration file.

To use a configuration file, create a file named `config` within your lightning directory.
By default this will be `$HOME/.lightning/config`.

Configuration options are set using a key=value pair on each line of the file, for example:

```ini
alias=SLEEPYDRAGON
rgb=008000
network=testnet
```

For a full list of possible lightningd configuration options, run:

```bash
lightningd --help
```

## Further information

### Pruning

c-lightning requires JSON-RPC access to a fully synchronized `bitcoind` in order to synchronize with the Bitcoin network.
Access to ZeroMQ is not required and `bitcoind` does not need to be run with `txindex` like other implementations.
The lightning daemon will poll `bitcoind` for new blocks that it hasn't processed yet, thus synchronizing itself with `bitcoind`.
If `bitcoind` prunes a block that c-lightning has not processed yet, e.g., c-lightning was not running for a prolonged period, then `bitcoind` will not be able to serve the missing blocks, hence c-lightning will not be able to synchronize anymore and will be stuck.
In order to avoid this situation you should be monitoring the gap between c-lightning's blockheight using `lightning-cli getinfo` and `bitcoind`'s blockheight using `bitcoin-cli getblockchaininfo`.
If the two blockheights drift apart it might be necessary to intervene.

### Developers
Developers wishing to contribute should start with the developer guide [here](doc/HACKING.md).


[blockstream-store-blog]: https://blockstream.com/2018/01/16/en-lightning-charge/
[std]: https://github.com/lightningnetwork/lightning-rfc
[travis-ci]: https://travis-ci.org/ElementsProject/lightning.svg?branch=master
[travis-ci-link]: https://travis-ci.org/ElementsProject/lightning
[prs]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat
[prs-link]: http://makeapullrequest.com
[IRC]: https://img.shields.io/badge/chat-on%20freenode-brightgreen.svg
[IRC-link]: https://webchat.freenode.net/?channels=c-lightning
[irc1]: http://webchat.freenode.net/?channels=%23lightning-dev
[irc2]: http://webchat.freenode.net/?channels=%23c-lightning
[ml1]: https://lists.ozlabs.org/listinfo/c-lightning
[ml2]: https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev
[docs]: https://lightning.readthedocs.org
[ppa]: https://launchpad.net/~lightningnetwork/+archive/ubuntu/ppa
[releases]: https://github.com/ElementsProject/lightning/releases
[dockerhub]: https://hub.docker.com/r/elementsproject/lightningd/
[jsonrpcspec]: https://www.jsonrpc.org/specification
[changelog-unreleased]: https://github.com/ElementsProject/lightning/blob/master/CHANGELOG.md#unreleased
