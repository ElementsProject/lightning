# c-lightning: A specification compliant Lightning Network implementation in C

c-lightning is a [standard compliant][std] implementation of the Lightning
Network protocol.
The Lightning Network is a scalability solution for Bitcoin, enabling
secure and instant transfer of funds between any two parties for any
amount.

[std]: https://github.com/lightningnetwork/lightning-rfc

For more information about the Lightning Network please refer to
http://lightning.network.

## Project Status

[![Build Status][travis-ci]][travis-ci-link]
[![Pull Requests Welcome][prs]][prs-link]
[![Irc][IRC]][IRC-link]

[travis-ci]: https://travis-ci.org/ElementsProject/lightning.svg?branch=master
[travis-ci-link]: https://travis-ci.org/ElementsProject/lightning
[prs]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat
[prs-link]: http://makeapullrequest.com
[IRC]: https://img.shields.io/badge/chat-on%20freenode-brightgreen.svg
[IRC-link]: https://webchat.freenode.net/?channels=c-lightning

This implementation is still very much a work in progress.
It can be used for testing, but __it should not be used for real funds__.
We do our best to identify and fix problems, and implement missing
features.

Any help testing the implementation, reporting bugs, or helping with
outstanding issues is very welcome.
Don't hesitate to reach out to us on IRC at
[#lightning-dev @ freenode.net][irc1], [#c-lightning @
freenode.net][irc2], or on the implementation-specific mailing list
[c-lightning@lists.ozlabs.org][ml1], or on the Lightning Network-wide
mailing list [lightning-dev@lists.linuxfoundation.org][ml2].

[irc1]: http://webchat.freenode.net/?channels=%23lightning-dev
[irc2]: http://webchat.freenode.net/?channels=%23c-lightning
[ml1]: https://lists.ozlabs.org/listinfo/c-lightning
[ml2]: https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev

## Getting Started

c-lightning currently only works on Linux (and possibly Mac OS with some
tweaking), and requires a locally (or remotely) running `bitcoind` (version 0.15 or
above) that is fully caught up with the network you're testing on.
Pruning (prune=n option in bitcoin.conf) is not currently supported.

### Installation

Please refer to the [installation documentation](doc/INSTALL.md) for
detailed instructions.
For the impatient here's the gist of it for Ubuntu and Debian:

    sudo apt-get update
    sudo apt-get install -y \
      autoconf automake build-essential git libtool libgmp-dev \
      libsqlite3-dev python python3 net-tools zlib1g-dev
    git clone https://github.com/ElementsProject/lightning.git
    cd lightning
    ./configure
    make

Or if you like to throw `docker` into the mix, you can use the official docker image either directly or as a base layer for more complex images.
The docker image is [elementsproject/lightningd](https://hub.docker.com/r/elementsproject/lightningd/) (from this [Dockerfile](Dockerfile)).
Image tags with `-dev` at the end are images built with `DEVELOPER=1`.
If you build the image yourself, you can use the build arg `DEVELOPER=1` to build c-lightning in developer mode.

It has the following environment variable:

* `EXPOSE_TCP` default to false, if true, use expose c-lightning RPC on port 9835. (Use this only for testing)

Here is an example of a docker-compose file with bitcoind and c-lightning on `testnet` which expose bitcoind's RPC interface on default ports `18332` and c-lightning API on port `9735`:

```
version: "3"
services:
  bitcoind:
    image: nicolasdorier/docker-bitcoin:0.16.3
    container_name: bitcoind
    environment:
      BITCOIN_EXTRA_ARGS: |
        testnet=1
        whitelist=0.0.0.0/0
        server=1
        rpcuser=rpcuser
        rpcpassword=rpcpass
    expose:
      - "18332"
    ports:
      - "0.0.0.0:18333:18333"
    volumes:
      - "bitcoin_datadir:/data"

  clightning_bitcoin:
    image: elementsproject/lightningd
    container_name: lightningd
    command:
      - --bitcoin-rpcconnect=bitcoind
      - --bitcoin-rpcuser=rpcuser
      - --bitcoin-rpcpassword=rpcpass
      - --network=testnet
      - --alias=myawesomenode
      - --log-level=debug
    environment:
      EXPOSE_TCP: "true"
    expose:
      - "9735"
    ports:
      - "0.0.0.0:9735:9735"
    volumes:
      - "clightning_bitcoin_datadir:/root/.lightning"
      - "bitcoin_datadir:/etc/bitcoin"
    links:
      - bitcoind

volumes:
  bitcoin_datadir:
  clightning_bitcoin_datadir:
```

Alternatively you can use `LIGHTNINGD_OPT`:

```
  clightning_bitcoin:
    image: elementsproject/lightningd
    environment:
      EXPOSE_TCP: "true"
      LIGHTNINGD_OPT: |
        bitcoin-rpcconnect=bitcoind
        bitcoin-rpcuser=rpcuser
        bitcoin-rpcpassword=rpcpass
        network=testnet
        alias=myawesomenode
        log-level=debug
```

To select the blockchain you are running LND on, you can alternatively use `LIGHTNINGD_CHAIN` with value `ltc` or `btc` and `LIGHTNINGD_NETWORK` with values `mainnet`, `testnet` or `regtest`).

### Starting `lightningd`

In order to start `lightningd` you will need to have a local `bitcoind`
node running in either testnet or regtest mode:

    bitcoind -daemon -testnet

Wait until `bitcoind` has synchronized with the testnet network.

Make sure that you do not have `walletbroadcast=0` in your
`~/.bitcoin/bitcoin.conf`, or you may run into trouble.
Notice that currently pruned nodes are not supported and may result in
`lightningd` being unable to synchronize with the blockchain.

You can start `lightningd` with the following command:

    lightningd/lightningd --network=testnet --log-level=debug

### Listing all commands:
`cli/lightning-cli help` will print a table of the API and lists the
following commands

### Opening a channel on the Bitcoin testnet

First you need to transfer some funds to `lightningd` so that it can
open a channel:

    # Returns an address <address>
    cli/lightning-cli newaddr

    # Returns a transaction id <txid>
    bitcoin-cli -testnet sendtoaddress <address> <amount_in_bitcoins>

`lightningd` will register the funds once the transaction is confirmed.

If you don't have any testcoins you can get a few from a faucet such as
[TPs' testnet faucet][tps] or [Kiwi's testnet faucet][kiw].
You can send it directly to the `lightningd` address.

You may need to generate a p2sh-segwit address if the faucet does not support
bech32:

    # Return a p2sh-segwit address
    cli/lightning-cli newaddr p2sh-segwit

[tps]: http://tpfaucet.appspot.com/
[kiw]: https://testnet.manu.backend.hamburg/faucet

Confirm `lightningd` got funds by:

    # Returns an array of on-chain funds.
    cli/lightning-cli listfunds

Once `lightningd` has funds, we can connect to a node and open a channel.
Let's assume the **remote** node is accepting connections at `<ip>`
(and optional `<port>`, if not 9735) and has the node ID `<node_id>`:

```
cli/lightning-cli connect <node_id> <ip> [<port>]
cli/lightning-cli fundchannel <node_id> <amount_in_satoshis>
```

This opens a connection and, on top of that connection, then opens
a channel.
The funding transaction needs 1 confirmation in order for the channel
to be usable, and 6 to be broadcast for others to use.
You can check the status of the channel using `cli/lightning-cli
listpeers`, which after 3 confirmations (1 on testnet) should say
that `state` is `CHANNELD_NORMAL`; after 6 confirmations you can use
`cli/lightning-cli listchannels` to verify that the `public` field is now
`true`.

### Different states
* `OPENINGD` means that `lightning_openingd` is negotiating channel
  opening.
* `CHANNELD_AWAITING_LOCKIN` means that `lightning_channeld` is waiting
  until the minimum number of confirmation on the channel funding
  transaction.
* `CHANNELD_NORMAL` means your channel is operating normally.
* `CHANNELD_SHUTTING_DOWN` means one or both sides have asked to shut
  down the channel, and we're waiting for existing HTLCs to clear.
* `CLOSINGD_SIGEXCHANGE` means we're trying to negotiate the fee for
  the mutual close transaction.
* `CLOSINGD_COMPLETE` means we've broadcast our mutual close
  transaction (which spends the funding transaction) , but haven't seen
  it in a block yet.
* `FUNDING_SPEND_SEEN` means we've seen the funding transaction spent.
* `ONCHAIN` means that the `lightning_onchaind` is tracking the onchain
  closing of the channel.
* `AWAITING_UNILATERAL` means that we're waiting for a unilateral close to hit the blockchain.

All these states have more information about what's going on in the
`status` field in `listpeers`.

### Sending and receiving payments

Payments in Lightning are invoice based.
The recipient creates an invoice with the expected `<amount>` in
millisatoshi (or `"any"` for a donation), a unique `<label>` and a
`<description>` the payer will see:

```
cli/lightning-cli invoice <amount> <label> <description>
```

This returns some internal details, and a standard invoice
string called `bolt11` (named after the [BOLT #11 lightning
spec][BOLT11]).

[BOLT11]: https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md

The sender can feed this `bolt11` string to the `decodepay` command to
see what it is, and pay it simply using the `pay` command:

```
cli/lightning-cli pay <bolt11>
```

Note that there are lower-level interfaces (and more options to these
interfaces) for more sophisticated use.

## Configuration File
lightningd can be configured either by passing options via the command
line, or via a configuration file.
Command line options will always override the values in the configuration
file.

To use a configuration file, create a file named "config" within your
".lightning" directory. Usually, this will be ~/.lightning/config

Configuration options are set using a key=value pair on each line of
the file, for example:

```
alias=SLEEPYDRAGON
rgb=008000
port=9735
network=testnet
```

For a full list of possible lightningd configuration options, run:
```
lightningd/lightningd --help
```

## Further information

### Developers
Developers wishing to contribute should start with the developer guide [here](doc/HACKING.md). 


### JSON RPC
JSON-RPC interface is documented in the following manual pages:

* [invoice](doc/lightning-invoice.7.txt)
* [listinvoices](doc/lightning-listinvoices.7.txt)
* [waitinvoice](doc/lightning-waitinvoice.7.txt)
* [waitanyinvoice](doc/lightning-waitanyinvoice.7.txt)
* [delinvoice](doc/lightning-delinvoice.7.txt)
* [getroute](doc/lightning-getroute.7.txt)
* [sendpay](doc/lightning-sendpay.7.txt)
* [pay](doc/lightning-pay.7.txt)
* [listpayments](doc/lightning-listpayments.7.txt)
* [decodepay](doc/lightning-decodepay.7.txt)

For simple access to the JSON-RPC interface you can use the
`cli/lightning-cli` tool, or the [python API client](contrib/pylightning).
