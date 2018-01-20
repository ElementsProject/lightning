# c-lightning: A specification compliant Lightning Network implementation in C

c-lightning is a [standard compliant](https://github.com/lightningnetwork/lightning-rfc) implementation of the Lightning Network protocol.
The Lightning Network is a scalability solution for Bitcoin, enabling secure and instant transfer of funds between any two parties for any amount.

For more information about the Lightning Network please refer to http://lightning.network.

## Project Status

This implementation is still very much a work in progress. It can be used for testing, but __it should not be used for real funds__.
We do our best to identify and fix problems, and implement missing features.

Any help testing the implementation, reporting bugs, or helping with outstanding issues is very welcome.
Don't hesitate to reach out to us on IRC at [#lightning-dev @ freenode.net](http://webchat.freenode.net/?channels=%23lightning-dev), [#c-lightning @ freenode.net](http://webchat.freenode.net/?channels=%23c-lightning), or on the mailing list [lightning-dev@lists.linuxfoundation.org](https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev).

## Getting Started

c-lightning currently only works on Linux (and possibly Mac OS with some tweaking), and requires a locally running `bitcoind` (version 0.15 or above) that is fully caught up with the network you're testing on.

### Installation

Please refer to the [installation documentation](doc/INSTALL.md) for detailed instructions.
For the impatient here's the gist of it for Ubuntu and Debian:

```
sudo apt-get install -y autoconf automake build-essential git libtool libgmp-dev libsqlite3-dev python python3 net-tools
git clone https://github.com/ElementsProject/lightning.git
cd lightning
make
```

Or if you like to throw `docker` into the mix:

```
sudo docker run \
	-v $HOME/.lightning:/root/.lightning \
	-v $HOME/.bitcoin:/root/.bitcoin \
	-p 9735:9735 \
	cdecker/lightningd:latest
```
### Starting `lightningd`

In order to start `lightningd` you will need to have a local `bitcoind` node running in either testnet or regtest mode:

```
bitcoind -daemon -testnet
```

Wait until `bitcoind` has synchronized with the testnet network. In case you use regtest, make sure you generate at least 432 blocks to activate SegWit.

Make sure that you do not have `walletbroadcast=0` in your
`~/.bitcoin/bitcoin.conf`, or you may run into trouble.

You can start `lightningd` with the following command:

```
lightningd/lightningd --network=testnet --log-level=debug
```

### Listing all commands:
`cli/lighting-cli help` will print a table of the API and lists the following commands

### Opening a channel on the Bitcoin testnet

First you need to transfer some funds to `lightningd` so that it can open a channel:

```
# Returns an address <address>
cli/lightning-cli newaddr

# Returns a transaction id <txid>
bitcoin-cli -testnet sendtoaddress <address> <amount>
```

`lightningd` will register the funds once the transaction is
confirmed.

If you don't have any testcoins you can get a few from a faucet
such as [TPs' testnet faucet](http://tpfaucet.appspot.com/) or
[Kiwi's testnet faucet](https://testnet.manu.backend.hamburg/faucet).
You can send it directly to the `lightningd` address.

Confirm `lightningd` got funds by:

```
# Returns an array of on-chain funds.
cli/lightning-cli listfunds
```

Once `lightningd` has funds, we can connect to a node and open a
channel.
Let's assume the **remote** node is accepting connections at
`<ip>` (and optional `<port>`, if not 9735) and has the node ID
`<node_id>`:

```
cli/lightning-cli connect <node_id> <ip> [<port>]
cli/lightning-cli fundchannel <node_id> <amount>
```

This opens a connection and, on top of that connection, then opens a channel.
The funding transaction needs 1 confirmations in order for the channel to be usable, and 6 to be broadcast for others to use.
You can check the status of the channel using `cli/lightning-cli listpeers`, which after 1 confirmation should say that `state` is `CHANNELD_NORMAL`; after 6 confirmations you can use `cli/lightning-cli listchannels` to verify that the `public` field is now `true`.

### Sending and receiving payments

Payments in Lightning are invoice based.
The recipient creates an invoice with the expected `<amount>` in millisatoshi (or `"any"` for a donation), a unique `<label>` and a `<description>` the payer will see:

```
cli/lightning-cli invoice <amount> <label> <description>
```

This returns some internal details, and a standard invoice string called `bolt11` (named after the [BOLT #11 lightning spec](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md)).

The sender can feed this `bolt11` string to the `decodepay` command to see what it is, and pay it simply using the `pay` command:

```
cli/lightning-cli pay <bolt11>
```

Note that there are lower-level interfaces (and more options to these interfaces) for more sophisticated use.

## Further information

JSON-RPC interface is documented in the following manual pages:

* [invoice](doc/lightning-invoice.7.txt)
* [listinvoice](doc/lightning-listinvoice.7.txt)
* [waitinvoice](doc/lightning-waitinvoice.7.txt)
* [waitanyinvoice](doc/lightning-waitanyinvoice.7.txt)
* [delinvoice](doc/lightning-delinvoice.7.txt)
* [getroute](doc/lightning-getroute.7.txt)
* [sendpay](doc/lightning-sendpay.7.txt)

For simple access to the JSON-RPC interface you can use the `cli/lightning-cli` tool, or the [python API client](contrib/pylightning).
