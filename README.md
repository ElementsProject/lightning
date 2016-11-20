# Lightning Protocol Reference Implementation

In this repository we're developing a reference implementation of
bitcoin lightning (see:
[http://lightning.network](http://lightning.network) which proposed
the original "lightning network").

This implementation is being developed in parallel with the protocol
definition, which you can find [on my fork of the protocol description repository](https://github.com/rustyrussell/lightning).

If you're interested in using the daemon to test payments, the
JSON-RPC interface is documented in the following manual pages:
* [invoice](doc/lightning-invoice.7.txt)
* [listinvoice](doc/lightning-listinvoice.7.txt)
* [waitinvoice](doc/lightning-waitinvoice.7.txt)
* [delinvoice](doc/lightning-delinvoice.7.txt)
* [getroute](doc/lightning-getroute.7.txt)
* [sendpay](doc/lightning-sendpay.7.txt)

Steps:

0.  If you're running a previous version, you'll need to shut it down
    (maybe close channels first) and delete the $HOME/.lightning directory.
1.  [Install and compile](INSTALL.md) the requirements.
2.  Make sure bitcoind is running in testnet mode, and has the latest
    blocks.
3.  Get some test bitcoins, such as from [TPs' testnet faucet](http://tpfaucet.appspot.com/).
3.  If you want others to connect to your lightningd, create $HOME/.lightning/config and put `port=8334` in it (or any other port).
4.  Run `daemon/lightningd`.
6.  Run `daemon/lightning-cli getinfo` to check it's working.
7.  Find a node using `daemon/lightning-cli getnodes` (this will populate
    over time).
8.  Create a new connection to the node using `contrib/lightning-open-channel
    ADDRESS PORT AMOUNT` where AMOUNT is in BTC (.04294967 is the maximum
    possible).  If successful, this will return only once a block has been
    mined with the funding transaction in it.
9.  You can create more channels if you wish.
10.  You can accept payment using `daemon/lightning-cli invoice
    MILLISATOSHI LABEL`; it will give you a payment hash to give to the
    payer.
11. You can send payments using `contrib/lightning-pay DEST-ID MILLISATOSHI PAYMENT-HASH`.

Final note: This is very much a testbed and work in progress; expect
All The Things to change, all the time.

Welcome aboard!

Rusty.
