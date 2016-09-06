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

So far, we have [inter-node encryption](https://github.com/rustyrussell/lightning-rfc/blob/master/bolts/01-encryption.md) and [transaction negotiation](https://github.com/rustyrussell/lightning-rfc/blob/master/bolts/02-wire-protocol.md).

Routing between non-adjacent nodes is currently done manually using the 'dev-addroute' command; later on daemons will
advertise their IP addresses, and publish routes and fees.  These details are currently being
hashed out on the [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev) and the IRC channel [#lightning-dev](https://botbot.me/freenode/lightning-dev/) on Freenode.

Final note: This is very much a testbed and work in progress; expect
All The Things to change, all the time.

Welcome aboard!

Rusty.
