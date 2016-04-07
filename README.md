# Lightning Protocol Reference Implementation

In this repository we're developing a reference implementation of
bitcoin lightning (see:
[http://lightning.network](http://lightning.network) which proposed
the original "lightning network").

This implementation is being developed in parallel with the protocol
definition, which you can find [https://github.com/rustyrussell/lightning](on my fork of the protocol description repository).

So far, we are working on the [https://github.com/rustyrussell/lightning/blob/master/communications/low/01-encryption.md](inter-node encryption) and [https://github.com/rustyrussell/lightning/blob/master/communications/low/02-wire-protocol.md](transaction negotiation) phases.

Later steps will enhance the protocol to network individual daemons,
advertise their IP addresses, publish routes and fees, and use that
information to pay specific nodes.  These details are currently being
hashed out on the [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev) and the IRC channel [#lightning-dev](https://botbot.me/freenode/lightning-dev/) on Freenode.

The protocol requires features not currently in bitcoin, but can be tested
with bitcoin (on testnet) with OP_NOP substitution.

Final note: This is very much a testbed and work in progress; expect
All The Things to change, all the time.

Welcome aboard!

Rusty.
