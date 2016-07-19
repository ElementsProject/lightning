# Lightning Protocol Reference Implementation

In this repository we're developing a reference implementation of
bitcoin lightning (see:
[http://lightning.network](http://lightning.network) which proposed
the original "lightning network").

This implementation is being developed in parallel with the protocol
definition, which you can find [on my fork of the protocol description repository](https://github.com/rustyrussell/lightning).

So far, we are working on the [inter-node encryption](https://github.com/rustyrussell/lightning-rfc/blob/master/bolts/01-encryption.md) and [transaction negotiation](https://github.com/rustyrussell/lightning-rfc/blob/master/bolts/02-wire-protocol.md) phases.

Later steps will enhance the protocol to network individual daemons,
advertise their IP addresses, publish routes and fees, and use that
information to pay specific nodes.  These details are currently being
hashed out on the [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev) and the IRC channel [#lightning-dev](https://botbot.me/freenode/lightning-dev/) on Freenode.

Final note: This is very much a testbed and work in progress; expect
All The Things to change, all the time.

Welcome aboard!

Rusty.
