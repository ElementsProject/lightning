# Lightning Protocol Reference Implementation

In this repository we're developing a reference implementation of
bitcoin lightning (see:
[http://lightning.network](http://lightning.network) which proposed
the original "lightning network").

The first step was to develop a wire protocol for nodes to talk to
each other.  The wire protocol is documented in
[lightning.proto](lightning.proto) (a
[protobuf](https://developers.google.com/protocol-buffers/) definition
file).  There are command line utilities to create and process various
packets in [test-cli](test-cli/HOWTO-USE.md).

The second step is to create a daemon which uses that protocol to
communicate with others to set up channels and make simple payments.
This also involves monitoring the blockchain for transactions.  This
is where development is currently occurring.

Later steps will enhance the protocol to network individual daemons,
advertize their IP addresses, publish routes and fees, and use that
information to pay specific nodes.  These details are currently being
hashed out on the [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/lightning-dev) and the IRC channel [#lightning-dev](https://botbot.me/freenode/lightning-dev/) on Freenode.

The protocol requires features not currently in bitcoin, so by default
it runs on top of the sidechain [Elements
Alpha](https://github.com/ElementsProject/elements).  It can be tested
with bitcoin (on testnet) with OP_NOP substitution, at the top level
Makefile.

Final note: This is very much a testbed and work in progress; expect
All The Things to change, all the time.

Welcome aboard!

Rusty.
