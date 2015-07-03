Strawman protocol for lightning channels.

The wire protocol is documented in [lightning.proto](lightning.proto)
(a [protobuf](https://developers.google.com/protocol-buffers/)
definition file).

There are command line utilities to create and process various packets
in [test-cli](test-cli/HOWTO-USE.md).

It requires features not currently in bitcoin, so it runs on top of
the sidechain [Elements Alpha](https://github.com/ElementsProject/elements)

This is very much a testbed and work in progress; expect All The
Things to change, all the time.

Cheers,

Rusty.
