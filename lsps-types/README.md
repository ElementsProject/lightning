# `lsps-types`: LSPS protocol types

Protocol types for the Lightning Service Provider specifications
[LSPS0][bLIP-50] and [LSPS2][bLIP-52], and the LSPS2 opening fee
computation.

Both sides of an LSPS2 JIT channel, the client and the LSP, use this
crate, so they share one implementation of the message types and of
the opening fee computation.

It has no async runtime or Core Lightning dependencies, so it can be
used by any LSPS implementation.

[bLIP-50]: https://github.com/lightning/blips/blob/master/blip-0050.md
[bLIP-52]: https://github.com/lightning/blips/blob/master/blip-0052.md
