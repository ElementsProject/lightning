Welcome, fellow coder!

This repository contains a code to run a lightning protocol daemon.
It's broken into subdaemons, with the idea being that we can add more
layers of separation between different clients and extra barriers to
exploits.

It is designed to implement the lightning protocol as specified in
[various BOLTs](https://github.com/lightningnetwork/lightning-rfc).

Getting Started
---------------
It's in C, to encourage alternate implementations.  It uses the Linux
coding style.  Patches are welcome!

To read the code, you'll probably need to understand ccan/tal: it's a
hierarchical memory allocator, where each allocation has a parent, and
thus lifetimes are grouped.  eg. a 'struct bitcoin_tx' has a pointer
to an array of 'struct bitcoin_tx_input'; they are allocated off the
'struct bitcoind_tx', so freeing the 'struct bitcoind_tx' frees them
all.  Tal also supports destructors, which are usually used to remove
things from lists, etc.

The daemons mostly use async io (ccan/io): you register callbacks and they
happen once I/O is available, then you return what to do next.  This
does not use threads, so the code flow is generally fairly simple.

Here's a list of parts, with notes:

* ccan - useful routines from http://ccodearchive.net
  - Use make update-ccan to update it.
  - Use make update-ccan CCAN_NEW="mod1 mod2..." to add modules

* bitcoin/ - bitcoin script, signature and transaction routines.
  - Not a complete set, but enough for our purposes.

* external/ - external libraries from other sources
  - libsodium - encryption library (should be replaced soon with built-in)
  - libwally-core - bitcoin helper library
  - secp256k1 - bitcoin curve encryption library within libwally-core
  - jsmn - tiny JSON parsing helper
  - libbase58 - base58 address encoding/decoding library.

* tools/ - tools for building
  - check-bolt.c: check the source code contains correct BOLT quotes
    (as used by check-source)
  - generate-wire.py: generate marshal/unmarshal routines from
    extracts from BOLT specs, and as specified by subdaemons.

* contrib/ - python support and other stuff which doesn't belong :)

* wire/ - basic marshalling/un

* common/ - routines needed by any two or more of the directories below

* cli/ - commandline utility to control lightning daemon.

* lightningd/ - master daemon which controls the subdaemons and passes peer file descriptors between them.

* wallet/ - database code used by master for tracking what's happening.

* hsmd/ - daemon which looks after the cryptographic secret, and performs commitment signing.

* gossipd/ - daemon to chat to peers which don't have any channels, and maintains routing information and broadcasts gossip.

* openingd/ - daemon to open a channel for a single peer.

* channeld/ - daemon to operate a single peer once channel is operating normally.

* closingd/ - daemon to handle mutual closing negotiation with a single peer.

* onchaind/ - daemon to hand a single channel which has had its funding transaction spent.

Feel free to ask questions on the lightning-dev mailing list, or on #c-lightning on IRC, or email me at rusty@rustcorp.com.au.

Cheers!<br>
Rusty.
