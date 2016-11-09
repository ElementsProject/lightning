Welcome, fellow coder!

This repository contains a prototype for testing the lightning protocols.

Getting Started
---------------
It's in C, to encourage alternate implementations.  It uses the Linux
coding style.  Patches are welcome!  See the TODO.md file if you want
ideas.

To read the code, you'll probably need to understand ccan/tal: it's a
heirarchical memory allocator, where each allocation has a parent, and
thus lifetimes are grouped.  eg. a 'struct bitcoin_tx' has a pointer
to an array of 'struct bitcoin_tx_input'; they are allocated off the
'struct bitcoind_tx', so freeing the 'struct bitcoind_tx' frees them
all.  Tal also supports destructors, which are usually used to remove
things from lists, etc.

The daemon uses async io (ccan/io): you register callbacks and they
happen once I/O is available, then you return what to do next.  This
does not use threads, so the code flow is generally fairly simple.

Here's a list of parts, with notes:

* ccan - useful routines from http://ccodearchive.net
  - Use make update-ccan to update it.
  - Use make update-ccan CCAN_NEW="mod1 mod2..." to add modules

* bitcoin/ - bitcoin script, signature and transaction routines.
  - Not a complete set, but enough for our purposes.

* secp256k1/ - a copy of libsecp256k1.
  - TODO: Replace this will the library once 1.0 is well distributed.

* test/ - A few standalone test programs
  - test_onion: C code to generate and decode the routing onion (Obsolete; will replace with Sphynx!)
  - test_state_coverage: routine to test state machine.

* daemon/ - The start of a lightningd daemon and lightning-cli
  - Networking and comms:
    - cryptopkt: cryptographic handshake and comms routines.
    - dns: async dns lookup
    - netaddr: wrapper type for network addresses.

  - JSON and command support:
    - jsmn/ : a "minimalistic JSON parser" from http://zserge.com/jsmn.html
    - json: simple wrappers around jsmn for parsing and creating JSON
    - jsonrpc: routines for handing JSON commands (async).
    - lightning-cli: simple lightning command line client.

  - Misc:
    - configdir: support for ~/.lightning/config
    - log: logging routines
    - pseudorand: pseudorandom wrapper
    - secrets: routines for using secret keys.
    - timeout: timer support.

  - Dealing with bitcoin events:
    - bitcoind: communication with bitcoind to monitor/send txs.
    - watch: wrapper for watching specific events.

  - Core code:
    - lightningd: main routine for lightning
    - packets: per-peer packet creation and acceptance routines 
    - peer: peer routines and data structure.

* Top level:
  - funding: tracking of state of a channel, including feesplit logic.
  - state: core state machine for the lightning protocol.
  - Helpers for lightning-specific transactions
    - close_tx: mutual close transaction
    - commit_tx: commit transaction (optionally with htlcs)
    - permute_tx: code to permute transactions outputs for anon
  - Various helper routines:
    - find_p2sh_out: helper to find a given tx output.
    - gen_state_names: source generator for enum names.
    - opt_bits: commandline parser for "bits" (100 satoshi)
    - protobuf_convert: conversion to/from protobufs.
    - version: helper to print the version and build features.

Feel free to ask questions on the lightning-dev mailing list, or on #lightning-dev on IRC, or email me at rusty@rustcorp.com.au.

Cheers!<br>
Rusty.
