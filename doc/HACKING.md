Welcome, fellow coder!

This repository contains a code to run a lightning protocol daemon.
It's broken into subdaemons, with the idea being that we can add more
layers of separation between different clients and extra barriers to
exploits.

It is designed to implement the lightning protocol as specified in
[various BOLTs](https://github.com/lightningnetwork/lightning-rfc).

Getting Started
---------------
It's in C, to encourage alternate implementations.  It uses the [Linux
coding style](https://www.kernel.org/doc/html/v4.10/process/coding-style.html). 
Patches are welcome!

To read the code, you'll probably need to understand ccan/tal: it's a
hierarchical memory allocator, where each allocation has a parent, and
thus lifetimes are grouped.  eg. a `struct bitcoin_tx` has a pointer
to an array of `struct bitcoin_tx_input`; they are allocated off the
`struct bitcoind_tx`, so freeing the `struct bitcoind_tx` frees them
all.  Tal also supports destructors, which are usually used to remove
things from lists, etc.

Some routines use take(): take() marks a pointer as to be consumed
(e.g. freed automatically before return) by a called function.  It can
safely accept NULL pointers.  Functions whose prototype in headers has
the macro TAKES can have the specific argument as a take() call.  Use
this sparingly, as it can be very confusing.

The more complex daemons use async io (ccan/io): you register callbacks and they
happen once I/O is available, then you return what to do next.  This
does not use threads, so the code flow is generally fairly simple.

The Components
--------------
Here's a list of parts, with notes:

* ccan - useful routines from http://ccodearchive.net
  - Use make update-ccan to update it.
  - Use make update-ccan CCAN_NEW="mod1 mod2..." to add modules
  - Do not edit this!  If you want a wrapper, add one to common/utils.h.

* bitcoin/ - bitcoin script, signature and transaction routines.
  - Not a complete set, but enough for our purposes.

* external/ - external libraries from other sources
  - libbacktrace - library to provide backtraces when things go wrong.
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
  - mockup.sh / update-mocks.sh: tools to generate mock functions for unit tests.

* devtools/ - tools for developers
   - Currently just bolt11-cli for decoding bolt11

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

Debugging
---------

You can debug crashing subdaemons with the argument
`--dev-debugger=lightning_channeld`, where `channeld` is the subdaemon name. It
will print out (to stderr) a command such as:

    gdb -ex 'attach 22398' -ex 'p debugger_connected=1' lightningd/lightning_hsmd

Run this command to start debugging. You may need to type `return` one more time
to exit the infinite while loop, otherwise you can type `continue` to begin.

Database
--------

c-lightning state is persisted in `lightning-dir`. It is a sqlite database
stored in the `lightningd.sqlite3` file, typically under `~/.lightning`. You can
run queries against this file like so:

    $ sqlite3 ~/.lightning/lightningd.sqlite3 "SELECT HEX(prev_out_tx), prev_out_index, status FROM outputs"

Or you can launch into the sqlite3 repl and check things out from there:

    $ sqlite3 ~/.lightning/lightningd.sqlite3
    SQLite version 3.21.0 2017-10-24 18:55:49
    Enter ".help" for usage hints.
    sqlite> .tables
    channel_configs  invoices         peers            vars
    channel_htlcs    outputs          shachain_known   version
    channels         payments         shachains
    sqlite> .schema outputs
    ...

Some data is stored as raw bytes, use `HEX(column)` to pretty print these.

Make sure that clightning is not running when you query the database, as some
queries may lock the database and cause crashes.

#### Common variables
Table `vars` contains global variables used by lightning node.

    $ sqlite3 ~/.lightning/lightningd.sqlite3
    SQLite version 3.21.0 2017-10-24 18:55:49
    Enter ".help" for usage hints.
    sqlite> .headers on
    sqlite> select * from vars;
    name|val
    next_pay_index|2
    bip32_max_index|4
    ...

Note:
* `next_pay_index` last resolved invoice counter.
* `bip32_max_index` last wallet derivation counter. 

Every times `newaddr` command is called, a new wallet is generated with Bip32 derivation and `bip32_max_index` counter is increased to the last derivation index.
Each address generated after `bip32_max_index` is not included as lightning funds.


Testing
-------

There are three kinds of tests.  For best results, you should have
valgrind installed, and build with DEVELOPER=1 (currently the default).

* source tests - run by `make check-source`, looks for whitespace,
  header order, and checks formatted quotes from BOLTs if BOLTDIR
  exists (currently disabled, since BOLTs are being re-edited).

* unit tests - run by `make check`, these are run-*.c files in test/
  subdirectories which can test routines inside C source files.  You
  should insert `/* AUTOGENERATED MOCKS START */` and `/* AUTOGENERATED MOCKS END */`
  lines, and `make update-mocks` will automatically generate stub functions
  which will allow you to link (which will conveniently crash if they're called).

* blackbox tests - run by `make check` or directly as
  `PYTHONPATH=contrib/pylightning DEVELOPER=1 python3 tests/test_lightningd.py -f`.
  You can run these much faster by putting `NO_VALGRIND=1` after DEVELOPER=1, or
  after `make check`, which has the added bonus of doing memory leak detection.
  You can also append `LightningDTests.TESTNAME` to run a single test.

Our Travis CI instance (see `.travis.yml`) runs all these for each pull request.

Further Information
-------------------

Feel free to ask questions on the lightning-dev mailing list, or on #c-lightning on IRC, or email me at rusty@rustcorp.com.au.

Cheers!<br>
Rusty.
