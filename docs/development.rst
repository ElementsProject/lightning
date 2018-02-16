Development
***********

It's in C, to encourage alternate implementations.  It uses the `Linux coding style <https://www.kernel.org/doc/html/v4.10/process/coding-style.html>`_.
Patches are welcome!

To read the code, you'll probably need to understand ccan/tal: it's a
hierarchical memory allocator, where each allocation has a parent, and
thus lifetimes are grouped.  eg. a `struct bitcoin_tx` has a pointer
to an array of `struct bitcoin_tx_input`; they are allocated off the
`struct bitcoind_tx`, so freeing the `struct bitcoind_tx` frees them
all.  Tal also supports destructors, which are usually used to remove
things from lists, etc.

Some routines use `take()`: `take()` marks a pointer as to be consumed
(e.g. freed automatically before return) by a called function.  It can
safely accept `NULL` pointers.  Functions whose prototype in headers has
the macro `TAKES` can have the specific argument as a `take()` call.  Use
this sparingly, as it can be very confusing.

The more complex daemons use async io (`ccan/io`): you register callbacks and they
happen once I/O is available, then you return what to do next.  This
does not use threads, so the code flow is generally fairly simple.

Channel State Machine
#####################

The following is a state transition diagram that a connection and an eventual channel move through:

.. graphviz::

   digraph foo {
      subgraph gossipd {
        UNINITIALIZED;
        GOSSIPING;
	label = "gossipd";
	color=lightgrey;
      }
      "GOSSIPING" -> "UNINITIALIZED";
      "UNINITIALIZED" -> "OPENINGD" [ label="fundchannel" ];
      "OPENINGD" -> "CHANNELD_AWAITING_LOCKIN";
      "CHANNELD_AWAITING_LOCKIN" -> "CHANNELD_NORMAL" [ label="~6 confirmations" ];
      "CHANNELD_NORMAL" -> "FUNDING_SPEND_SEEN";
      "FUNDING_SPEND_SEEN" -> "ONCHAIND_OUR_UNILATERAL";
      "FUNDING_SPEND_SEEN" -> "ONCHAIND_THEIR_UNILATERAL";
      "CHANNELD_NORMAL" -> "CHANNELD_SHUTTING_DOWN";
      "CHANNELD_SHUTTING_DOWN" -> "CLOSINGD_SIGEXCHANGE";
      "CLOSINGD_SIGEXCHANGE" -> "CLOSINGD_COMPLETE";
   }

Code Structure
##############

The Components
--------------
Here's a list of parts, with notes:

* `ccan/` - useful routines from http://ccodearchive.net
   - Use `make update-ccan` to update it.
   - Use `make update-ccan CCAN_NEW="mod1 mod2..."` to add modules
   - Do not edit this!  If you want a wrapper, add one to `common/utils.h`.
* `bitcoin/` - bitcoin script, signature and transaction routines.
   - Not a complete set, but enough for our purposes.
* `external/` - external libraries from other sources
   - `libbacktrace` - library to provide backtraces when things go wrong.
   - `libsodium` - encryption library (should be replaced soon with built-in)
   - `libwally-core` - bitcoin helper library
   - `secp256k1` - bitcoin curve encryption library within libwally-core
   - `jsmn` - tiny JSON parsing helper
   - `libbase58` - base58 address encoding/decoding library.
* `tools/` - tools for building
   - `check-bolt.c`: check the source code contains correct BOLT quotes (as used by check-source)
   - `generate-wire.py`: generate marshal/unmarshal routines from extracts from BOLT specs, and as specified by subdaemons.
   - `mockup.sh`, `update-mocks.sh`: tools to generate mock functions for unit tests.
* `devtools/`: tools for developers
   - Currently just `bolt11-cli` for decoding bolt11
* `contrib/` - python support and other stuff which doesn't belong :)
* `wire/` - basic marshalling/un
* `common/` - routines needed by any two or more of the directories below
* `cli/` - commandline utility to control lightning daemon.
* `lightningd/` - master daemon which controls the subdaemons and passes peer file descriptors between them.
* `wallet/` - database code used by master for tracking what's happening.
* `hsmd/` - daemon which looks after the cryptographic secret, and performs commitment signing.
* `gossipd/` - daemon to chat to peers which don't have any channels, and maintains routing information and broadcasts gossip.
* `openingd/` - daemon to open a channel for a single peer.
* `channeld/` - daemon to operate a single peer once channel is operating normally.
* `closingd/` - daemon to handle mutual closing negotiation with a single peer.
* `onchaind/` - daemon to hand a single channel which has had its funding transaction spent.

Memory Management
#################

.. c:function:: tal(ctx, type)

  `tal` allocate memory for the given `type` as a child of the given
  `ctx`. That means that a future call to `tal_free(ctx)` or one of
  the parents of `ctx` will cascade and free this allocation. In the
  rate case of not having a parent context from which to allocate
  from, you can pass in `NULL` as `ctx` to create a new rooted tree of
  allocations.

.. c:function:: tal_free(alloc)

  `tal_free` is the counterpart of `tal` and will free any child
  allocations of `alloc` recursively before freeing `alloc`
  itself. Should `alloc` have a destructor attached, it'll get called
  *before* the `alloc` itself is freed.
