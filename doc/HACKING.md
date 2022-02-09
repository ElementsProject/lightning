Hacking
=======

Welcome, fellow coder!

This repository contains a code to run a lightning protocol daemon.
It's broken into subdaemons, with the idea being that we can add more
layers of separation between different clients and extra barriers to
exploits.

It is designed to implement the lightning protocol as specified in
[various BOLTs](https://github.com/lightningnetwork/lightning-rfc).


Getting Started
---------------
It's in C, to encourage alternate implementations.  Patches are welcome!
You should read our [Style Guide](STYLE.md).

To read the code, you should start from
[lightningd.c](../lightningd/lightningd.c) and hop your way through
the '~' comments at the head of each daemon in the suggested
order.

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

* tools/ - tools for building
  - check-bolt.c: check the source code contains correct BOLT quotes
    (as used by check-source)
  - generate-wire.py: generates wire marshal/unmarshal-ing
    routines for subdaemons and BOLT specs.
  - mockup.sh / update-mocks.sh: tools to generate mock functions for
    unit tests.

* tests/ - blackbox tests (mainly)
  - unit tests are in tests/ subdirectories in each other directory.

* doc/ - you are here

* devtools/ - tools for developers
   - Generally for decoding our formats.

* contrib/ - python support and other stuff which doesn't belong :)

* wire/ - basic marshalling/un for messages defined in the BOLTs

* common/ - routines needed by any two or more of the directories below

* cli/ - commandline utility to control lightning daemon.

* lightningd/ - master daemon which controls the subdaemons and passes
  peer file descriptors between them.

* wallet/ - database code used by master for tracking what's happening.

* hsmd/ - daemon which looks after the cryptographic secret, and performs
  commitment signing.

* gossipd/ - daemon to maintain routing information and broadcast gossip.

* connectd/ - daemon to connect to other peers, and receive incoming.

* openingd/ - daemon to open a channel for a single peer, and chat to
  a peer which doesn't have any channels/

* channeld/ - daemon to operate a single peer once channel is operating
  normally.

* closingd/ - daemon to handle mutual closing negotiation with a single peer.

* onchaind/ - daemon to handle a single channel which has had its funding
  transaction spent.

Debugging
---------

You can build c-lightning with DEVELOPER=1 to use dev commands listed in
``cli/lightning-cli help``. ``./configure --enable-developer`` will do that.
You can log console messages with log_info() in lightningd and status_debug()
in other subdaemons.

You can debug crashing subdaemons with the argument
`--dev-debugger=channeld`, where `channeld` is the subdaemon name.  It
will run `gnome-terminal` by default with a gdb attached to the
subdaemon when it starts.  You can change the terminal used by setting
the `DEBUG_TERM` environment variable, such as `DEBUG_TERM="xterm -e"`
or `DEBUG_TERM="konsole -e"`.

It will also print out (to stderr) the gdb command for manual connection.  The
subdaemon will be stopped (it sends itself a SIGSTOP); you'll need to
`continue` in gdb.

Database
--------

c-lightning state is persisted in `lightning-dir`.
It is a sqlite database stored in the `lightningd.sqlite3` file, typically
under `~/.lightning/<network>/`.
You can run queries against this file like so:

    $ sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3 \
      "SELECT HEX(prev_out_tx), prev_out_index, status FROM outputs"

Or you can launch into the sqlite3 repl and check things out from there:

    $ sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3
    SQLite version 3.21.0 2017-10-24 18:55:49
    Enter ".help" for usage hints.
    sqlite> .tables
    channel_configs  invoices         peers            vars
    channel_htlcs    outputs          shachain_known   version
    channels         payments         shachains
    sqlite> .schema outputs
    ...

Some data is stored as raw bytes, use `HEX(column)` to pretty print these.

Make sure that clightning is not running when you query the database,
as some queries may lock the database and cause crashes.

#### Common variables
Table `vars` contains global variables used by lightning node.

    $ sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3
    SQLite version 3.21.0 2017-10-24 18:55:49
    Enter ".help" for usage hints.
    sqlite> .headers on
    sqlite> select * from vars;
    name|val
    next_pay_index|2
    bip32_max_index|4
    ...

Variables:
* `next_pay_index` next resolved invoice counter that will get assigned.
* `bip32_max_index` last wallet derivation counter.

Note: Each time `newaddr` command is called, `bip32_max_index` counter
is increased to the last derivation index.
Each address generated after `bip32_max_index` is not included as
lightning funds.


Build and Development
---------------------
Install `valgrind` and the python dependencies for best results:

```
sudo apt update
sudo apt install valgrind cppcheck shellcheck libsecp256k1-dev libpq-dev
pip3 install --upgrade pip
pip3 install --user -r requirements.txt
```

Re-run `configure` for the python dependencies and build using `make`.

```
./configure --enable-developer
make -j$(nproc)
```


Testing
-------
Tests are run with: `make check [flags]` where the pertinent flags are:

```
DEVELOPER=[0|1] - developer mode increases test coverage
VALGRIND=[0|1]  - detects memory leaks during test execution but adds a significant delay
PYTEST_PAR=n    - runs pytests in parallel
```

A modern desktop can build and run through all the tests in a couple of minutes with:

    make -j12 full-check PYTEST_PAR=24 DEVELOPER=1 VALGRIND=0

Adjust `-j` and `PYTEST_PAR` accordingly for your hardware.

There are three kinds of tests:

* **source tests** - run by `make check-source`, looks for whitespace,
  header order, and checks formatted quotes from BOLTs if BOLTDIR
  exists.

* **unit tests** - standalone programs that can be run individually. You can
  also run all of the unit tests with `make check-units`.
  They are `run-*.c` files in test/ subdirectories used to test routines
  inside C source files.

  You should insert the lines when implementing a unit test:

  `/* AUTOGENERATED MOCKS START */`

  `/* AUTOGENERATED MOCKS END */`

  and `make update-mocks` will automatically generate stub functions which will
  allow you to link (and conveniently crash if they're called).

* **blackbox tests** - These tests setup a mini-regtest environment and test
  lightningd as a whole.  They can be run individually:

  `PYTHONPATH=contrib/pylightning:contrib/pyln-client:contrib/pyln-testing:contrib/pyln-proto py.test -v tests/`

  You can also append `-k TESTNAME` to run a single test.  Environment variables
  `DEBUG_SUBD=<subdaemon>` and `TIMEOUT=<seconds>` can be useful for debugging
  subdaemons on individual tests.

* **pylightning tests** - will check contrib pylightning for codestyle and run
  the tests in `contrib/pylightning/tests` afterwards:

  `make check-python`

Our Travis CI instance (see `.travis.yml`) runs all these for each
pull request.

#### Additional Environment Variables

```
TEST_CHECK_DBSTMTS=[0|1]            - When running blackbox tests, this will
                                      load a plugin that logs all compiled
                                      and expanded database statements.
                                      Note: Only SQLite3.
TEST_DB_PROVIDER=[sqlite3|postgres] - Selects the database to use when running
                                      blackbox tests.
EXPERIMENTAL_DUAL_FUND=[0|1]	    - Enable dual-funding tests.
```

#### Troubleshooting

##### Valgrind complains about code we don't control

Sometimes `valgrind` will complain about code we do not control
ourselves, either because it's in a library we use or it's a false
positive. There are generally three ways to address these issues
(in descending order of preference):

 1. Add a suppression for the one specific call that is causing the
    issue. Upon finding an issue `valgrind` is instructed in the
    testing framework to print filters that'd match the issue. These
    can be added to the suppressions file under
    `tests/valgrind-suppressions.txt` in order to explicitly skip
    reporting these in future. This is preferred over the other
    solutions since it only disables reporting selectively for things
    that were manually checked. See the [valgrind docs][vg-supp] for
    details.
 2. Add the process that `valgrind` is complaining about to the
    `--trace-children-skip` argument in `pyln-testing`. This is used
    in cases of full binaries not being under our control, such as the
    `python3` interpreter used in tests that run plugins. Do not use
    this for binaries that are compiled from our code, as it tends to
    mask real issues.
 3. Mark the test as skipped if running under `valgrind`. It's mostly
    used to skip tests that otherwise would take considerably too long
    to test on CI. We discourage this for suppressions, since it is a
    very blunt tool.

[vg-supp]: https://valgrind.org/docs/manual/manual-core.html#manual-core.suppress

Making BOLT Modifications
-------------------------

All of code for marshalling/unmarshalling BOLT protocol messages is generated
directly from the spec. These are pegged to the BOLTVERSION, as specified in
`Makefile`.


Source code analysis
--------------------
An updated version of the NCC source code analysis tool is available at

https://github.com/bitonic-cjp/ncc

It can be used to analyze the lightningd source code by running
`make clean && make ncc`. The output (which is built in parallel with the
binaries) is stored in .nccout files. You can browse it, for instance, with
a command like `nccnav lightningd/lightningd.nccout`.

Subtleties
----------

There are a few subtleties you should be aware of as you modify deeper
parts of the code:

* `ccan/structeq`'s STRUCTEQ_DEF will define safe comparison function foo_eq()
  for struct foo, failing the build if the structure has implied padding.
* `command_success`, `command_fail`, and `command_fail_detailed` will free the
  `cmd` you pass in.
  This also means that if you `tal`-allocated anything from the `cmd`, they
  will also get freed at those points and will no longer be accessible
  afterwards.
* When making a structure part of a list, you will instance a
  `struct list_node`.
  This has to be the *first* field of the structure, or else `dev-memleak`
  command will think your structure has leaked.


Protocol Modifications
----------------------

The source tree contains CSV files extracted from the v1.0 BOLT
specifications (wire/extracted_peer_wire_csv and
wire/extracted_onion_wire_csv).  You can regenerate these by setting
`BOLTDIR` and `BOLTVERSION` appropriately, and running `make
extract-bolt-csv`.


Further Information
-------------------

Feel free to ask questions on the lightning-dev mailing list, or on
`#c-lightning` on IRC, or email me at rusty@rustcorp.com.au.

Cheers!<br>
Rusty.
