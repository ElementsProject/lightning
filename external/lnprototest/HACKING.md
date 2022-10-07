# Adding New Tests, Testing New Nodes

The most common thing to do is to add a new test for a new feature.

## Adding A New Test

To add a new test, simply add a file starting with `test_` to the
tests/ directory.  Every function in this file starting with `test_`
will be run (the rest, presumably, are helpers you need).

For every test, there is a runner which wraps a particular node
implementation: using the default "DummyRunner" helps debug the tests
themselves.

A test consists of one or more Event (e.g. send a message, receive a
message), in a DAG.  The test runner repeats the test until every
Event has been covered.  The most important event is probably
TryAll(), which gives multiple alternative paths of Events, each of
which should be tried (it will try the "most Events" path first, to
try to get maximum coverage early in testing).

Tests which don't have an ExpectError event have a check at the end to
make sure no errors occurred.

## Using ExpectMsg Events

`ExpectMsg` matches a (perhaps only partially defined) message, then
calls its `if_match` function which can do more fine-grained matching.
For example, it could check that a specific field is not specified, or
a specific bit is set, etc.  There's also `ignore` which is a list
of Message to ignore: it defaults to common gossip queries.

`ExpectMsg` also stores the received fields in the runner's `stash`:
the convenient `rcvd` function can be used to access them for use in
`Msg` fields.


## Creating New Event Types

For various special effects, you might want to create a new Event
subclass.

Events are constructed once, but then their `action` method is called
in multiple orders for multiple traverses: they can store state across
runs in the `runner` using its `add_stash()` and `get_stash()`
methods, as used by `ExpectMsg` and `Msg`.  The entire stash
is emptied upon restart.


## Test Checklist

1. Did you quote the part of the BOLT you are testing?  This is vital
   to make your tests readable, and to ensure they change with the
   spec.  `make check-quotes` will all the quotes (starting with `#
   BOLT #N:`) are correct based on the `../lightning-rfc` directory,
   or run `tools/check_quotes.py testfile`.  If you are creating tests
   for a specific (e.g. non-master) git revision, you can use `#
   BOLT-commitid #N:` and use `--include-commit=commitid` option for
   every commit id it should check.

2. Does your test check failures as well as successes?

3. Did you test something which wasn't clear in the spec?  Consider
   opening a PR or issue to add an explicit requirement.

4. Does it pass `make check-source` a.k.a. flake8 and mypy?

## Adding a New Runner

You can write a new runner for an implementation by inheriting from
the Runner class.  This runner could live in this repository or in
your implementation's repository: you can set it with
`--runner=modname.classname`.

This is harder than writing a new test, but ultimately far more
useful, as it expands the coverage of every new test.

To add a new runner, you'll need to create a new subclass of Runner, that
fills in the Runner API. You can find a good skeleton for a new runner in
`lnprototest/dummyrunner.py`

A completed c-lightning example runner can be found in `lnprototest/clightning/clightning.py`

Here's a short outline of the current expected methods for a Runner.

- `get_keyset`: returns the node's KeySet (`revocation_base_secret`, `payment_base_secret`, `htlc_base_secret`, and `shachain_seed`)
- `get_node_privkey`: Private key of the node. Used to generate the node id and establish a communication channel with the node under test.
- `get_node_bitcoinkey`: Private key of the node under test's funding pubkey
- `has_option`: checks for features (e.g. `option_anchor_outputs`) in which cast it returns `None`, or "even" or "odd" (required or supported).  Also checks for non-feature-bit features, such as `supports_open_accept_channel_types` which returns `None` or "true".
- `add_startup_flag`: Add flag to runner's startup.
- `start`: Starts up / initializes the node under test.
- `stop`: Stops the node under test and closes the connection.
- `restart`: Restarts the node under tests, closes the existing connection, cleans up the existing test files, and restarts bitcoind. Note that it's useful to print a `RESTART` log when verbose logging is activated, e.g.

        if self.config.getoption('verbose'):
            print("[RESTART]")

- `connect`: Create a connection to the node under test using the provided `connprivkey`.
- `getblockheight`: Return the blockcount from bitcoind
- `trim_blocks`: invalidate bitcoind blocks until `newheight`
- `add_blocks`: Send provided `txs` (if any). Generate `n` new blocks.
- `disconnect`: Implemented in the parent Runner, not necessary to implement in child unless necessary.
- `recv`: Send `outbuf` over `conn` to node under test
- `fundchannel`: Initiate a fundchannel attempt to the connection's pubkey (the test harness) for the given `amount` and `feerate`. MUST NOT block (should execute this fundchannel request on a secondary thread)
- `init_rbf`: For v2 channel opens, initiates an RBF attempt. Same as `fundchannel`, must not block.
- `invoice`: Generate an invoice from the node under test for the given amount and preimage
- `accept_add_fund`: Configure the node under test to contribute to any incoming v2 open channel offers.
- `addhtlc`: Add the provided htlc to the the node. clightning does this via the `sendpay` command
- `get_output_message`: Read a message from the node's connection
- `expect_tx`: Wait for the provided txid to appear in the mempool
- `check_error`: Gets message from connection and returns it as hex. Also calls parent Runner method (which marks this as an `expected_error`)
- `check_final_error`: Called by Runner.disconnect(). Closes the connection by forcing a disconnect on the peer. Processes all remaining messages from peer. Raises EventError if error message is returned.


### Passing cmdline args to the Runner
Note that the c-lightning runner, in `__init__`, converts
cmdline `runner_args` into a `startup_flag` array, which are then
passed to the node at `start`

Relevant portion from `clightning.py/Runner#__init__`
```
        self.startup_flags = []
        for flag in config.getoption("runner_args"):
            self.startup_flags.append("--{}".format(flag))
```


Relevant portion from `clightning.py/Runner#start`
```
        self.proc = subprocess.Popen(['{}/lightningd/lightningd'.f...
                                      '--network=regtest',
                                      '--bitcoin-rpcuser=rpcuser',
                                      '--bitcoin-rpcpassword=rpcpass',
                                      '--bitcoin-rpcport={}'.format(self.bitcoind.port),
                                      '--log-level=debug',
                                      '--log-file=log']
                                     + self.startup_flags)
```



### Initializing the funding for the tests with `submitblock`

Note that the bitcoind backend in `lnprototest/backend/bitcoind.py`
creates an initial block spendable by the privkey
`cUB4V7VCk6mX32981TWviQVLkj3pa2zBcXrjMZ9QwaZB5Kojhp59`, then an
additional 100 blocks so it's mature.  `tests/helpers.py` has
`tx_spendable` which spends this into several useful outputs, and many
tests rely on this.
