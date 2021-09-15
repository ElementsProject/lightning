# FAQ

## Table of contents
- [General questions](#general-questions)
- [Loss of {funds / data}](#loss)


## General questions

### I don't know where to start, help me !

There is a C-lightning plugin specifically for this purpose, it's called
[`helpme`](https://github.com/lightningd/plugins/tree/master/helpme).

Assuming you have followed the [installation steps](INSTALL.md), have `lightningd`
up and running, and `lightning-cli` in your `$PATH` you can start the plugin like so:

```
# Clone the plugins repository
git clone https://github.com/lightningd/plugins
# Make sure the helpme plugin is executable (git should have already handled this)
chmod +x plugins/helpme/helpme.py
# Install its dependencies (there is only one actually)
pip3 install --user -r plugins/helpme/requirements.txt
# Then just start it :)
lightning-cli plugin start $PWD/plugins/helpme/helpme.py
```

The plugin registers a new command `helpme` which will guide you through the main
components of C-lightning:

```
lightning-cli helpme
```

### How to get the balance of each channel ?

You can use the `listfunds` command and take a ratio of `our_amount_msat` over
`amount_msat`. Note that this doesn't account for the [channel reserve](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale).

A better option is to use the [`summary` plugin](https://github.com/lightningd/plugins/tree/master/summary)
which nicely displays channel balances, along with other useful channel information.

### My channel is in state `STATE`, what does that mean ?

See the [listpeers command manpage](https://lightning.readthedocs.io/lightning-listpeers.7.html#return-value).

### My payment is failing / all my payments are failing, why ?

There are many reasons for a payment failure. The most common one is a
[failure](https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#failure-messages)
along the route from you to the payee.
The best (and most common) solution to a route failure problem is to open more channels,
which should increase the available routes to the recipient and lower the probability of a failure.

Hint: use the [`pay`](lightning-pay.7.md) command which is will iterate through trying all possible routes,
instead of the low-level `sendpay` command which only tries the passed in route.

### How can I receive payments ?

In order to receive payments you need inbound liquidity. You get inbound liquidity when
another node opens a channel to you or by successfully completing a payment out through a channel you opened.

If you need a lot of inbound liquidity, you can use a service that trustlessly swaps on-chain Bitcoin
for Lightning channel capacity.
There are a few online service providers that will create channels to you.
A few of them charge fees for this service.
Note that if you already have a channel open to them, you'll need to close it before requesting another channel.

### Are there any issues if my node changes its IP address? What happens to the channels if it does?

There is no risk to your channels if your IP address changes.
However, be sure to change your announced address (or [setup a TOR hidden service](TOR.md))
in your config so that others can establish connections at your new address !

### Can I have two hosts with the same public key and different IP addresses, both online and operating at the same time?

No.

### Can I use a single `bitcoind` for multiple `lightningd` ?

Yes. All `bitcoind` calls are handled by the bundled `bcli` plugin. `lightningd` does not use
`bitcoind`'s wallet. While on the topic, `lightningd` does not require the `-txindex` option on `bitcoind`.

If you use a single `bitcoind` for multiple `lightningd`'s, be sure to raise the `bitcoind`
max RPC thread limit (`-rpcthreads`), each `lightningd` can use up to 4 threads, which is
the default `bitcoind` max.

### Can I use C-lightning on mobile ?

#### Remote control

[Spark-wallet](https://github.com/shesek/spark-wallet/) is the most popular remote control
HTTP server for `lightningd`.
**Use it [behind tor](https://github.com/shesek/spark-wallet/blob/master/doc/onion.md)**.

#### `lightningd` on Android

Effort has been made to get `lightningd` running on Android,
[see issue #3484](https://github.com/ElementsProject/lightning/issues/3484). Currently unusable.

### How to "backup my wallet" ?

See [BACKUP.md](https://lightning.readthedocs.io/BACKUP.html) for a more
comprehensive discussion of your options.

In summary: as a Bitcoin user, one may be familiar with a file or a seed
(or some mnemonics) from which
it can recover all its funds.

C-lightning has an internal bitcoin wallet, which you can use to make "on-chain"
transactions, (see [withdraw](https://lightning.readthedocs.io/lightning-withdraw.7.html).
These on-chain funds are backed up via the HD wallet seed, stored in byte-form in `hsm_secret`.

`lightningd` also stores information for funds locked in Lightning Network channels, which are stored
in a database. This database is required for on-going channel updates as well as channel closure.
There is no single-seed backup for funds locked in channels.

While crucial for node operation, snapshot-style backups of the `lightningd` database is **discouraged**,
as _any_ loss of state may result in permanent loss of funds.
See the [penalty mechanism](https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#revoked-transaction-close-handling)
for more information on why any amount of state-loss results in fund loss.

Real-time database replication is the recommended approach to backing up node data.
Tools for replication are currently in active development, using the `db_write`
[plugin hook](https://lightning.readthedocs.io/PLUGINS.html#db-write).


## Loss

### Rescanning the block chain for lost utxos

There are 3 types of 'rescans' you can make:
- `rescanblockchain`: A `bitcoind` RPC call which rescans the blockchain
   starting at the given height. This does not have an effect on c-lightning
   as `lightningd` tracks all block and wallet data independently.
- `--rescan=depth`: A `lightningd` configuration flag. This flag is read at node startup
   and tells lightningd at what depth from current blockheight to rebuild its internal state.
   (You can specify an exact block to start scanning from, instead of depth from current height,
   by using a negative number.)
-  `dev-rescan-outputs`: A `lightningd` RPC call. Only available if your node has been
   configured and built in DEVELOPER mode (i.e. `./configure --enable-developer`) This
   will sync the state for known UTXOs in the `lightningd` wallet with `bitcoind`.
   As it only operates on outputs already seen on chain by the `lightningd` internal
   wallet, this will not find missing wallet funds.


### Database corruption / channel state lost

If you lose data (likely corrupted `lightningd.sqlite3`) about a channel __with `option_static_remotekey` enabled__,
you can wait for your peer to unilateraly close the channel, then use `tools/hsmtool` with the
`guesstoremote` command to attempt to recover your funds from the peer's published unilateral close transaction.

If `option_static_remotekey` was not enabled, you're probably out of luck. The keys for your funds in your peer's
unilateral close transaction are derived from information you lost. Fortunately, since version `0.7.3` channels
are created with `option_static_remotekey` by default if your peer supports it.
Which is to say that channels created after block [598000](https://blockstream.info/block/0000000000000000000dd93b8fb5c622b9c903bf6f921ef48e266f0ead7faedb)
(short channel id starting with > 598000) have a high chance of supporting `option_static_remotekey`.

You can verify it using the `features` field from the [`listpeers` command](https://lightning.readthedocs.io/lightning-listpeers.7.html)'s result.

Here is an example in Python checking if [one of the `option_static_remotekey` bits][spec-features] is set in the negotiated features corresponding to `0x02aaa2`:
```python
>>> bool(0x02aaa2 & ((1 << 12) | (1 << 13)))
True
```

If `option_static_remotekey` is enabled you can attempt to recover the
funds in a channel following [this tutorial][mandelbit-recovery] on
how to extract the necessary information from the network topology. If
successful, result will be a private key matching a unilaterally
closed channel, that you can import into any wallet, recovering the
funds into that wallet.

[spec-features]: https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
[mandelbit-recovery]: https://github.com/mandelbit/bitcoin-tutorials/blob/master/CLightningRecoverFunds.md

## Technical Questions

### How do I get the `psbt` for RPC calls that need it?

A `psbt` is created and returned by a call to [`utxopsbt` with `reservedok=true`](https://lightning.readthedocs.io/lightning-utxopsbt.7.html?highlight=psbt).
