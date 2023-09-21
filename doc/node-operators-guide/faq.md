---
title: "Troubleshooting & FAQ"
slug: "faq"
excerpt: "Common issues and frequently asked questions on operating a CLN node."
hidden: false
createdAt: "2023-01-25T13:15:09.290Z"
updatedAt: "2023-07-05T09:42:38.017Z"
---
# General questions

### I don't know where to start, help me !

There is a Core Lightning plugin specifically for this purpose, it's called [`helpme`](https://github.com/lightningd/plugins/tree/master/helpme).

Assuming you have followed the [installation steps](doc:installation), have `lightningd` up and running, and `lightning-cli` in your `$PATH` you can start the plugin like so:

```shell
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

```shell
lightning-cli helpme
```



### How to get the balance of each channel ?

You can use the `listfunds` command and take a ratio of `our_amount_msat` over  
`amount_msat`. Note that this doesn't account for the [channel reserve](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#rationale).

A better option is to use the [`summary` plugin](https://github.com/lightningd/plugins/tree/master/summary) which nicely displays channel balances, along with other useful channel information.

### My channel is in state `STATE`, what does that mean ?

See the [listpeers](ref:lightning-listpeers) command.

### My payment is failing / all my payments are failing, why ?

There are many reasons for a payment failure. The most common one is a [failure](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages)  
along the route from you to the payee. The best (and most common) solution to a route failure problem is to open more channels, which should increase the available routes to the recipient and lower the probability of a failure.

**Hint:** use the [`pay`](ref:lightning-pay) command which is will iterate through trying all possible routes,  
instead of the low-level `sendpay` command which only tries the passed in route.

### How can I receive payments ?

In order to receive payments you need inbound liquidity. You get inbound liquidity when another node opens a channel to you or by successfully completing a payment out through a channel you opened.

If you need a lot of inbound liquidity, you can use a service that trustlessly swaps on-chain Bitcoin for Lightning channel capacity. There are a few online service providers that will create channels to you. A few of them charge fees for this service. Note that if you already have a channel open to them, you'll need to close it before requesting another channel.

### Are there any issues if my node changes its IP address? What happens to the channels if it does?

There is no risk to your channels if your IP address changes. Other nodes might not be able to connect to you, but your node can still connect to them. But Core Lightning also has an integrated IPv4/6 address discovery mechanism. If your node detects an new public address, it will update its announcement. For this to work binhind a NAT router you need to forward the default TCP port 9735 to your node. IP discovery is only active if no other addresses are announced.

Alternatively, you can [setup a TOR hidden service](doc:tor) for your node that will also work well behind NAT firewalls.

### Can I have two hosts with the same public key and different IP addresses, both online and operating at the same time?

No.

### Can I use a single `bitcoind` for multiple `lightningd` ?

Yes. All `bitcoind` calls are handled by the bundled `bcli` plugin. `lightningd` does not use `bitcoind`'s wallet. While on the topic, `lightningd` does not require the `-txindex` option on `bitcoind`.

If you use a single `bitcoind` for multiple `lightningd`'s, be sure to raise the `bitcoind`  
max RPC thread limit (`-rpcthreads`), each `lightningd` can use up to 4 threads, which is  
the default `bitcoind` max.

### Can I use Core Lightning on mobile ?

#### Remote control

[Spark-wallet](https://github.com/shesek/spark-wallet/) is the most popular remote control HTTP server for `lightningd`. Use it [behind tor](https://github.com/shesek/spark-wallet/blob/master/doc/onion.md).

#### `lightningd` on Android

Effort has been made to get `lightningd` running on Android, [see issue #3484](https://github.com/ElementsProject/lightning/issues/3484). Currently unusable.

# Channel Management

### How to forget about a channel?

Channels may end up stuck during funding and never confirm on-chain. There is a variety of causes, the most common ones being that the funds have been double-spent, or the funding fee was too low to be confirmed. This is unlikely to happen in normal operation, as CLN tries to use sane defaults and prevents double-spends whenever possible, but using custom feerates or when the bitcoin backend has no good fee estimates it is still possible.

Before forgetting about a channel it is important to ensure that the funding transaction will never be confirmable by double-spending the funds. To do so you have to rescan the UTXOs using  
[`dev-rescan-outputs`](doc:faq#rescanning-the-blockchain-for-lost-utxos) to reset any funds that may have been used in the funding transaction, then move all the funds to a new address:

```bash
lightning-cli dev-rescan-outputs
ADDR=$(lightning-cli newaddr bech32 | jq .bech32)
lightning-cli withdraw $ADDR all
```



This step is not required if the funding transaction was already double-spent, however it is safe to do it anyway, just in case.

Then wait for the transaction moving the funds to confirm. This ensures any pending funding transaction can no longer be confirmed. 

As an additional step you can also force-close the unconfirmed channel:

```bash
lightning-cli close $PEERID 10  # Force close after 10 seconds
```



This will store a unilateral close TX in the DB as last resort means of recovery should the channel unexpectedly confirm anyway.

Now you can use the `dev-forget-channel` command to remove the DB entries from the database.

```bash
lightning-cli dev-forget-channel $NODEID
```



This will perform additional checks on whether it is safe to forget the channel, and only then removes the channel from the DB. Notice that this command is only available if CLN was started with `--developer`.

### My channel is stuck in state `CHANNELD_AWAITING_LOCKIN`

There are two root causes to this issue:

- Funding transaction isn't confirmed yet. In this case we have to wait longer, or, in the case of a transaction that'll never confirm, forget the channel safely.
- The peer hasn't sent a lockin message. This message acknowledges that the node has seen sufficiently many confirmations to consider the channel funded.

In the case of a confirmed funding transaction but a missing lockin message, a simple reconnection may be sufficient to nudge it to acknowledge the confirmation:

```bash
lightning-cli disconnect $PEERID true  # force a disconnect
lightning-cli connect $PEERID
```



The lack of funding locked messages is a bug we are trying to debug here at issue [5336](https://github.com/ElementsProject/lightning/issues/5366), if you have encountered this issue please drop us a comment and any information that may be helpful.

If this didn't work it could be that the peer is simply not caught up with the blockchain and hasn't seen the funding confirm yet. In this case we can either wait or force a unilateral close:

```bash
lightning-cli close $PEERID 10  # Force a unilateral after 10 seconds
```



If the funding transaction is not confirmed we may either wait or attempt to double-spend it. Confirmations may take a long time, especially when the fees used for the funding transaction were low. You can check if the transaction is still going to confirm by looking the funding transaction on a block explorer:

```bash
TXID=$(lightning-cli listpeers $PEERID | jq -r ''.peers[].channels[].funding_txid')
```



This will give you the funding transaction ID that can be looked up in any explorer.

If you don't want to wait for the channel to confirm, you could forget the channel (see [How to forget about a channel?](doc:faq#how-to-forget-about-a-channel) for details), however be careful as that may be dangerous and you'll need to rescan and double-spend the outputs so the funding cannot confirm.

# Loss of funds

### Rescanning the blockchain for lost utxos

There are 3 types of 'rescans' you can make:

- `rescanblockchain`: A `bitcoind` RPC call which rescans the blockchain starting at the given height. This does not have an effect on Core Lightning as `lightningd` tracks all block and wallet data independently.
- `--rescan=depth`: A `lightningd` configuration flag. This flag is read at node startup and tells lightningd at what depth from current blockheight to rebuild its internal state.  
   (You can specify an exact block to start scanning from, instead of depth from current height, by using a negative number)
- `dev-rescan-outputs`: A `lightningd` RPC call. Only available if your node has been started in developer mode (i.e. `--developer`). This will sync the state for known UTXOs in the `lightningd` wallet with `bitcoind`. As it only operates on outputs already seen on chain by the `lightningd` internal wallet, this will not find missing wallet funds.

### Database corruption / channel state lost

If you lose data (likely corrupted `lightningd.sqlite3`) about a channel **with `option_static_remotekey` enabled**, you can wait for your peer to unilateraly close the channel, then use `tools/hsmtool` with the `guesstoremote` command to attempt to recover your funds from the peer's published unilateral close transaction.

If `option_static_remotekey` was not enabled, you're probably out of luck. The keys for your funds in your peer's unilateral close transaction are derived from information you lost. Fortunately, since version `0.7.3` channels are created with `option_static_remotekey` by default if your peer supports it. Which is to say that channels created after block [598000](https://blockstream.info/block/0000000000000000000dd93b8fb5c622b9c903bf6f921ef48e266f0ead7faedb)  
(short channel id starting with > 598000) have a high chance of supporting `option_static_remotekey`. You can verify it using the `features` field from the [`listpeers` command](ref:lightning-listpeers)'s result.

Here is an example in Python checking if [one of the `option_static_remotekey` bits](https://github.com/lightning/bolts/blob/master/09-features.md) is set in the negotiated features corresponding to `0x02aaa2`:

```python
>>> bool(0x02aaa2 & ((1 << 12) | (1 << 13)))
True
```



If `option_static_remotekey` is enabled you can attempt to recover the funds in a channel following [this tutorial](https://github.com/mandelbit/bitcoin-tutorials/blob/master/CLightningRecoverFunds.md) on how to extract the necessary information from the network topology. If successful, result will be a private key matching a unilaterally closed channel, that you can import into any wallet, recovering the funds into that wallet.

# Technical Questions

### How do I get the `psbt` for RPC calls that need it?

A `psbt` is created and returned by a call to [`utxopsbt` with `reservedok=true`](ref:lightning-utxopsbt).
