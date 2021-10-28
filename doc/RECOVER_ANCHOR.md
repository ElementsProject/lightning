# Recovering (Very Lost) Anchor Outputs

So the worst has happened and you've suffered a terrible dataloss. You've tried reconnecting to your peers, and they've sent all of your channels to chain.

Now you're attempting to recover your lost funds by reclaiming all of the
funds from on-chain outputs.

There are *two* types of on-chain outputs that you might encounter:
	- P2WPKH, which just need a private key to spend
	- P2WSH, which need a script and some special handling to spend

If the channel was using anchor outputs, then the output will be P2WSH.

Never fear, we'll walk you through how to get your funds back for both of these.

## guesstoremote

The first thing you'll need is the peer's public id and the on-chain address that they paid your funds to when they unilaterally closed on you. You'll also need your `hsm_secret` file. We'll pass all of this through the `guesstoremote` recovery option.

Required inputs:
	- `hsm_secret` file
	- the public id of the node you were a peer with
	- the onchain address of the funds you're trying to recover


Once you have these things for a channel, run them through `guesstoremote`.

	$ ./tools/guesstoremote <onchain address> <node_id> 1000 <path to hsm_secret file>

If the result you get lists a wif and privkey, then this is a P2WPKH output. You just need to import the WIF into bitcoind to be able to spend this address.

	: bech32      :
	: pubkey hash :
	: pubkey      :
	: privkey     :
	: wif         :

If the result you get lists a  'csv' and 'script hash', this is a P2WSH and you'll need to use the `recover_anchor` tool to get a signature for it.

	: bech32      :
	: script hash :
	: script      :
	: csv         :
	: pubkey      :
	: privkey     :

## `recover_anchor`

To spend an output that's a P2WSH, you'll first need to make a PSBT that spends that output. You can do this using bitcoin-cli's `createpsbt`. Make sure that you add the correct change output etc.

Here's an example. Note that you'll need to get your own address for the output and figure out what the amount should be yourself. There may be other tools that are easier to use for this.

The `txid` input in this case is the output we want to recover. You'll also need to know the exact amount, in satoshis, that you're trying to recover.

	$ bitcoin-cli createpsbt '[{"txid": "f4b9ba88f98d2540573a0abecae247059c9c86749c4a03d71b894fabe96fc9ed", "vout":1, "sequence":0}]' '[{"tb1qcsrpjt06gsrzxkr4cyt933r9nguzmc0hlh5x6s":0.00001000}]'

Once you have a PSBT, we'll pass the PSBT and the data output from `guesstoremote` to the `./tools/recover_anchor` tool.

	$ ./tools/recover_anchor \
		<psbt> 		 \ # psbt
		0		 \ # index on the psbt to sign
		643221sat	 \ # amount of the output we're saving
		<script> 	 \ # script from guesstoremote
		4019		 \ # csv from guesstoremote
		<privkey>	   # privkey from guesstoremote

This will return a PSBT with a signature for the indicated output. You can then finalize and broadcast this transaction.

	$ bitcoin-cli finalizepsbt <psbt with signed output>
	$ bitcoin-cli sendrawtransaction <hex>
