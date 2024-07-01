The bookkeeper keeps track of coins moving through your Lightning node.

See the doc/PLUGINS.md#coin_movement section on the message that CLN emits for us to process.

// FIXME: add more detailed documenation for how bookkeeper works.


## 3rd Party Coin Movements
Bookeeper ingests 3rd party plugin notifications about on-chain movements that it should watch.

This allows for us to account for non-internal on-chain wallets in the single place, making `bookkeeper` your single source of truth for bitcoin for an organization or node-operator.

As a plugin writer, if you want to emit onchain events that the bookkeeper should track, you should emit an event with the following format:

```
{
	"utxo_deposit": {
		"account": "nifty's secret stash",
		"transfer_from: null,
		"outpoint": xxxx:x,
		"amount_msat": "10000sat",
		"coin_type": "bc",
		"timestamp": xxxx,
		"blockheight": xxx,
	}
}
```

```
{
	"utxo_spend": {
		"account": "nifty's secret stash",
		"outpoint": xxxx:x,
		"spending_txid": xxxx,
		"amount_msat": "10000sat",
		"coin_type": "bc",
		"timestamp": xxxx,
		"blockheight": xxx,
	}
}
```


## Withdrawing money (sending to a external account)

Sending money to an external account is a bit unintuitive in in the UTXO model that we're using to track coin moves; technically a send to an external account is a "deposit" to 3rd party's UTXO.

To account for these, `bookkeeper` expects to receive a `utxo_deposit` event for the creation of an output to a 3rd party. It's assumed that you'll issue these at transaction creation time, and that they won't be final until we receive notice of spend of the inputs in the tx that created them.

To notify that money is being sent to a 3rd party output, here's the event we'd expect.

The two keys here are the following:

- The `account` is `external`. This is a special account in `bookkeeper` and used for tracking external deposits (aka sends)
- The `transfer_from` field is set to the name of the account that is sending out the money.


```
{
	"utxo_deposit": {
		"account": "external",
		"transfer_from": "nifty's secret stash",
		"outpoint": xxxx:x,
		"amount_msat": "10000sat",
		"coin_type": "bc",
		"timestamp": xxxx,
		"blockheight": xxx,
	}
}
```


## List of todos

List of things to check/work on, as a todo list.

- Transfers btw a 3rd party wallet and the internal CLN wallet? These should be registered as internal transfers and not show up in `listincome`
