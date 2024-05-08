---
title: "Bitcoin backend"
slug: "bitcoin-backend"
hidden: false
createdAt: "2023-02-03T08:58:27.125Z"
updatedAt: "2023-07-13T05:18:59.439Z"
---
Core Lightning communicates with the Bitcoin network through a plugin. It uses the `bcli` plugin by default but you can use a custom one, multiple custom ones for different operations, or write your own for your favourite Bitcoin data source!

Communication with the plugin is done through 5 JSONRPC commands, `lightningd` can use from 1 to 5 plugin(s) registering these 5 commands for gathering Bitcoin data. Each plugin must follow the below specification for `lightningd` to operate.

### `getchaininfo`

Called at startup, it's used to check the network `lightningd` is operating on and to get the sync status of the backend. Optionally, the plugins can use `last_height` to make sure that the Bitcoin backend is not behind Core Lightning.

The plugin must respond to `getchaininfo` with the following fields:  
    - `chain` (string), the network name as introduced in bip70  
    - `headercount` (number), the number of fetched block headers  
    - `blockcount` (number), the number of fetched block body  
    - `ibd` (bool), whether the backend is performing initial block download

### `estimatefees`

Polled by `lightningd` to get the current feerate, all values must be passed in sat/kVB.

The plugin must return `feerate_floor` (e.g. 1000 if mempool is empty), and an array of 0 or more `feerates`.  Each element of `feerates` is an object with `blocks` and `feerate`, in ascending-blocks order, for example:

```
{
	"feerate_floor": <sat per kVB>,
	"feerates": [
		{ "blocks": 2, "feerate": <sat per kVB> },
		{ "blocks": 6, "feerate": <sat per kVB> },
		{ "blocks": 12, "feerate": <sat per kVB> }
		{ "blocks": 100, "feerate": <sat per kVB> }
	]
}
```

lightningd will currently linearly interpolate to estimate between given blocks (it will not extrapolate, but use the min/max blocks values).

### `getrawblockbyheight`

This call takes one parameter, `height`, which determines the block height of the block to fetch.

The plugin must set all fields to `null` if no block was found at the specified `height`.

The plugin must respond to `getrawblockbyheight` with the following fields:  
    - `blockhash` (string), the block hash as a hexadecimal string  
    - `block` (string), the block content as a hexadecimal string

### `getutxout`

This call takes two parameter, the `txid` (string) and the `vout` (number) identifying the UTXO we're interested in.

The plugin must set both fields to `null` if the specified TXO was spent.

The plugin must respond to `gettxout` with the following fields:  
    - `amount` (number), the output value in **sats**  
    - `script` (string), the output scriptPubKey

### `sendrawtransaction`

This call takes two parameters, a string `tx` representing a hex-encoded Bitcoin transaction,  
and a boolean `allowhighfees`, which if set means suppress any high-fees check implemented in the backend, since the given transaction may have fees that are very high.

The plugin must broadcast it and respond with the following fields:  
    - `success` (boolean), which is `true` if the broadcast succeeded  
    - `errmsg` (string), if success is `false`, the reason why it failed
