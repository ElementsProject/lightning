lightning-fundpsbt -- Command to populate PSBT inputs from the wallet
================================================================

SYNOPSIS
--------

**fundpsbt** *satoshi* *feerate* *startweight* \[*minconf*\] \[*reserve*\] \[*locktime*\] \[*min_witness_weight*\] \[*excess_as_change*\]

DESCRIPTION
-----------

`fundpsbt` is a low-level RPC command which creates a PSBT using unreserved
inputs in the wallet, optionally reserving them as well.

*satoshi* is the minimum satoshi value of the output(s) needed (or the
string "all" meaning use all unreserved inputs).  If a value, it can
be a whole number, a whole number ending in *sat*, a whole number
ending in *000msat*, or a number with 1 to 8 decimal places ending in
*btc*.

*feerate* can be one of the feerates listed in lightning-feerates(7),
or one of the strings *urgent* (aim for next block), *normal* (next 4
blocks or so) or *slow* (next 100 blocks or so) to use lightningd’s
internal estimates.  It can also be a *feerate* is a number, with an
optional suffix: *perkw* means the number is interpreted as
satoshi-per-kilosipa (weight), and *perkb* means it is interpreted
bitcoind-style as satoshi-per-kilobyte. Omitting the suffix is
equivalent to *perkb*.

*startweight* is the weight of the transaction before *fundpsbt* has
added any inputs.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*reserve* is either boolean or a number: if *true* or a non-zero
number then *reserveinputs* is called (successfully, with
*exclusive* true) on the returned PSBT for this number of blocks (or
72 blocks if *reserve* is simply *true*).

*locktime* is an optional locktime: if not set, it is set to a recent
block height.

*min_witness_weight* is an optional minimum weight to use for a UTXO's
witness. If the actual witness weight is greater than the provided minimum,
the actual witness weight will be used.

*excess_as_change* is an optional boolean to flag to add a change output
for the excess sats.

EXAMPLE USAGE
-------------

Let's assume the caller is trying to produce a 100,000 satoshi output.

First, the caller estimates the weight of the core (typically 42) and
known outputs of the transaction (typically (9 + scriptlen) * 4).  For
a simple P2WPKH it's a 22 byte scriptpubkey, so that's 124 weight.

It calls "*fundpsbt* 100000sat slow 166", which succeeds, and returns
the *psbt* and *feerate_per_kw* it used, the *estimated_final_weight*
and any *excess_msat*.

If *excess_msat* is greater than the cost of adding a change output,
the caller adds a change output randomly to position 0 or 1 in the
PSBT.  Say *feerate_per_kw* is 253, and the change output is a P2WPKH
(weight 124), the cost is around 31 sats.  With the dust limit disallowing
payments below 546 satoshis, we would only create a change output
if *excess_msat* was greater or equal to 31 + 546.

RETURN VALUE
------------

On success, returns the *psbt* containing the inputs, *feerate_per_kw*
showing the exact numeric feerate it used, *estimated_final_weight* for
the estimated weight of the transaction once fully signed, and
*excess_msat* containing the amount above *satoshi* which is
available.  This could be zero, or dust.  If *satoshi* was "all",
then *excess_msat* is the entire amount once fees are subtracted
for the weights of the inputs and startweight.

If *reserve* was *true* or a non-zero number, then a *reservations*
array is returned, exactly like *reserveinputs*.

If *excess_as_change* is true and the excess is enough to cover
an additional output above the `dust_limit`, then an output is
added to the PSBT for the excess amount. The *excess_msat* will
be zero. A *change_outnum* will be returned with the index of
the change output.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 301: Insufficient UTXOs to meet *satoshi* value.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-utxopsbt(7), lightning-reserveinputs(7), lightning-unreserveinputs(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:25b32367f5bbf6f1e53036c38b7b7d19eebf62fa749a3ab580e4093eedc88584)
