lightning-utxopsbt -- Command to populate PSBT inputs from given UTXOs
================================================================

SYNOPSIS
--------

**utxopsbt** *satoshi* *feerate* *startweight* *utxos* \[*reserve*\] \[*reservedok*\] \[*locktime*\] \[*min_witness_weight*\]

DESCRIPTION
-----------

*utxopsbt* is a low-level RPC command which creates a PSBT using unreserved
inputs in the wallet, optionally reserving them as well.

It deliberately mirrors the parameters and output of
lightning-fundpsbt(7) except instead of an optional *minconf*
parameter to select unreserved outputs from the wallet, it takes a
compulsory list of outputs to use.

*utxos* must be an array of "txid:vout", each of which must be
reserved or available: the total amount must be sufficient to pay for
the resulting transaction plus *startweight* at the given *feerate*,
with at least *satoshi* left over (unless *satoshi* is **all**, which
is equivalent to setting it to zero).

Unless *reservedok* is set to true (default is false) it will also fail
if any of the *utxos* are already reserved.

*locktime* is an optional locktime: if not set, it is set to a recent
block height.

*min_witness_weight* is an optional minimum weight to use for a UTXO's
witness. If the actual witness weight is greater than the provided minimum,
the actual witness weight will be used.

RETURN VALUE
------------

On success, returns the *psbt* containing the inputs, *feerate_per_kw*
showing the exact numeric feerate it used, *estimated_final_weight* for
the estimated weight of the transaction once fully signed, and
*excess_msat* containing the amount above *satoshi* which is
available.  This could be zero, or dust.  If *satoshi* was "all",
then *excess_msat* is the entire amount once fees are subtracted
for the weights of the inputs and *startweight*.

If *reserve* was true, then a *reservations* array is returned,
exactly like *reserveinputs*.

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

lightning-fundpsbt(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

