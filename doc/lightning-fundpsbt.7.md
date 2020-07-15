lightning-fundpsbt -- Command to populate PSBT inputs from the wallet
================================================================

SYNOPSIS
--------

**fundpsbt** *satoshi* *feerate* \[*minconf*\] \[*reserve*\]

DESCRIPTION
-----------

`fundpsbt` is a low-level RPC command which creates a PSBT using unreserved
inputs in the wallet, optionally reserving them as well.

*satoshi* is the minimum satoshi value of the output(s) needed (or the
string "all" meaning use all unreserved inputs).  If a value, it can
be a whole number, a whole number ending in *sat*, a whole number
ending in *000msat*, or a number with 1 to 8 decimal places ending in
*btc*.

You calculate the value by starting with the amount you want to pay
and adding the fee which will be needed to pay for the base of the
transaction plus that output, and any other outputs and inputs you
will add to the final transaction.

*feerate* is a number, with an optional suffix: *perkw* means the
number is interpreted as satoshi-per-kilosipa (weight), and *perkb*
means it is interpreted bitcoind-style as
satoshi-per-kilobyte. Omitting the suffix is equivalent to *perkb*.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*reserve* is a boolean: if true (the default), then *reserveinputs* is
called (successfully, with *exclusive* true) on the returned PSBT.

RETURN VALUE
------------

On success, returns the *psbt* containing the inputs, and
*excess_msat* containing the amount above *satoshi* which is
available.  This could be zero, or dust.  If *satoshi* was "all",
then *excess_msat* is the entire amount once fees are subtracted
for the weights of the inputs.

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

lightning-reserveinputs(7), lightning-unreserveinputs(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
