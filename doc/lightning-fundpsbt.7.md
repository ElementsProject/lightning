lightning-fundpsbt -- Command to populate PSBT inputs from the wallet
================================================================

SYNOPSIS
--------

**fundpsbt** *satoshi* *feerate* *startweight* [*minconf*] [*reserve*] [*locktime*] [*min\_witness\_weight*] [*excess\_as\_change*]

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
blocks or so) or *slow* (next 100 blocks or so) to use lightningd's
internal estimates.  It can also be a *feerate* is a number, with an
optional suffix: *perkw* means the number is interpreted as
satoshi-per-kilosipa (weight), and *perkb* means it is interpreted
bitcoind-style as satoshi-per-kilobyte. Omitting the suffix is
equivalent to *perkb*.

*startweight* is the weight of the transaction before *fundpsbt* has
added any inputs.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

If *reserve* if not zero, then *reserveinputs* is called (successfully, with
*exclusive* true) on the returned PSBT for this number of blocks (default
72 blocks if unspecified).

*locktime* is an optional locktime: if not set, it is set to a recent
block height.

*min\_witness\_weight* is an optional minimum weight to use for a UTXO's
witness. If the actual witness weight is greater than the provided minimum,
the actual witness weight will be used.

*excess\_as\_change* is an optional boolean to flag to add a change output
for the excess sats.

EXAMPLE USAGE
-------------

Let's assume the caller is trying to produce a 100,000 satoshi output.

First, the caller estimates the weight of the core (typically 42) and
known outputs of the transaction (typically (9 + scriptlen) * 4).  For
a simple P2WPKH it's a 22 byte scriptpubkey, so that's 124 weight.

It calls "*fundpsbt* 100000sat slow 166", which succeeds, and returns
the *psbt* and *feerate\_per\_kw* it used, the *estimated\_final\_weight*
and any *excess\_msat*.

If *excess\_msat* is greater than the cost of adding a change output,
the caller adds a change output randomly to position 0 or 1 in the
PSBT.  Say *feerate\_per\_kw* is 253, and the change output is a P2WPKH
(weight 124), the cost is around 31 sats.  With the dust limit disallowing
payments below 546 satoshis, we would only create a change output
if *excess\_msat* was greater or equal to 31 + 546.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **psbt** (string): Unsigned PSBT which fulfills the parameters given
- **feerate\_per\_kw** (u32): The feerate used to create the PSBT, in satoshis-per-kiloweight
- **estimated\_final\_weight** (u32): The estimated weight of the transaction once fully signed
- **excess\_msat** (msat): The amount above *satoshi* which is available.  This could be zero, or dust; it will be zero if *change\_outnum* is also returned
- **change\_outnum** (u32, optional): The 0-based output number where change was placed (only if parameter *excess\_as\_change* was true and there was sufficient funds)
- **reservations** (array of objects, optional): If *reserve* was true or a non-zero number, just as per lightning-reserveinputs(7):
  - **txid** (txid): The txid of the transaction
  - **vout** (u32): The 0-based output number
  - **was\_reserved** (boolean): Whether this output was previously reserved (always *false*)
  - **reserved** (boolean): Whether this output is now reserved (always *true*)
  - **reserved\_to\_block** (u32): The blockheight the reservation will expire

[comment]: # (GENERATE-FROM-SCHEMA-END)

If *excess\_as\_change* is true and the excess is enough to cover
an additional output above the `dust_limit`, then an output is
added to the PSBT for the excess amount. The *excess\_msat* will
be zero. A *change\_outnum* will be returned with the index of
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

[comment]: # ( SHA256STAMP:35947e2b2c402a87c4bad3a5a90443bfe5db44d71cb515541074abfc4dc3f24d)
