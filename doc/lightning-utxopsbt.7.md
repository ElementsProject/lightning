lightning-utxopsbt -- Command to populate PSBT inputs from given UTXOs
================================================================

SYNOPSIS
--------

**utxopsbt** *satoshi* *feerate* *startweight* *utxos* [*reserve*] [*reservedok*] [*locktime*] [*min\_witness\_weight*] [*excess\_as\_change*]

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

If *reserve* if not zero, then *reserveinputs* is called (successfully, with
*exclusive* true) on the returned PSBT for this number of blocks (default
72 blocks if unspecified).

Unless *reservedok* is set to true (default is false) it will also fail
if any of the *utxos* are already reserved.

*locktime* is an optional locktime: if not set, it is set to a recent
block height.

*min\_witness\_weight* is an optional minimum weight to use for a UTXO's
witness. If the actual witness weight is greater than the provided minimum,
the actual witness weight will be used.

*excess\_as\_change* is an optional boolean to flag to add a change output
for the excess sats.

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
  - **was\_reserved** (boolean): Whether this output was previously reserved
  - **reserved** (boolean): Whether this output is now reserved (always *true*)
  - **reserved\_to\_block** (u32): The blockheight the reservation will expire

[comment]: # (GENERATE-FROM-SCHEMA-END)


On success, returns the *psbt* it created, containing the inputs,
*feerate\_per\_kw* showing the exact numeric feerate it used, 
*estimated\_final\_weight* for the estimated weight of the transaction
once fully signed, and *excess\_msat* containing the amount above *satoshi*
which is available.  This could be zero, or dust.  If *satoshi* was "all",
then *excess\_msat* is the entire amount once fees are subtracted
for the weights of the inputs and *startweight*.

If *reserve* was *true* or a non-zero number, then a *reservations*
array is returned, exactly like *reserveinputs*.

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

lightning-fundpsbt(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:5fe266fd3032274779129a8bf3868228a22481f178f3ec98a4fa9b6ad8a127d5)
