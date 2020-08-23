lightning-donateutxo -- Command to donate a UTXO to miners
==========================================================

SYNOPSIS
--------

**donateutxo** *utxo* *amount*

DESCRIPTION
-----------

**donateutxo** donates a specific *utxo* (a string of the form "txid:vout")
to miners.

The *amount* must exactly match the amount of the UTXO.
This parameter exists as a basic safety check for manual usage of this
command.
A human user of this command must acquire the exact value of the UTXO
and explicitly specify it,
as a basic check that the amount to be donated is reasonable.

Once donated, **there is no way to recover the funds**.
Miners have very strong incentive to gather such donations and do not
have any incentive to mine an alternative transaction to claw back the
donation.

This is intended to be used to reduce privacy leakage on dust coins sometimes
created by blockchain analysis.
Thus, it will only donate one UTXO at a time, and will not accept multiple
UTXOS being donated, as those addresses would become linked.

RETURN VALUE
------------

On success, returns the *tx* and *txid* of the donation transaction.

On failure, one of the following error codes may be returned:

* -32602: If the given *utxo* is incorrect, or has been spent or
  reserved for other use.
* 301: If the given *amount* does not match the exact amount of the
  given *utxo*.

AUTHOR
------

ZmnSCPxj < <ZmnSCPxj@protonmail.com> > is mainly responsible.

SEE ALSO
--------

lightning-withdraw(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
