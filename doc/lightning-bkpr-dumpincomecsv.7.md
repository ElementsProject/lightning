lightning-bkpr-dumpincomecsv -- Command to emit a CSV of income events
=================================================================

SYNOPSIS
--------

**bkpr-dumpincomecsv** *csv_format* \[*csv_file*\] \[*consolidate_fees*\] \[*start_time*\] \[*end_time*\]

DESCRIPTION
-----------

The **bkpr-dumpincomcsv** RPC command writes a CSV file to disk at *csv_file*
location. This is a formatted output of the **listincome** RPC command.

**csv_format** is which CSV format to use. See RETURN VALUE for options.

**csv_file** is the on-disk destination of the generated CSV file.

If **consolidate_fees** is true, we emit a single, consolidated event for
any onchain-fees for a txid and account. Otherwise, events for every update to
the onchain fee calculation for this account and txid will be printed.
Defaults to true. Note that this means that the events emitted are
non-stable, i.e.  calling **dumpincomecsv** twice may result in different
onchain fee events being emitted, depending on how much information we've
logged for that transaction.

The **start_time** is a UNIX timestamp (in seconds) that filters events after the provided timestamp. Defaults to zero.

The **end_time** is a UNIX timestamp (in seconds) that filters events up to and at the provided timestamp. Defaults to max-int.


RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **csv\_file** (string): File that the csv was generated to
- **csv\_format** (string): Format to print csv as (one of "cointracker", "koinly", "harmony", "quickbooks")

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

niftynei <niftynei@gmail.com> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-bkpr-listfunds(7),
lightning-bkpr-listaccountevents(7),
lightning-bkpr-channelsapy(7), lightning-listpeers(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:1375c000d025b6cb72daa3b2ea64ec3212ae1aa5552c0d87918fd869d2fc5a0b)
