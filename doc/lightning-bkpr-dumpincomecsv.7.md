lightning-bkpr-dumpincomecsv -- Command to emit a CSV of income events
=================================================================

SYNOPSIS
--------

**bkpr-dumpincomecsv** *csv\_format* \[*csv\_file*\] \[*consolidate\_fees*\] \[*start\_time*\] \[*end\_time*\]

DESCRIPTION
-----------

The **bkpr-dumpincomcsv** RPC command writes a CSV file to disk at *csv\_file*
location. This is a formatted output of the **listincome** RPC command.

**csv\_format** is which CSV format to use. See RETURN VALUE for options.

**csv\_file** is the on-disk destination of the generated CSV file.

If **consolidate\_fees** is true, we emit a single, consolidated event for
any onchain-fees for a txid and account. Otherwise, events for every update to
the onchain fee calculation for this account and txid will be printed.
Defaults to true. Note that this means that the events emitted are
non-stable, i.e.  calling **dumpincomecsv** twice may result in different
onchain fee events being emitted, depending on how much information we've
logged for that transaction.

The **start\_time** is a UNIX timestamp (in seconds) that filters events after the provided timestamp. Defaults to zero.

The **end\_time** is a UNIX timestamp (in seconds) that filters events up to and at the provided timestamp. Defaults to max-int.


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

[comment]: # ( SHA256STAMP:e7ac14cae72e6a26d886b57e5a72139615638b4129e38337fceb216a7917133f)
