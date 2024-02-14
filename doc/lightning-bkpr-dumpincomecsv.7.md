lightning-bkpr-dumpincomecsv -- Command to emit a CSV of income events
======================================================================

SYNOPSIS
--------

**bkpr-dumpincomecsv** *csv\_format* [*csv\_file*] [*consolidate\_fees*] [*start\_time*] [*end\_time*] 

DESCRIPTION
-----------

The **bkpr-dumpincomcsv** RPC command writes a CSV file to disk at *csv\_file* location. This is a formatted output of the **listincome** RPC command.

- **csv\_format** (string): CSV format to use. See RETURN VALUE for options.
- **csv\_file** (string, optional): On-disk destination of the generated CSV file.
- **consolidate\_fees** (boolean, optional): If true, we emit a single, consolidated event for any onchain-fees for a txid and account. Otherwise, events for every update to the onchain fee calculation for this account and txid will be printed. Note that this means that the events emitted are non-stable, i.e. calling **dumpincomecsv** twice may result in different onchain fee events being emitted, depending on how much information we've logged for that transaction. The default is True.
- **start\_time** (u64, optional): UNIX timestamp (in seconds) that filters events after the provided timestamp. The default is zero.
- **end\_time** (u64, optional): UNIX timestamp (in seconds) that filters events up to and at the provided timestamp. The default is max-int.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:bkpr-dumpincomecsv#1",
  "method": "bkpr-dumpincomecsv",
  "params": [
    "koinly",
    "koinly.csv"
  ]
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **csv\_file** (string): File that the csv was generated to.
- **csv\_format** (string) (one of "cointracker", "koinly", "harmony", "quickbooks"): Format to print csv as.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "csv_file": "koinly.csv",
  "csv_format": "koinly"
}
```

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-bkpr-listfunds(7), lightning-bkpr-listaccountevents(7), lightning-bkpr-channelsapy(7), lightning-listpeers(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
