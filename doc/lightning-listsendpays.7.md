lightning-listsendpays -- Low-level command for querying sendpay status
=======================================================================

SYNOPSIS
--------

**listsendpays** [*bolt11*] [*payment\_hash*] [*status*] [*index* [*start*] [*limit*]]

DESCRIPTION
-----------

The **listsendpays** RPC command gets the status of all *sendpay*
commands (which is also used by the *pay* command), or with *bolt11* or
*payment\_hash* limits results to that specific payment. You cannot
specify both. It is possible filter the payments also by *status*.

Note that there may be more than one concurrent *sendpay*
command per *pay*, so this command should be used with caution.

If neither *bolt11* or *payment\_hash* is specified,
`index` controls ordering, by `created` (default) or `updated`.  If
`index` is specified, `start` may be specified to start from that
value, which is generally returned from lightning-wait(7), and `limit`
can be used to specify the maximum number of entries to return.

RETURN VALUE
------------

Note that the returned array is ordered by increasing *id*.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **payments** is returned.  It is an array of objects, where each object contains:

- **created\_index** (u64): 1-based index indicating order this payment was created in *(added v23.11)*
- **id** (u64): old synonym for created\_index
- **groupid** (u64): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): status of the payment (one of "pending", "failed", "complete")
- **created\_at** (u64): the UNIX timestamp showing when this payment was initiated
- **amount\_sent\_msat** (msat): The amount sent
- **partid** (u64, optional): Part number (for multiple parts to a single payment)
- **updated\_index** (u64, optional): 1-based index indicating order this payment was changed (only present if it has changed since creation) *(added v23.11)*
- **amount\_msat** (msat, optional): The amount delivered to destination (if known)
- **destination** (pubkey, optional): the final destination of the payment if known
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if pay supplied one)
- **description** (string, optional): the description matching the bolt11 description hash (if pay supplied one)
- **bolt12** (string, optional): the bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "complete":

  - **payment\_preimage** (secret): the proof of payment: SHA256 of this **payment\_hash**

If **status** is "failed":

  - **erroronion** (hex, optional): the onion message returned

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly
responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-sendpay(7), lightning-listinvoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:d2c1dbc5953bb86579edf048ee02752d776e763d90729d46339d9a27412d2021)
