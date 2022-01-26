lightning-listsendpays -- Low-level command for querying sendpay status
=======================================================================

SYNOPSIS
--------

**listsendpays** [*bolt11*] [*payment\_hash*] [*status*]

DESCRIPTION
-----------

The **listsendpays** RPC command gets the status of all *sendpay*
commands (which is also used by the *pay* command), or with *bolt11* or
*payment\_hash* limits results to that specific payment. You cannot
specify both. It is possible filter the payments also by *status*.

Note that in future there may be more than one concurrent *sendpay*
command per *pay*, so this command should be used with caution.

RETURN VALUE
------------

Note that the returned array is ordered by increasing *id*.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **payments** is returned.  It is an array of objects, where each object contains:
- **id** (u64): unique ID for this payment attempt
- **payment_hash** (hex): the hash of the *payment_preimage* which will prove payment (always 64 characters)
- **status** (string): status of the payment (one of "pending", "failed", "complete")
- **created_at** (u64): the UNIX timestamp showing when this payment was initiated
- **amount_sent_msat** (msat): The amount sent
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment_hash
- **amount_msat** (msat, optional): The amount delivered to destination (if known)
- **destination** (pubkey, optional): the final destination of the payment if known
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if pay supplied one)
- **bolt12** (string, optional): the bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "complete":
  - **payment_preimage** (hex): the proof of payment: SHA256 of this **payment_hash** (always 64 characters)

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

[comment]: # ( SHA256STAMP:1dfcb495e0004b9dadffd7f69b58275bf9168c9f4007675b390ebbaea07ffde6)
