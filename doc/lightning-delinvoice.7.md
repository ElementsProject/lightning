lightning-delinvoice -- Command for removing an invoice (or just its description)
=================================================================================

SYNOPSIS
--------

**delinvoice** *label* *status* [*desconly*] 

DESCRIPTION
-----------

The **delinvoice** RPC command removes an invoice with *status* as given in **listinvoices**, or with *desconly* set, removes its description.

- **label** (one of): Label of the invoice to be deleted.:
  - (string)
  - (u64)
- **status** (string) (one of "paid", "expired", "unpaid"): Label of the invoice to be deleted. The caller should be particularly aware of the error case caused by the *status* changing just before this command is invoked!
- **desconly** (boolean, optional): If set to True, the invoice is not deleted, but has its description removed (this can save space with very large descriptions, as would be used with lightning-invoice(7) *deschashonly*.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:delinvoice#1",
  "method": "delinvoice",
  "params": {
    "label": "invlabel2",
    "status": "unpaid",
    "desconly": true
  }
}
{
  "id": "example:delinvoice#2",
  "method": "delinvoice",
  "params": {
    "label": "keysend-1708640419.666098582",
    "status": "paid",
    "desconly": null
  }
}
```

RETURN VALUE
------------

Note: The return is the same as an object from lightning-listinvoice(7).
On success, an object is returned, containing:

- **label** (string): Unique label given at creation time.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **created\_index** (u64): 1-based index indicating order this invoice was created in. *(added v23.08)*
- **status** (string) (one of "paid", "expired", "unpaid"): State of invoice.
- **expires\_at** (u64): UNIX timestamp when invoice expires (or expired).
- **bolt11** (string, optional): BOLT11 string.
- **bolt12** (string, optional): BOLT12 string.
- **amount\_msat** (msat, optional): The amount required to pay this invoice.
- **description** (string, optional): Description used in the invoice.
- **updated\_index** (u64, optional): 1-based index indicating order this invoice was changed (only present if it has changed since creation). *(added v23.08)*

If **bolt12** is present:
  - **local\_offer\_id** (hex, optional): Offer for which this invoice was created.
  - **invreq\_payer\_note** (string, optional): The optional *invreq\_payer\_note* from invoice\_request which created this invoice.

If **status** is "paid":
  - **pay\_index** (u64): Unique index for this invoice payment.
  - **amount\_received\_msat** (msat): How much was actually received.
  - **paid\_at** (u64): UNIX timestamp of when payment was received.
  - **payment\_preimage** (secret): SHA256 of this is the *payment\_hash* offered in the invoice.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "label": "invlabel2",
  "bolt11": "lnbcrt420p1pja0tefsp5vvzg40t4g24l0eqk0jch7mc6jm3ec52ts8w8gwzpwtx9c8nv05rspp533e9csxurt7j9sn2cx7hsn6m00475qgrau8sux5r7djpdedwy2fshp5xqsmrtgfcwsnhxcxmf3tuc65kl6fxvqhvujfmxw2kpeh95yy2x8sxqyjw5qcqp99qxpqysgqgfjrz4q5zcq2lluxxg9h475mq2d3w0tpdstm5274zmhadjl8cqapylfskzk96apka5599a2flm90rmavsk7q8mhh87yle3sgh5vrlycq72fern",
  "payment_hash": "8c725c40dc1afd22c26ac1bd784f5b7bebea0103ef0f0e1a83f36416e5ae2293",
  "amount_msat": 42,
  "status": "unpaid",
  "expires_at": 1709238697,
  "created_index": 3
}
{
  "label": "keysend-1708640419.666098582",
  "bolt11": "lnbcrt1pja0j9rsp5tg3zvj846gcdzw394njazq40s946sq2ur3hkl4xu4xudtjdtckxspp5fuunrfzsnyz2uxjmg2n95mqhghv4fpvv2kud3kvq4fkys3vmzu5sdqvddjhjum9dejqxqyjw5qcqp99qxpqysgqwt7r0gjlgt7zrfldc3um9myfc36acpqnsdn77c2m42facjtps30yufc5nsmwzhgexlj59f6xa5hess6e3tqrxynt9fejzj3rrshddtcqnappmj",
  "payment_hash": "4f3931a4509904ae1a5b42a65a6c1745d954858c55b8d8d980aa6c48459b1729",
  "status": "paid",
  "pay_index": 1,
  "amount_received_msat": 10000000,
  "paid_at": 1708640419,
  "payment_preimage": "b760af47f456a217e8dfda21a282f1f78c903487c1b21b3b318135f75aa3bf11",
  "description": "keysend",
  "expires_at": 1709245219,
  "created_index": 1,
  "updated_index": 1
}
```

ERRORS
------

The following errors may be reported:

- -1: Database error.
- 905: An invoice with that label does not exist.
- 906: The invoice *status* does not match the parameter. An error object will be returned as error *data*, containing *current\_status* and *expected\_status* fields. This is most likely due to the *status* of the invoice changing just before this command is invoked.
- 908: The invoice already has no description, and *desconly* was set.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-waitinvoice(7), lightning-invoice(7), lightning-delexpiredinvoice(7), lightning-autoclean-status(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
