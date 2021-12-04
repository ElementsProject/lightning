lightning-disableoffer -- Command for removing an offer
=======================================================

SYNOPSIS
--------
**(WARNING: experimental-offers only)**

**disableoffer** *offer\_id*

DESCRIPTION
-----------

The **disableoffer** RPC command disables an offer, so that no further
invoices will be given out (if made with lightning-offer(7)) or
invoices accepted  (if made with lightning-offerout(7)).

We currently don't support deletion of offers, so offers are not
forgotten entirely (there may be invoices which refer to this offer).

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "disableoffer",
  "params": {
    "offer_id": "713a16ccd4eb10438bdcfbc2c8276be301020dd9d489c530773ba64f3b33307d ",
  }
}
```

RETURN VALUE
------------

Note: the returned object is the same format as **listoffers**.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **offer_id** (hex): the merkle hash of the offer (always 64 characters)
- **active** (boolean): Whether the offer can produce invoices/payments (always *false*)
- **single_use** (boolean): Whether the offer is disabled after first successful use
- **bolt12** (string): The bolt12 string representing this offer
- **bolt12_unsigned** (string): The bolt12 string representing this offer, without signature
- **used** (boolean): Whether the offer has had an invoice paid / payment made
- **label** (string, optional): The label provided when offer was created

[comment]: # (GENERATE-FROM-SCHEMA-END)

EXAMPLE JSON RESPONSE
-----
```json
{
   "offer_id": "053a5c566fbea2681a5ff9c05a913da23e45b95d09ef5bd25d7d408f23da7084",
   "active": false,
   "single_use": false,
   "bolt12": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqvqcdgq2z9pk7enxv4jjqen0wgs8yatnw3ujz83qkc6rvp4j28rt3dtrn32zkvdy7efhnlrpr5rp5geqxs783wtlj550qs8czzku4nk3pqp6m593qxgunzuqcwkmgqkmp6ty0wyvjcqdguv3pnpukedwn6cr87m89t74h3auyaeg89xkvgzpac70z3m9rn5xzu28c",
   "used": false
}

```


AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-offer(7), lightning-offerout(7), lightning-listoffers(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:a7dbc87d991d1040283b5fbfe732fb9bc7c81efad3aa8b5bfb11ffe59ed3f069)
