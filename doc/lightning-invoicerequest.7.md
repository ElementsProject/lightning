lightning-invoicerequest -- Command for offering payments
=========================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**invoicerequest** *amount* *description* [*issuer*] [*label*] [*absolute\_expiry*] [*single\_use*] 

DESCRIPTION
-----------

Command *added* in v22.11.

The **invoicerequest** RPC command creates an `invoice_request` to send payments: it automatically enables the processing of an incoming invoice, and payment of it. The reader of the resulting `invoice_request` can use lightning-sendinvoice(7) to collect their payment.

- **amount** (msat): A positive value in millisatoshi precision; it can be a whole number, or a whole number ending in *msat* or *sat*, or a number with three decimal places ending in *sat*, or a number with 1 to 11 decimal places ending in *btc*.
- **description** (string): A short description of purpose of the payment, e.g. *ATM withdrawl*. This value is encoded into the resulting `invoice_request` and is viewable by anyone you expose it to. It must be UTF-8, and cannot use *\u* JSON escape codes.
- **issuer** (string, optional): Who is issuing it (i.e. you) if appropriate.
- **label** (string, optional): An internal-use name for the offer, which can be any UTF-8 string.
- **absolute\_expiry** (u64, optional): The time the offer is valid until, in seconds since the first day of 1970 UTC. If not set, the `invoice_request` remains valid (though it can be deactivated by the issuer of course). This is encoded in the `invoice_request`.
- **single\_use** (boolean, optional): Indicates that the `invoice_request` is only valid once; we may attempt multiple payments, but as soon as one is successful no more invoices are accepted (i.e. only one person can take the money). The default is True.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:invoicerequest#1",
  "method": "invoicerequest",
  "params": {
    "amount": "10000sat",
    "description": "simple test",
    "issuer": "clightning test suite"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **invreq\_id** (hash): The SHA256 hash of all invoice\_request fields less than 160.
- **active** (boolean) (always *true*): Whether the invoice\_request is currently active.
- **single\_use** (boolean): Whether the invoice\_request will become inactive after we pay an invoice for it.
- **bolt12** (string): The bolt12 string starting with lnr.
- **used** (boolean) (always *false*): Whether the invoice\_request has already been used.
- **label** (string, optional): The label provided when creating the invoice\_request.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "invreq_id": "715484ead84bcdae5b33e3015c686fa1bdd4ae9ade3c4729b58257a98cfcd9b5",
  "active": true,
  "single_use": true,
  "bolt12": "lnr1qqgteyhfyp40c79a5y3gfe33nxfs6zstwd5k6urvv5s8getnwsfp2cmvd9nksarwd9hxwgr5v4ehggrnw45hge2syqrzymjxzydqkkw24ufxqslttwlj3s608f0rx2slc7etw0833zgs75srnztgqkppqfnwgkvdr57yzh6h92zg3qctvrm7w38djg67kzcm4yeg8vc4cq633uzq99smfawuu6pz0zh9jl6dl8v25u3kzes975x2j9tr0qp0ux0tlzcxjrgehxh9luz5vwjpk92tys9f9zlm038krcz4uqfxgelwf43tgfc",
  "used": false
}
```

ERRORS
------

On failure, an error is returned and no `invoice_request` is created. If the lightning process fails before responding, the caller should use lightning-listinvoicerequests(7) to query whether it was created or not.

- -1: Catchall nonspecific error.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoicerequests(7), lightning-disableinvoicerequest(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
