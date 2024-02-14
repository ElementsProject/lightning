lightning-listinvoicerequests -- Command for querying invoice\_request status
=============================================================================

SYNOPSIS
--------

**listinvoicerequests** [*invreq\_id*] [*active\_only*] 

DESCRIPTION
-----------

Command *added* in v22.11.

The **listinvoicerequests** RPC command gets the status of a specific `invoice_request`, if it exists, or the status of all `invoice_requests` if given no argument.

- **invreq\_id** (string, optional): A specific invoice can be queried by providing the `invreq_id`, which is presented by lightning-invoicerequest(7), or can be calculated from a bolt12 invoice.
- **active\_only** (boolean, optional): If it is *True* then only active invoice requests are returned. The default is *False*.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listinvoicerequests#1",
  "method": "listinvoicerequests",
  "params": [
    "cf0b41d4eb248d975909deb9accf9722b1c86839de80ee8815ce907bbb700a1d"
  ]
}
```

RETURN VALUE
------------

On success, an object containing **invoicerequests** is returned. It is an array of objects, where each object contains:

- **invreq\_id** (hash): The SHA256 hash of all invoice\_request fields less than 160.
- **active** (boolean): Whether the invoice\_request is currently active.
- **single\_use** (boolean): Whether the invoice\_request will become inactive after we pay an invoice for it.
- **bolt12** (string): The bolt12 string starting with lnr.
- **used** (boolean): Whether the invoice\_request has already been used.
- **label** (string, optional): The label provided when creating the invoice\_request.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "invoicerequests": [
    {
      "invreq_id": "cf0b41d4eb248d975909deb9accf9722b1c86839de80ee8815ce907bbb700a1d",
      "active": true,
      "single_use": true,
      "bolt12": "lnr1qqgx9ag7nmtns87htndlgcfndlq0wzstwd5k6urvv5s8getnw3gzqp3zderpzxstt8927ynqg044h0egcd8n5h3n9g0u0v4h8ncc3yg02gzqta0pqpvzzqnxu3vc68fug904w25y3zpskc8huazwmy34av93h2fjswe3tsp4rrcyps5sf5jwnn2tr3ghn32mdta8jvax62pwzhna8sktmaezl3f4s3zy35gx6dfay7r8zn299uwr7ugpze74zft4m8q3fnk2sr0ljqpve3jq",
      "used": false
    }
  ]
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-invoicerequests(7), lightning-disableinvoicerequest(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
