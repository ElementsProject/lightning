lightning-listsendpays -- Low-level command for querying sendpay status
=======================================================================

SYNOPSIS
--------

**listsendpays** [*bolt11*] [*payment\_hash*] [*status*] [*index* [*start*] [*limit*]]

DESCRIPTION
-----------

The **listsendpays** RPC command gets the status of all *sendpay* commands (which is also used by the *pay* command), or with *bolt11* or *payment\_hash* limits results to that specific payment. You cannot specify both. It is possible to filter the payments also by *status*.

Note that there may be more than one concurrent *sendpay* command per *pay*, so this command should be used with caution.

- **bolt11** (string, optional): Bolt11 invoice.
- **payment\_hash** (hash, optional): The hash of the payment\_preimage.
- **status** (string, optional) (one of "pending", "complete", "failed"): Whether the invoice has been paid, pending, or failed.
- **index** (string, optional) (one of "created", "updated"): If neither bolt11 or payment\_hash is specified, `index` controls ordering, by `created` (default) or `updated`. *(added v23.11)*
- **start** (u64, optional): If `index` is specified, `start` may be specified to start from that value, which is generally returned from lightning-wait(7). *(added v23.11)*
- **limit** (u32, optional): If `index` is specified, `limit` can be used to specify the maximum number of entries to return. *(added v23.11)*

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listsendpays#1",
  "method": "listsendpays",
  "params": {
    "bolt11": null,
    "payment_hash": null,
    "status": null,
    "index": null,
    "start": null,
    "limit": null
  }
}
{
  "id": "example:listsendpays#2",
  "method": "listsendpays",
  "params": {
    "bolt11": "lnbcrt1230n1pja03q9sp5xu9aypccf3n6vld2waxcysy47ct2wl5x5adtm7k8u30knqes22lspp5duw2v8csh0zh4xg9ql3amem98avlkc2ecre99tgmr2340amf9kmsdqjv3jhxcmjd9c8g6t0dcxqyjw5qcqp99qxpqysgqwh78s8wqg0kepspw0epcxmxteh5wu8n6ddlwdnyj758fqxpqk8ejf597x8ju3r32xqgae3yzjjz9e5s6l2vs5zxvkayhmemmx74wvyqqyqf8c9",
    "payment_hash": null,
    "status": null,
    "index": null,
    "start": null,
    "limit": null
  }
}
```

RETURN VALUE
------------

Note that the returned array is ordered by increasing *id*.
On success, an object containing **payments** is returned. It is an array of objects, where each object contains:

- **created\_index** (u64): 1-based index indicating order this payment was created in. *(added v23.11)*
- **id** (u64): Old synonym for created\_index.
- **groupid** (u64): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "pending", "failed", "complete"): Status of the payment.
- **created\_at** (u64): The UNIX timestamp showing when this payment was initiated.
- **amount\_sent\_msat** (msat): The amount sent.
- **partid** (u64, optional): Part number (for multiple parts to a single payment).
- **updated\_index** (u64, optional): 1-based index indicating order this payment was changed (only present if it has changed since creation). *(added v23.11)*
- **amount\_msat** (msat, optional): The amount delivered to destination (if known).
- **destination** (pubkey, optional): The final destination of the payment if known.
- **label** (string, optional): The label, if given to sendpay.
- **bolt11** (string, optional): The bolt11 string (if pay supplied one).
- **description** (string, optional): The description matching the bolt11 description hash (if pay supplied one).
- **bolt12** (string, optional): The bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "complete":
  - **payment\_preimage** (secret): The proof of payment: SHA256 of this **payment\_hash**.
  - **completed\_at** (u64, optional): The UNIX timestamp showing when this payment was completed. *(added pre-v0.10.1)*

If **status** is "failed":
  - **erroronion** (hex, optional): The onion message returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "payments": [
    {
      "created_index": 1,
      "id": 1,
      "payment_hash": "e3b43574acd074b0c4ba1b13b5155ff5f9c76742e643ed003e17301c5a2db149",
      "groupid": 1,
      "destination": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "amount_msat": 20000,
      "amount_sent_msat": 20000,
      "created_at": 1706225269,
      "status": "pending",
      "bolt11": "lnbcrt200n1pjm9mn5sp5gq84lgga959m6gg4g0kj29ypwjaxxnm4cu5csymq8p6nqxv800mspp5uw6r2a9v6p6tp396rvfm292l7huuwe6zuep76qp7zucpck3dk9ysdpqf9grgmt62fmk5stswefh23n2tpykvcmzxqyjw5qcqp99qxpqysgqz8s496zmwed278jvp075zlhrnj0ncg45kcfw5s2lkhtxd3wc39f8wflp5gmd827dk470xpasfpx0azsfu0k8ttwae7620h8d050w28cqan776g"
    },
    {
      "created_index": 2,
      "id": 2,
      "payment_hash": "f55d92cfe019b5a015f5e5956e9255053cda14786171d5002feb12ae5254e5a5",
      "groupid": 1,
      "destination": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "amount_msat": 30000,
      "amount_sent_msat": 30000,
      "created_at": 1706225269,
      "status": "pending",
      "bolt11": "lnbcrt300n1pjm9mn5sp5zqfkr93rp92mdyj6m8lzpcu90rfefcaqff8fxdd2sc5mace23ujspp574we9nlqrx66q904uk2kayj4q57d59rcv9ca2qp0avf2u5j5ukjsdpq29j55nfcgfcnsvzw2er57knhwcmhzwt0xqyjw5qcqp99qxpqysgq76p2jpnegtzlxmn0aqt6d3f89q4p6y5v3v2qz7t2mm6xt90nt324cq400tl82k28562aux8jxs57d603g7s0q4g3dapu9a7vln94j7spsut799"
    }
  ]
}
{
  "payments": [
    {
      "created_index": 1,
      "id": 1,
      "payment_hash": "6f1ca61f10bbc57a990507e3dde7653f59fb6159c0f252ad1b1aa357f7692db7",
      "groupid": 1,
      "updated_index": 1,
      "destination": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "amount_msat": 123000,
      "amount_sent_msat": 123000,
      "created_at": 1708639237,
      "completed_at": 1708639238,
      "status": "complete",
      "payment_preimage": "91f8366681fdfd309c048082fcde81a79116f85a7b2dd09aef1e34f5f7c3397b",
      "bolt11": "lnbcrt1230n1pja03q9sp5xu9aypccf3n6vld2waxcysy47ct2wl5x5adtm7k8u30knqes22lspp5duw2v8csh0zh4xg9ql3amem98avlkc2ecre99tgmr2340amf9kmsdqjv3jhxcmjd9c8g6t0dcxqyjw5qcqp99qxpqysgqwh78s8wqg0kepspw0epcxmxteh5wu8n6ddlwdnyj758fqxpqk8ejf597x8ju3r32xqgae3yzjjz9e5s6l2vs5zxvkayhmemmx74wvyqqyqf8c9"
    }
  ]
}
```

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-sendpay(7), lightning-listinvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
