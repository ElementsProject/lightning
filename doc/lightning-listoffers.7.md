lightning-listoffers -- Command for listing offers
=======================================================

SYNOPSIS
--------
**(WARNING: experimental-offers only)**

**listoffers** \[*offer_id*\] \[*active_only*\]

DESCRIPTION
-----------

The **listoffers** RPC command list all offers, or with `offer_id`,
only the offer with that offer_id (if it exists).  If `active_only` is
set and is true, only offers with `active` true are returned.

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "listoffers",
  "params": {
	"active_only": false
  }
}
```

RETURN VALUE
------------

On success, an array *offers* of objects is returned. Each object contains:

* *offer_id*: the hash of the offer.
* *active*: true
* *single_use*: true if *single_use* was specified.
* *bolt12*: the bolt12 offer, starting with "lno1"
* *used*: true if an associated invoice has been paid.

Optionally:
* *label*: the user-specified label.


EXAMPLE JSON RESPONSE
-----
```json
{
  "offers": [
    {
      "offer_id": "053a5c566fbea2681a5ff9c05a913da23e45b95d09ef5bd25d7d408f23da7084",
      "active": true,
      "single_use": false,
      "bolt12": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqvqcdgq2z9pk7enxv4jjqen0wgs8yatnw3ujz83qkc6rvp4j28rt3dtrn32zkvdy7efhnlrpr5rp5geqxs783wtlj550qs8czzku4nk3pqp6m593qxgunzuqcwkmgqkmp6ty0wyvjcqdguv3pnpukedwn6cr87m89t74h3auyaeg89xkvgzpac70z3m9rn5xzu28c",
      "used": false
    },
    {
      "offer_id": "3247d3597fec19e362ca683416a48a0f76a44c1600725a7ee1936548feadacca",
      "active": true,
      "single_use": false,
      "bolt12": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcxqd24x3qgqgqlgzs3gdhkven9v5sxvmmjype82um50ys3ug9kxsmqdvj3c6ut2cuu2s4nrf8k2dulccgaqcdzxgp583utjlu49rcyqt8hc3s797umxn3r9367rdqc577rma7key58fywkajxnuzyapge86hj2pg80rjrma40xdqrxnsnva5l3ce7hz4ua8wf755dees4y9vnq",
      "used": true
    }
  ]
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
