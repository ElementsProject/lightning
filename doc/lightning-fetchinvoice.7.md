lightning-fetchinvoice -- Command for fetch an invoice for an offer
===================================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**fetchinvoice** *offer* [*amount\_msat*] [*quantity*] [*recurrence\_counter*] [*recurrence\_start*] [*recurrence\_label*] [*timeout*] [*payer\_note*] 

DESCRIPTION
-----------

The **fetchinvoice** RPC command contacts the issuer of an *offer* to get an actual invoice that can be paid. It highlights any changes between the offer and the returned invoice.

If **fetchinvoice-noconnect** is not specified in the configuation, it will connect to the destination in the (currently common!) case where it cannot find a route which supports `option_onion_messages`.

- **offer** (string): Offer string to get an actual invoice that can be paid.
- **amount\_msat** (msat, optional): Required if the offer does not specify an amount at all, otherwise it is optional (but presumably if you set it to less than the offer, you will get an error from the issuer).
- **quantity** (u64, optional): Required if the offer specifies quantity\_max, otherwise it is not allowed.
- **recurrence\_counter** (u64, optional): Required if the offer specifies recurrence, otherwise it is not allowed. recurrence\_counter should first be set to 0, and incremented for each successive invoice in a given series.
- **recurrence\_start** (number, optional): Required if the offer specifies recurrence\_base with start\_any\_period set, otherwise it is not allowed. It indicates what period number to start at.
- **recurrence\_label** (string, optional): Required if recurrence\_counter is set, and otherwise is not allowed. It must be the same as prior fetchinvoice calls for the same recurrence, as it is used to link them together.
- **timeout** (number, optional): If we don't get a reply before this we fail (default, 60 seconds).
- **payer\_note** (string, optional): To ask the issuer to include in the fetched invoice.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:fetchinvoice#1",
  "method": "fetchinvoice",
  "params": {
    "offer": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqypq5zmnd9khqmr9yp6x2um5zcssxhftzxfdlwsnfcgw2sy8t5mxa0ytcdfat2nkdwqvpy9nnsa9mzza",
    "payer_note": "Thanks for the fish!"
  }
}
{
  "id": "example:fetchinvoice#2",
  "method": "fetchinvoice",
  "params": {
    "offer": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqypq5zmnd9khqmr9yp6x2um5zcssxhftzxfdlwsnfcgw2sy8t5mxa0ytcdfat2nkdwqvpy9nnsa9mzza",
    "amount_msat": 3
  }
}
{
  "id": "example:fetchinvoice#3",
  "method": "fetchinvoice",
  "params": {
    "offer": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqypq5zmnd9khqmr9yp6x2um5zsqs593pqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4j",
    "quantity": 2
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **invoice** (string): The BOLT12 invoice we fetched.
- **changes** (object): Summary of changes from offer.:
  - **description\_appended** (string, optional): Extra characters appended to the *description* field.
  - **description** (string, optional): A completely replaced *description* field.
  - **vendor\_removed** (string, optional): The *vendor* from the offer, which is missing in the invoice.
  - **vendor** (string, optional): A completely replaced *vendor* field.
  - **amount\_msat** (msat, optional): The amount, if different from the offer amount multiplied by any *quantity* (or the offer had no amount, or was not in BTC).
- **next\_period** (object, optional): Only for recurring invoices if the next period is under the *recurrence\_limit*.:
  - **counter** (u64): The index of the next period to fetchinvoice.
  - **starttime** (u64): UNIX timestamp that the next period starts.
  - **endtime** (u64): UNIX timestamp that the next period ends.
  - **paywindow\_start** (u64): UNIX timestamp of the earliest time that the next invoice can be fetched.
  - **paywindow\_end** (u64): UNIX timestamp of the latest time that the next invoice can be fetched.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "invoice": "lni1qqgvcm9h7yakcmw4mzazspu8vfgpwq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqgzpg9hx6tdwpkx2gr5v4ehg93pqdwjkyvjm7apxnssu4qgwhfkd67ghs6n6k48v6uqczgt88p6tky965pqqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy84sggren772kj8mau5jp86nc6fszx48rv7ep0quszyyls8rlld3sshjr94j9z5dpsku6mnypnx7u3qw35x2grxd9eksgdqnqp462c3jt0m5y6wzrj5pp6axehtez7r20265antsrqfpvuu8fwcshgr0tsv8e6829e8xmv7laz0kwhtlx6vtk8q3d6rtthdhtwvnn6j585szquc2t7us8kguxypzasg8ewkakgx2ny5ugks0f32x67sm9e5fms4asqrylajc2dqh8ag55mv5p5ghy3e2z8zwmllle8uu7jsxv5ke8d6rr5h7kthmz7ya0hxp4nt7elvw7vghcl6fgsuqqqqqqqqqqqqqqq9qqqqqqqqqqqqq8fykt06c5sqqqqqpfqyvhtunn4gyzy0lphn4wn6ctzlsajy46wscjcglf3hxcnvlaxqs3ydkhgaklsc42spq2czzq6a9vge9ha6zd8ppe2qsawnvm4u30p484d2we4cpsyskwwr5hvgthcyqyuen02ejwpa9cjjrttvp223yxsqkrwnlaszkhas84w0ape300ued4p75xu3cqtcg0cslsx9fvh7dhdqx565t6wa0alf6u2hug90j2hs",
  "changes": {}
}
{
  "invoice": "lni1qqg0mfchkz0gkmn8zzu5zaxd0qvlzq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqgzpg9hx6tdwpkx2gr5v4ehg93pqdwjkyvjm7apxnssu4qgwhfkd67ghs6n6k48v6uqczgt88p6tky965pqqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy84yqgrtqss8d4vgzd3286u9rk0zg9qr7a6z2xm6mjnz9pydztcn0j74tjvch0f5zvqxhftzxfdlwsnfcgw2sy8t5mxa0ytcdfat2nkdwqvpy9nnsa9mzzaqth4fzjqxxmsaxvc4v2urs6hsh6k0e564x00g68vuyp5w7yjedzxvqgr8ltzmj0n7ltxr0tz9rafn9zcy9jldjqfuf20w6gjmr7nj04d360sqvkdwprxn22dlp3xay9yq4nhrw2jm0c8t6r7japhdad6leawxyqzkg92tx8gqxp9f2d8j5k2axta0gr7yr9zrsqqqqqqqqqqqqqqq5qqqqqqqqqqqqqayjedltzjqqqqqq9yq3ja0jwj4qswt3kgs9mxq7gck66x60m5rndykpw3a7hf4ntlp9qe2vgwzzrvcwd2qypmqggrt543ryklhgf5uy89gzr46dnwhj9ux5744fmxhqxqjzeecwja3pwlqsxyjcdwur4hl4qf7nsjgg8euvy45lznufh5kydkwz6llsucuhvwp9ezeggaj3k057ge6ftvaffjkwn6j3y7faeuysrx3m2xccphu65sx",
  "changes": {}
}
{
  "invoice": "lni1qqgd508mv9rpjg2ec8dr8qcslf2cjq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqgzpg9hx6tdwpkx2gr5v4ehg9qppgtzzq3dygmzpg6e53ll0aavg37gt3rvjg762vufygdqq4xprs0regcat9gzqp3zderpzxstt8927ynqg044h0egcd8n5h3n9g0u0v4h8ncc3yg02cqsykppqfkyy6q8ry9pchxtuajh456hhcf7dxx733cx76etuv5ftfmfa2ymhgycqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4jq6uhkeymz26zx7zgw4gdmw2vj9xqn4hu2sqxhp0pcgt87pf9chyfvqsywtejxjh603kx7am3zaf6d6xuumw30p8zmcdz7r95nn4lr92exk3qqe2x6xqwpdzh2zwq3vnyra8nfc6d7y6hegpkvc7p2nulj7hvhwl5hjfr23wn60mjftqspn7d4ejhrpsr5m2y8qqqqqqqqqqqqqqqpgqqqqqqqqqqqqp6f9jm7k9yqqqqqq2gpr96l9mt2pqxuyr0gqw92h0xz2y2uy5uxss4ujcac5jehj9ay2sxkapr80t5ha65qgykqssytfzxcs2xkdy0lml0tzy0jzugmyj8kjn8zfzrgq9fsgurc72x82e7pqxhl4u29cjluw5s8fwa9wtvh0qytr7vqk0vtndsz07mrrtmjw629m8mnqkjaf43kt889qeq2f7deu6t853lngpzclapt8nj0g528v9ay",
  "changes": {}
}
```

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.
- 1002: Offer has expired.
- 1003: Cannot find a route to the node making the offer.
- 1004: The node making the offer returned an error message.
- 1005: We timed out trying to fetch an invoice.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-sendinvoice(7), lightning-pay(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
