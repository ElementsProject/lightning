lightning-decode -- Command for decoding an invoice string (low-level)
=======================================================================

SYNOPSIS
--------

**decode** *string*

DESCRIPTION
-----------

The **decode** RPC command checks and parses:

- a *bolt11* or *bolt12* string (optionally prefixed by `lightning:`
  or `LIGHTNING:`) as specified by the BOLT 11 and BOLT 12
  specifications.
- a *rune* as created by lightning-commando-rune(7).

It may decode other formats in future.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **type** (string): what kind of object it decoded to (one of "bolt12 offer", "bolt12 invoice", "bolt12 invoice\_request", "bolt11 invoice", "rune")
- **valid** (boolean): if this is false, you *MUST* not use the result except for diagnostics!

If **type** is "bolt12 offer", and **valid** is *true*:

  - **offer\_id** (hex): the id we use to identify this offer (always 64 characters)
  - **offer\_description** (string): the description of the purpose of the offer
  - **offer\_node\_id** (pubkey): public key of the offering node
  - **offer\_chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only):
    - the genesis blockhash (always 64 characters)
  - **offer\_metadata** (hex, optional): any metadata the creater of the offer includes
  - **offer\_currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters)
  - **currency\_minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known)
  - **offer\_amount** (u64, optional): the amount in the `offer_currency` adjusted by `currency_minor_unit`, if any
  - **offer\_amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no `offer_currency`)
  - **offer\_issuer** (string, optional): the description of the creator of the offer
  - **offer\_features** (hex, optional): the feature bits of the offer
  - **offer\_absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires
  - **offer\_quantity\_max** (u64, optional): the maximum quantity (or, if 0, means any quantity)
  - **offer\_paths** (array of objects, optional): Paths to the destination:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **blinded\_node\_id** (pubkey): node\_id of the hop
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop
  - **offer\_recurrence** (object, optional): how often to this offer should be used:
    - **time\_unit** (u32): the BOLT12 time unit
    - **period** (u32): how many `time_unit` per payment period
    - **time\_unit\_name** (string, optional): the name of `time_unit` (if valid)
    - **basetime** (u64, optional): period starts at this UNIX timestamp
    - **start\_any\_period** (u64, optional): you can start at any period (only if `basetime` present)
    - **limit** (u32, optional): maximum period number for recurrence
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period):
      - **seconds\_before** (u32): seconds prior to period start
      - **seconds\_after** (u32): seconds after to period start
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*)
  - **unknown\_offer\_tlvs** (array of objects, optional): Any extra fields we didn't know how to parse:
    - **type** (u64): The type
    - **length** (u64): The length
    - **value** (hex): The value
  - the following warnings are possible:
    - **warning\_unknown\_offer\_currency**: The currency code is unknown (so no `currency_minor_unit`)

If **type** is "bolt12 offer", and **valid** is *false*:

  - the following warnings are possible:
    - **warning\_missing\_offer\_node\_id**: `offer_node_id` is not present
    - **warning\_invalid\_offer\_description**: `offer_description` is not valid UTF8
    - **warning\_missing\_offer\_description**: `offer_description` is not present
    - **warning\_invalid\_offer\_currency**: `offer_currency_code` is not valid UTF8
    - **warning\_invalid\_offer\_issuer**: `offer_issuer` is not valid UTF8

If **type** is "bolt12 invoice\_request", and **valid** is *true*:

  - **offer\_description** (string): the description of the purpose of the offer
  - **offer\_node\_id** (pubkey): public key of the offering node
  - **invreq\_metadata** (hex): the payer-provided blob to derive invreq\_payer\_id
  - **invreq\_payer\_id** (hex): the payer-provided key
  - **signature** (bip340sig): BIP-340 signature of the `invreq_payer_id` on this invoice\_request
  - **offer\_id** (hex, optional): the id we use to identify this offer (always 64 characters)
  - **offer\_chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only):
    - the genesis blockhash (always 64 characters)
  - **offer\_metadata** (hex, optional): any metadata the creator of the offer includes
  - **offer\_currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters)
  - **currency\_minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known)
  - **offer\_amount** (u64, optional): the amount in the `offer_currency` adjusted by `currency_minor_unit`, if any
  - **offer\_amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no `offer_currency`)
  - **offer\_issuer** (string, optional): the description of the creator of the offer
  - **offer\_features** (hex, optional): the feature bits of the offer
  - **offer\_absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires
  - **offer\_quantity\_max** (u64, optional): the maximum quantity (or, if 0, means any quantity)
  - **offer\_paths** (array of objects, optional): Paths to the destination:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **blinded\_node\_id** (pubkey): node\_id of the hop
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop
  - **offer\_recurrence** (object, optional): how often to this offer should be used:
    - **time\_unit** (u32): the BOLT12 time unit
    - **period** (u32): how many `time_unit` per payment period
    - **time\_unit\_name** (string, optional): the name of `time_unit` (if valid)
    - **basetime** (u64, optional): period starts at this UNIX timestamp
    - **start\_any\_period** (u64, optional): you can start at any period (only if `basetime` present)
    - **limit** (u32, optional): maximum period number for recurrence
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period):
      - **seconds\_before** (u32): seconds prior to period start
      - **seconds\_after** (u32): seconds after to period start
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*)
  - **invreq\_chain** (hex, optional): which blockchain this offer is for (missing implies bitcoin mainnet only) (always 64 characters)
  - **invreq\_amount\_msat** (msat, optional): the amount the invoice should be for
  - **invreq\_features** (hex, optional): the feature bits of the invoice\_request
  - **invreq\_quantity** (u64, optional): the number of items to invoice for
  - **invreq\_payer\_note** (string, optional): a note attached by the payer
  - **invreq\_recurrence\_counter** (u32, optional): which number request this is for the same invoice
  - **invreq\_recurrence\_start** (u32, optional): when we're requesting to start an invoice at a non-zero period
  - **unknown\_invoice\_request\_tlvs** (array of objects, optional): Any extra fields we didn't know how to parse:
    - **type** (u64): The type
    - **length** (u64): The length
    - **value** (hex): The value
  - the following warnings are possible:
    - **warning\_unknown\_offer\_currency**: The currency code is unknown (so no `currency_minor_unit`)

If **type** is "bolt12 invoice\_request", and **valid** is *false*:

  - the following warnings are possible:
    - **warning\_invalid\_offer\_description**: `offer_description` is not valid UTF8
    - **warning\_missing\_offer\_description**: `offer_description` is not present
    - **warning\_invalid\_offer\_currency**: `offer_currency_code` is not valid UTF8
    - **warning\_invalid\_offer\_issuer**: `offer_issuer` is not valid UTF8
    - **warning\_missing\_invreq\_metadata**: `invreq_metadata` is not present
    - **warning\_missing\_invreq\_payer\_id**: `invreq_payer_id` is not present
    - **warning\_invalid\_invreq\_payer\_note**: `invreq_payer_note` is not valid UTF8
    - **warning\_missing\_invoice\_request\_signature**: `signature` is not present
    - **warning\_invalid\_invoice\_request\_signature**: Incorrect `signature`

If **type** is "bolt12 invoice", and **valid** is *true*:

  - **offer\_description** (string): the description of the purpose of the offer
  - **offer\_node\_id** (pubkey): public key of the offering node
  - **invreq\_metadata** (hex): the payer-provided blob to derive invreq\_payer\_id
  - **invreq\_payer\_id** (hex): the payer-provided key
  - **invoice\_paths** (array of objects): Paths to pay the destination:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **blinded\_node\_id** (pubkey): node\_id of the hop
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop
      - **fee\_base\_msat** (msat, optional): basefee for path
      - **fee\_proportional\_millionths** (u32, optional): proportional fee for path
      - **cltv\_expiry\_delta** (u32, optional): CLTV delta for path
      - **features** (hex, optional): features allowed for path
  - **invoice\_created\_at** (u64): the UNIX timestamp of invoice creation
  - **invoice\_payment\_hash** (hex): the hash of the *payment\_preimage* (always 64 characters)
  - **invoice\_amount\_msat** (msat): the amount required to fulfill invoice
  - **signature** (bip340sig): BIP-340 signature of the `offer_node_id` on this invoice
  - **offer\_id** (hex, optional): the id we use to identify this offer (always 64 characters)
  - **offer\_chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only):
    - the genesis blockhash (always 64 characters)
  - **offer\_metadata** (hex, optional): any metadata the creator of the offer includes
  - **offer\_currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters)
  - **currency\_minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known)
  - **offer\_amount** (u64, optional): the amount in the `offer_currency` adjusted by `currency_minor_unit`, if any
  - **offer\_amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no `offer_currency`)
  - **offer\_issuer** (string, optional): the description of the creator of the offer
  - **offer\_features** (hex, optional): the feature bits of the offer
  - **offer\_absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires
  - **offer\_quantity\_max** (u64, optional): the maximum quantity (or, if 0, means any quantity)
  - **offer\_paths** (array of objects, optional): Paths to the destination:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **blinded\_node\_id** (pubkey): node\_id of the hop
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop
  - **offer\_recurrence** (object, optional): how often to this offer should be used:
    - **time\_unit** (u32): the BOLT12 time unit
    - **period** (u32): how many `time_unit` per payment period
    - **time\_unit\_name** (string, optional): the name of `time_unit` (if valid)
    - **basetime** (u64, optional): period starts at this UNIX timestamp
    - **start\_any\_period** (u64, optional): you can start at any period (only if `basetime` present)
    - **limit** (u32, optional): maximum period number for recurrence
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period):
      - **seconds\_before** (u32): seconds prior to period start
      - **seconds\_after** (u32): seconds after to period start
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*)
  - **invreq\_chain** (hex, optional): which blockchain this offer is for (missing implies bitcoin mainnet only) (always 64 characters)
  - **invreq\_amount\_msat** (msat, optional): the amount the invoice should be for
  - **invreq\_features** (hex, optional): the feature bits of the invoice\_request
  - **invreq\_quantity** (u64, optional): the number of items to invoice for
  - **invreq\_payer\_note** (string, optional): a note attached by the payer
  - **invreq\_recurrence\_counter** (u32, optional): which number request this is for the same invoice
  - **invreq\_recurrence\_start** (u32, optional): when we're requesting to start an invoice at a non-zero period
  - **invoice\_relative\_expiry** (u32, optional): the number of seconds after *invoice\_created\_at* when this expires
  - **invoice\_fallbacks** (array of objects, optional): onchain addresses:
    - **version** (u8): Segwit address version
    - **hex** (hex): Raw encoded segwit address
    - **address** (string, optional): bech32 segwit address
  - **invoice\_features** (hex, optional): the feature bits of the invoice
  - **invoice\_node\_id** (pubkey, optional): the id to pay (usually the same as offer\_node\_id)
  - **invoice\_recurrence\_basetime** (u64, optional): the UNIX timestamp to base the invoice periods on
  - **unknown\_invoice\_tlvs** (array of objects, optional): Any extra fields we didn't know how to parse:
    - **type** (u64): The type
    - **length** (u64): The length
    - **value** (hex): The value
  - the following warnings are possible:
    - **warning\_unknown\_offer\_currency**: The currency code is unknown (so no `currency_minor_unit`)

If **type** is "bolt12 invoice", and **valid** is *false*:

  - **fallbacks** (array of objects, optional):
    - the following warnings are possible:
      - **warning\_invoice\_fallbacks\_version\_invalid**: `version` is > 16
  - the following warnings are possible:
    - **warning\_invalid\_offer\_description**: `offer_description` is not valid UTF8
    - **warning\_missing\_offer\_description**: `offer_description` is not present
    - **warning\_invalid\_offer\_currency**: `offer_currency_code` is not valid UTF8
    - **warning\_invalid\_offer\_issuer**: `offer_issuer` is not valid UTF8
    - **warning\_missing\_invreq\_metadata**: `invreq_metadata` is not present
    - **warning\_invalid\_invreq\_payer\_note**: `invreq_payer_note` is not valid UTF8
    - **warning\_missing\_invoice\_paths**: `invoice_paths` is not present
    - **warning\_missing\_invoice\_blindedpay**: `invoice_blindedpay` is not present
    - **warning\_missing\_invoice\_created\_at**: `invoice_created_at` is not present
    - **warning\_missing\_invoice\_payment\_hash**: `invoice_payment_hash` is not present
    - **warning\_missing\_invoice\_amount**: `invoice_amount` is not present
    - **warning\_missing\_invoice\_recurrence\_basetime**: `invoice_recurrence_basetime` is not present
    - **warning\_missing\_invoice\_node\_id**: `invoice_node_id` is not present
    - **warning\_missing\_invoice\_signature**: `signature` is not present
    - **warning\_invalid\_invoice\_signature**: Incorrect `signature`

If **type** is "bolt11 invoice", and **valid** is *true*:

  - **currency** (string): the BIP173 name for the currency
  - **created\_at** (u64): the UNIX-style timestamp of the invoice
  - **expiry** (u64): the number of seconds this is valid after `created_at`
  - **payee** (pubkey): the public key of the recipient
  - **payment\_hash** (hex): the hash of the *payment\_preimage* (always 64 characters)
  - **signature** (signature): signature of the *payee* on this invoice
  - **min\_final\_cltv\_expiry** (u32): the minimum CLTV delay for the final node
  - **amount\_msat** (msat, optional): Amount the invoice asked for
  - **description** (string, optional): the description of the purpose of the purchase
  - **description\_hash** (hex, optional): the hash of the description, in place of *description* (always 64 characters)
  - **payment\_secret** (hex, optional): the secret to hand to the payee node (always 64 characters)
  - **features** (hex, optional): the features bitmap for this invoice
  - **payment\_metadata** (hex, optional): the payment\_metadata to put in the payment
  - **fallbacks** (array of objects, optional): onchain addresses:
    - **type** (string): the address type (if known) (one of "P2PKH", "P2SH", "P2WPKH", "P2WSH")
    - **hex** (hex): Raw encoded address
    - **addr** (string, optional): the address in appropriate format for *type*
  - **routes** (array of arrays, optional): Route hints to the *payee*:
    - hops in the route:
      - **pubkey** (pubkey): the public key of the node
      - **short\_channel\_id** (short\_channel\_id): a channel to the next peer
      - **fee\_base\_msat** (msat): the base fee for payments
      - **fee\_proportional\_millionths** (u32): the parts-per-million fee for payments
      - **cltv\_expiry\_delta** (u32): the CLTV delta across this hop
  - **extra** (array of objects, optional): Any extra fields we didn't know how to parse:
    - **tag** (string): The bech32 letter which identifies this field (always 1 characters)
    - **data** (string): The bech32 data for this field

If **type** is "rune", and **valid** is *true*:

  - **valid** (boolean) (always *true*)
  - **string** (string): the string encoding of the rune
  - **restrictions** (array of objects): restrictions built into the rune: all must pass:
    - **alternatives** (array of strings): each way restriction can be met: any can pass:
      - the alternative of form fieldname condition fieldname
    - **summary** (string): human-readable summary of this restriction
  - **unique\_id** (string, optional): unique id (always a numeric id on runes we create)
  - **version** (string, optional): rune version, not currently set on runes we create

If **type** is "rune", and **valid** is *false*:

  - **valid** (boolean) (always *false*)
  - **hex** (hex, optional): the raw rune in hex
  - the following warnings are possible:
    - **warning\_rune\_invalid\_utf8**: the rune contains invalid UTF-8 strings

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-offer(7), lightning-offerout(7), lightning-fetchinvoice(7), lightning-sendinvoice(7), lightning-commando-rune(7)

[BOLT #11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)

[BOLT #12](https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md) (experimental, [bolt](https://github.com/lightning/bolts) #798)


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:7920e365fe0f41fc2aa99c9e99af7c0666da229310ce50c2c2728c973069b2a7)
