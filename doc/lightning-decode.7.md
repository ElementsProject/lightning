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

- **type** (string): what kind of object it decoded to (one of "bolt12 offer", "bolt12 invoice", "bolt12 invoice\_request", "bolt11 invoice", "rune") *(added v23.05)*
- **valid** (boolean): if this is false, you *MUST* not use the result except for diagnostics! *(added v23.05)*

If **type** is "bolt12 offer", and **valid** is *true*:

  - **offer\_id** (hex): the id we use to identify this offer (always 64 characters) *(added v23.05)*
  - **offer\_description** (string): the description of the purpose of the offer *(added v23.05)*
  - **offer\_node\_id** (pubkey): public key of the offering node *(added v23.05)*
  - **offer\_chains** (array of hashs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only) *(added v23.05)*:
    - the genesis blockhash
  - **offer\_metadata** (hex, optional): any metadata the creater of the offer includes *(added v23.05)*
  - **offer\_currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters) *(added v23.05)*
  - **currency\_minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known) *(added v23.05)*
  - **offer\_amount** (u64, optional): the amount in the `offer_currency` adjusted by `currency_minor_unit`, if any *(added v23.05)*
  - **offer\_amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no `offer_currency`) *(added v23.05)*
  - **offer\_issuer** (string, optional): the description of the creator of the offer *(added v23.05)*
  - **offer\_features** (hex, optional): the feature bits of the offer *(added v23.05)*
  - **offer\_absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires *(added v23.05)*
  - **offer\_quantity\_max** (u64, optional): the maximum quantity (or, if 0, means any quantity) *(added v23.05)*
  - **offer\_paths** (array of objects, optional): Paths to the destination *(added v23.05)*:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path *(added v23.05)*
    - **blinding** (pubkey): blinding factor for this path *(added v23.05)*
    - **path** (array of objects): an individual path *(added v23.05)*:
      - **blinded\_node\_id** (pubkey): node\_id of the hop *(added v23.05)*
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop *(added v23.05)*
  - **offer\_recurrence** (object, optional): how often to this offer should be used *(added v23.05)*:
    - **time\_unit** (u32): the BOLT12 time unit *(added v23.05)*
    - **period** (u32): how many `time_unit` per payment period *(added v23.05)*
    - **time\_unit\_name** (string, optional): the name of `time_unit` (if valid) *(added v23.05)*
    - **basetime** (u64, optional): period starts at this UNIX timestamp *(added v23.05)*
    - **start\_any\_period** (u64, optional): you can start at any period (only if `basetime` present) *(added v23.05)*
    - **limit** (u32, optional): maximum period number for recurrence *(added v23.05)*
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period) *(added v23.05)*:
      - **seconds\_before** (u32): seconds prior to period start *(added v23.05)*
      - **seconds\_after** (u32): seconds after to period start *(added v23.05)*
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*) *(added v23.05)*
  - **unknown\_offer\_tlvs** (array of objects, optional): Any extra fields we didn't know how to parse *(added v23.05)*:
    - **type** (u64): The type *(added v23.05)*
    - **length** (u64): The length *(added v23.05)*
    - **value** (hex): The value *(added v23.05)*
  - the following warnings are possible:
    - **warning\_unknown\_offer\_currency**: The currency code is unknown (so no `currency_minor_unit`) *(added v23.05)*

If **type** is "bolt12 offer", and **valid** is *false*:

  - the following warnings are possible:
    - **warning\_missing\_offer\_node\_id**: `offer_node_id` is not present *(added v23.05)*
    - **warning\_invalid\_offer\_description**: `offer_description` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_offer\_description**: `offer_description` is not present *(added v23.05)*
    - **warning\_invalid\_offer\_currency**: `offer_currency_code` is not valid UTF8 *(added v23.05)*
    - **warning\_invalid\_offer\_issuer**: `offer_issuer` is not valid UTF8 *(added v23.05)*

If **type** is "bolt12 invoice\_request", and **valid** is *true*:

  - **offer\_description** (string): the description of the purpose of the offer *(added v23.05)*
  - **offer\_node\_id** (pubkey): public key of the offering node *(added v23.05)*
  - **invreq\_metadata** (hex): the payer-provided blob to derive invreq\_payer\_id *(added v23.05)*
  - **invreq\_payer\_id** (hex): the payer-provided key *(added v23.05)*
  - **signature** (bip340sig): BIP-340 signature of the `invreq_payer_id` on this invoice\_request *(added v23.05)*
  - **offer\_id** (hex, optional): the id we use to identify this offer (always 64 characters) *(added v23.05)*
  - **offer\_chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only) *(added v23.05)*:
    - the genesis blockhash (always 64 characters)
  - **offer\_metadata** (hex, optional): any metadata the creator of the offer includes *(added v23.05)*
  - **offer\_currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters) *(added v23.05)*
  - **currency\_minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known) *(added v23.05)*
  - **offer\_amount** (u64, optional): the amount in the `offer_currency` adjusted by `currency_minor_unit`, if any *(added v23.05)*
  - **offer\_amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no `offer_currency`) *(added v23.05)*
  - **offer\_issuer** (string, optional): the description of the creator of the offer *(added v23.05)*
  - **offer\_features** (hex, optional): the feature bits of the offer *(added v23.05)*
  - **offer\_absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires *(added v23.05)*
  - **offer\_quantity\_max** (u64, optional): the maximum quantity (or, if 0, means any quantity) *(added v23.05)*
  - **offer\_paths** (array of objects, optional): Paths to the destination *(added v23.05)*:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path *(added v23.05)*
    - **blinding** (pubkey): blinding factor for this path *(added v23.05)*
    - **path** (array of objects): an individual path *(added v23.05)*:
      - **blinded\_node\_id** (pubkey): node\_id of the hop *(added v23.05)*
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop *(added v23.05)*
  - **offer\_recurrence** (object, optional): how often to this offer should be used *(added v23.05)*:
    - **time\_unit** (u32): the BOLT12 time unit *(added v23.05)*
    - **period** (u32): how many `time_unit` per payment period *(added v23.05)*
    - **time\_unit\_name** (string, optional): the name of `time_unit` (if valid) *(added v23.05)*
    - **basetime** (u64, optional): period starts at this UNIX timestamp *(added v23.05)*
    - **start\_any\_period** (u64, optional): you can start at any period (only if `basetime` present) *(added v23.05)*
    - **limit** (u32, optional): maximum period number for recurrence *(added v23.05)*
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period) *(added v23.05)*:
      - **seconds\_before** (u32): seconds prior to period start *(added v23.05)*
      - **seconds\_after** (u32): seconds after to period start *(added v23.05)*
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*) *(added v23.05)*
  - **invreq\_chain** (hex, optional): which blockchain this offer is for (missing implies bitcoin mainnet only) (always 64 characters) *(added v23.05)*
  - **invreq\_amount\_msat** (msat, optional): the amount the invoice should be for *(added v23.05)*
  - **invreq\_features** (hex, optional): the feature bits of the invoice\_request *(added v23.05)*
  - **invreq\_quantity** (u64, optional): the number of items to invoice for *(added v23.05)*
  - **invreq\_payer\_note** (string, optional): a note attached by the payer *(added v23.05)*
  - **invreq\_recurrence\_counter** (u32, optional): which number request this is for the same invoice *(added v23.05)*
  - **invreq\_recurrence\_start** (u32, optional): when we're requesting to start an invoice at a non-zero period *(added v23.05)*
  - **unknown\_invoice\_request\_tlvs** (array of objects, optional): Any extra fields we didn't know how to parse *(added v23.05)*:
    - **type** (u64): The type *(added v23.05)*
    - **length** (u64): The length *(added v23.05)*
    - **value** (hex): The value *(added v23.05)*
  - the following warnings are possible:
    - **warning\_unknown\_offer\_currency**: The currency code is unknown (so no `currency_minor_unit`) *(added v23.05)*

If **type** is "bolt12 invoice\_request", and **valid** is *false*:

  - the following warnings are possible:
    - **warning\_invalid\_offer\_description**: `offer_description` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_offer\_description**: `offer_description` is not present *(added v23.05)*
    - **warning\_invalid\_offer\_currency**: `offer_currency_code` is not valid UTF8 *(added v23.05)*
    - **warning\_invalid\_offer\_issuer**: `offer_issuer` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_invreq\_metadata**: `invreq_metadata` is not present *(added v23.05)*
    - **warning\_missing\_invreq\_payer\_id**: `invreq_payer_id` is not present *(added v23.05)*
    - **warning\_invalid\_invreq\_payer\_note**: `invreq_payer_note` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_invoice\_request\_signature**: `signature` is not present *(added v23.05)*
    - **warning\_invalid\_invoice\_request\_signature**: Incorrect `signature` *(added v23.05)*

If **type** is "bolt12 invoice", and **valid** is *true*:

  - **offer\_description** (string): the description of the purpose of the offer *(added v23.05)*
  - **offer\_node\_id** (pubkey): public key of the offering node *(added v23.05)*
  - **invreq\_metadata** (hex): the payer-provided blob to derive invreq\_payer\_id *(added v23.05)*
  - **invreq\_payer\_id** (hex): the payer-provided key *(added v23.05)*
  - **invoice\_paths** (array of objects): Paths to pay the destination *(added v23.05)*:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path *(added v23.05)*
    - **blinding** (pubkey): blinding factor for this path *(added v23.05)*
    - **payinfo** (object) *(added v23.05)*:
      - **fee\_base\_msat** (msat): basefee for path *(added v23.05)*
      - **fee\_proportional\_millionths** (u32): proportional fee for path *(added v23.05)*
      - **cltv\_expiry\_delta** (u32): CLTV delta for path *(added v23.05)*
      - **features** (hex): features allowed for path *(added v23.05)*
    - **path** (array of objects): an individual path *(added v23.05)*:
      - **blinded\_node\_id** (pubkey): node\_id of the hop *(added v23.05)*
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop *(added v23.05)*
  - **invoice\_created\_at** (u64): the UNIX timestamp of invoice creation *(added v23.05)*
  - **invoice\_payment\_hash** (hex): the hash of the *payment\_preimage* (always 64 characters) *(added v23.05)*
  - **invoice\_amount\_msat** (msat): the amount required to fulfill invoice *(added v23.05)*
  - **signature** (bip340sig): BIP-340 signature of the `offer_node_id` on this invoice *(added v23.05)*
  - **offer\_id** (hex, optional): the id we use to identify this offer (always 64 characters) *(added v23.05)*
  - **offer\_chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only) *(added v23.05)*:
    - the genesis blockhash (always 64 characters)
  - **offer\_metadata** (hex, optional): any metadata the creator of the offer includes *(added v23.05)*
  - **offer\_currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters) *(added v23.05)*
  - **currency\_minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known) *(added v23.05)*
  - **offer\_amount** (u64, optional): the amount in the `offer_currency` adjusted by `currency_minor_unit`, if any *(added v23.05)*
  - **offer\_amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no `offer_currency`) *(added v23.05)*
  - **offer\_issuer** (string, optional): the description of the creator of the offer *(added v23.05)*
  - **offer\_features** (hex, optional): the feature bits of the offer *(added v23.05)*
  - **offer\_absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires *(added v23.05)*
  - **offer\_quantity\_max** (u64, optional): the maximum quantity (or, if 0, means any quantity) *(added v23.05)*
  - **offer\_paths** (array of objects, optional): Paths to the destination *(added v23.05)*:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path *(added v23.05)*
    - **blinding** (pubkey): blinding factor for this path *(added v23.05)*
    - **path** (array of objects): an individual path *(added v23.05)*:
      - **blinded\_node\_id** (pubkey): node\_id of the hop *(added v23.05)*
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop *(added v23.05)*
  - **offer\_recurrence** (object, optional): how often to this offer should be used *(added v23.05)*:
    - **time\_unit** (u32): the BOLT12 time unit *(added v23.05)*
    - **period** (u32): how many `time_unit` per payment period *(added v23.05)*
    - **time\_unit\_name** (string, optional): the name of `time_unit` (if valid) *(added v23.05)*
    - **basetime** (u64, optional): period starts at this UNIX timestamp *(added v23.05)*
    - **start\_any\_period** (u64, optional): you can start at any period (only if `basetime` present) *(added v23.05)*
    - **limit** (u32, optional): maximum period number for recurrence *(added v23.05)*
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period) *(added v23.05)*:
      - **seconds\_before** (u32): seconds prior to period start *(added v23.05)*
      - **seconds\_after** (u32): seconds after to period start *(added v23.05)*
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*) *(added v23.05)*
  - **invreq\_chain** (hex, optional): which blockchain this offer is for (missing implies bitcoin mainnet only) (always 64 characters) *(added v23.05)*
  - **invreq\_amount\_msat** (msat, optional): the amount the invoice should be for *(added v23.05)*
  - **invreq\_features** (hex, optional): the feature bits of the invoice\_request *(added v23.05)*
  - **invreq\_quantity** (u64, optional): the number of items to invoice for *(added v23.05)*
  - **invreq\_payer\_note** (string, optional): a note attached by the payer *(added v23.05)*
  - **invreq\_recurrence\_counter** (u32, optional): which number request this is for the same invoice *(added v23.05)*
  - **invreq\_recurrence\_start** (u32, optional): when we're requesting to start an invoice at a non-zero period *(added v23.05)*
  - **invoice\_relative\_expiry** (u32, optional): the number of seconds after *invoice\_created\_at* when this expires *(added v23.05)*
  - **invoice\_fallbacks** (array of objects, optional): onchain addresses *(added v23.05)*:
    - **version** (u8): Segwit address version *(added v23.05)*
    - **hex** (hex): Raw encoded segwit address *(added v23.05)*
    - **address** (string, optional): bech32 segwit address *(added v23.05)*
  - **invoice\_features** (hex, optional): the feature bits of the invoice *(added v23.05)*
  - **invoice\_node\_id** (pubkey, optional): the id to pay (usually the same as offer\_node\_id) *(added v23.05)*
  - **invoice\_recurrence\_basetime** (u64, optional): the UNIX timestamp to base the invoice periods on *(added v23.05)*
  - **unknown\_invoice\_tlvs** (array of objects, optional): Any extra fields we didn't know how to parse *(added v23.05)*:
    - **type** (u64): The type *(added v23.05)*
    - **length** (u64): The length *(added v23.05)*
    - **value** (hex): The value *(added v23.05)*
  - the following warnings are possible:
    - **warning\_unknown\_offer\_currency**: The currency code is unknown (so no `currency_minor_unit`) *(added v23.05)*

If **type** is "bolt11 invoice", and **valid** is *true*:

  - **currency** (string): the BIP173 name for the currency *(added v23.05)*
  - **created\_at** (u64): the UNIX-style timestamp of the invoice *(added v23.05)*
  - **expiry** (u64): the number of seconds this is valid after `created_at` *(added v23.05)*
  - **payee** (pubkey): the public key of the recipient *(added v23.05)*
  - **payment\_hash** (hash): the hash of the *payment\_preimage* *(added v23.05)*
  - **signature** (signature): signature of the *payee* on this invoice *(added v23.05)*
  - **min\_final\_cltv\_expiry** (u32): the minimum CLTV delay for the final node *(added v23.05)*
  - **amount\_msat** (msat, optional): Amount the invoice asked for *(added v23.05)*
  - **description** (string, optional): the description of the purpose of the purchase *(added v23.05)*
  - **description\_hash** (hash, optional): the hash of the description, in place of *description* *(added v23.05)*
  - **payment\_secret** (secret, optional): the secret to hand to the payee node *(added v23.05)*
  - **features** (hex, optional): the features bitmap for this invoice *(added v23.05)*
  - **payment\_metadata** (hex, optional): the payment\_metadata to put in the payment *(added v23.05)*
  - **fallbacks** (array of objects, optional): onchain addresses *(added v23.05)*:
    - **type** (string): the address type (if known) (one of "P2PKH", "P2SH", "P2WPKH", "P2WSH") *(added v23.05)*
    - **hex** (hex): Raw encoded address *(added v23.05)*
    - **addr** (string, optional): the address in appropriate format for *type* *(added v23.05)*
    - the following warnings are possible:
      - **warning\_invoice\_fallbacks\_version\_invalid**: `version` is > 16 *(added v23.05)*
  - **routes** (array of arrays, optional): Route hints to the *payee* *(added v23.05)*:
    - hops in the route:
      - **pubkey** (pubkey): the public key of the node *(added v23.05)*
      - **short\_channel\_id** (short\_channel\_id): a channel to the next peer *(added v23.05)*
      - **fee\_base\_msat** (msat): the base fee for payments *(added v23.05)*
      - **fee\_proportional\_millionths** (u32): the parts-per-million fee for payments *(added v23.05)*
      - **cltv\_expiry\_delta** (u32): the CLTV delta across this hop *(added v23.05)*
  - **extra** (array of objects, optional): Any extra fields we didn't know how to parse *(added v23.05)*:
    - **tag** (string): The bech32 letter which identifies this field (always 1 characters) *(added v23.05)*
    - **data** (string): The bech32 data for this field *(added v23.05)*

If **type** is "rune", and **valid** is *true*:

  - **valid** (boolean) (always *true*) *(added v23.05)*
  - **string** (string): the string encoding of the rune *(added v23.05)*
  - **restrictions** (array of objects): restrictions built into the rune: all must pass *(added v23.05)*:
    - **alternatives** (array of strings): each way restriction can be met: any can pass *(added v23.05)*:
      - the alternative of form fieldname condition fieldname
    - **summary** (string): human-readable summary of this restriction *(added v23.05)*
  - **unique\_id** (string, optional): unique id (always a numeric id on runes we create) *(added v23.05)*
  - **version** (string, optional): rune version, not currently set on runes we create *(added v23.05)*

If **type** is "rune", and **valid** is *false*:

  - **valid** (boolean) (always *false*) *(added v23.05)*
  - **hex** (hex, optional): the raw rune in hex *(added v23.05)*
  - the following warnings are possible:
    - **warning\_rune\_invalid\_utf8**: the rune contains invalid UTF-8 strings *(added v23.05)*

If **type** is "bolt12 invoice", and **valid** is *false*:

  - **fallbacks** (array of objects, optional) *(added v23.05)*:
  - the following warnings are possible:
    - **warning\_invalid\_offer\_description**: `offer_description` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_offer\_description**: `offer_description` is not present *(added v23.05)*
    - **warning\_invalid\_offer\_currency**: `offer_currency_code` is not valid UTF8 *(added v23.05)*
    - **warning\_invalid\_offer\_issuer**: `offer_issuer` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_invreq\_metadata**: `invreq_metadata` is not present *(added v23.05)*
    - **warning\_invalid\_invreq\_payer\_note**: `invreq_payer_note` is not valid UTF8 *(added v23.05)*
    - **warning\_missing\_invoice\_paths**: `invoice_paths` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_blindedpay**: `invoice_blindedpay` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_created\_at**: `invoice_created_at` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_payment\_hash**: `invoice_payment_hash` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_amount**: `invoice_amount` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_recurrence\_basetime**: `invoice_recurrence_basetime` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_node\_id**: `invoice_node_id` is not present *(added v23.05)*
    - **warning\_missing\_invoice\_signature**: `signature` is not present *(added v23.05)*
    - **warning\_invalid\_invoice\_signature**: Incorrect `signature` *(added v23.05)*

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-offer(7), lightning-fetchinvoice(7), lightning-sendinvoice(7), lightning-commando-rune(7)

[BOLT #11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)

[BOLT #12](https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md) (experimental, [bolt](https://github.com/lightning/bolts) #798)


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:39da43957723db6caebbe20abffec1a5d970516370de67eceac1d1ab7092d169)
