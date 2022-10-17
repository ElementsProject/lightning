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

- **type** (string): what kind of object it decoded to (one of "bolt12 offer", "bolt12 invoice", "bolt12 invoice_request", "bolt11 invoice", "rune")
- **valid** (boolean): if this is false, you *MUST* not use the result except for diagnostics!

If **type** is "bolt12 offer", and **valid** is *true*:

  - **offer\_id** (hex): the id of this offer (merkle hash of non-signature fields) (always 64 characters)
  - **node\_id** (pubkey): public key of the offering node
  - **description** (string): the description of the purpose of the offer
  - **signature** (bip340sig, optional): BIP-340 signature of the *node_id* on this offer
  - **chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only):
    - the genesis blockhash (always 64 characters)
  - **currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters)
  - **minor\_unit** (u32, optional): the number of decimal places to apply to amount (if currency known)
  - **amount** (u64, optional): the amount in the *currency* adjusted by *minor_unit*, if any
  - **amount\_msat** (msat, optional): the amount in bitcoin (if specified, and no *currency*)
  - **send\_invoice** (boolean, optional): present if this is a send_invoice offer (always *true*)
  - **refund\_for** (hex, optional): the *payment_preimage* of invoice this is a refund for (always 64 characters)
  - **vendor** (string, optional): the name of the vendor for this offer
  - **features** (hex, optional): the array of feature bits for this offer
  - **absolute\_expiry** (u64, optional): UNIX timestamp of when this offer expires
  - **paths** (array of objects, optional): Paths to the destination:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **blinded\_node\_id** (pubkey): node_id of the hop
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop
  - **quantity\_min** (u64, optional): the minimum quantity
  - **quantity\_max** (u64, optional): the maximum quantity
  - **recurrence** (object, optional): how often to this offer should be used:
    - **time\_unit** (u32): the BOLT12 time unit
    - **period** (u32): how many *time_unit* per payment period
    - **time\_unit\_name** (string, optional): the name of *time_unit* (if valid)
    - **basetime** (u64, optional): period starts at this UNIX timestamp
    - **start\_any\_period** (u64, optional): you can start at any period (only if **basetime** present)
    - **limit** (u32, optional): maximum period number for recurrence
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period):
      - **seconds\_before** (u32): seconds prior to period start
      - **seconds\_after** (u32): seconds after to period start
      - **proportional\_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*)
  - the following warnings are possible:
    - **warning\_offer\_unknown\_currency**: The currency code is unknown (so no **minor_unit**)

If **type** is "bolt12 offer", and **valid** is *false*:

  - the following warnings are possible:
    - **warning\_offer\_missing\_description**: No **description**

If **type** is "bolt12 invoice", and **valid** is *true*:

  - **node\_id** (pubkey): public key of the offering node
  - **signature** (bip340sig): BIP-340 signature of the *node_id* on this invoice
  - **amount\_msat** (msat): the amount in bitcoin
  - **description** (string): the description of the purpose of the offer
  - **created\_at** (u64): the UNIX timestamp of invoice creation
  - **payment\_hash** (hex): the hash of the *payment_preimage* (always 64 characters)
  - **relative\_expiry** (u32): the number of seconds after *created_at* when this expires
  - **min\_final\_cltv\_expiry** (u32): the number of blocks required by destination
  - **offer\_id** (hex, optional): the id of this offer (merkle hash of non-signature fields) (always 64 characters)
  - **chain** (hex, optional): which blockchain this invoice is for (missing implies bitcoin mainnet only) (always 64 characters)
  - **send\_invoice** (boolean, optional): present if this offer was a send_invoice offer (always *true*)
  - **refund\_for** (hex, optional): the *payment_preimage* of invoice this is a refund for (always 64 characters)
  - **vendor** (string, optional): the name of the vendor for this offer
  - **features** (hex, optional): the array of feature bits for this offer
  - **paths** (array of objects, optional): Paths to the destination:
    - **first\_node\_id** (pubkey): the (presumably well-known) public key of the start of the path
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **blinded\_node\_id** (pubkey): node_id of the hop
      - **encrypted\_recipient\_data** (hex): encrypted TLV entry for this hop
      - **fee\_base\_msat** (msat, optional): base fee for the entire path
      - **fee\_proportional\_millionths** (u32, optional): proportional fee for the entire path
      - **cltv\_expiry\_delta** (u32, optional): total CLTV delta across path
      - **features** (hex, optional): Features allowed/required for this path
  - **quantity** (u64, optional): the quantity ordered
  - **recurrence\_counter** (u32, optional): the 0-based counter for a recurring payment
  - **recurrence\_start** (u32, optional): the optional start period for a recurring payment
  - **recurrence\_basetime** (u32, optional): the UNIX timestamp of the first recurrence period start
  - **payer\_key** (pubkey, optional): the transient key which identifies the payer
  - **payer\_info** (hex, optional): the payer-provided blob to derive payer_key
  - **fallbacks** (array of objects, optional): onchain addresses:
    - **version** (u8): Segwit address version
    - **hex** (hex): Raw encoded segwit address
    - **address** (string, optional): bech32 segwit address
  - **refund\_signature** (bip340sig, optional): the payer key signature to get a refund

If **type** is "bolt12 invoice", and **valid** is *false*:

  - **fallbacks** (array of objects, optional):
    - the following warnings are possible:
      - **warning\_invoice\_fallbacks\_version\_invalid**: **version** is > 16
  - the following warnings are possible:
    - **warning\_invoice\_missing\_amount**: **amount_msat* missing
    - **warning\_invoice\_missing\_description**: No **description**
    - **warning\_invoice\_missing\_blinded\_payinfo**: Has **paths** without payinfo
    - **warning\_invoice\_invalid\_blinded\_payinfo**: Does not have exactly one payinfo for each of **paths**
    - **warning\_invoice\_missing\_recurrence\_basetime**: Has **recurrence_counter** without **recurrence_basetime**
    - **warning\_invoice\_missing\_created\_at**: Missing **created_at**
    - **warning\_invoice\_missing\_payment\_hash**: Missing **payment_hash**
    - **warning\_invoice\_refund\_signature\_missing\_payer\_key**: Missing **payer_key** for refund_signature
    - **warning\_invoice\_refund\_signature\_invalid**: **refund_signature** incorrect
    - **warning\_invoice\_refund\_missing\_signature**: No **refund_signature**

If **type** is "bolt12 invoice_request", and **valid** is *true*:

  - **offer\_id** (hex): the id of the offer this is requesting (merkle hash of non-signature fields) (always 64 characters)
  - **payer\_key** (pubkey): the transient key which identifies the payer
  - **chain** (hex, optional): which blockchain this invoice_request is for (missing implies bitcoin mainnet only) (always 64 characters)
  - **amount\_msat** (msat, optional): the amount in bitcoin
  - **features** (hex, optional): the array of feature bits for this offer
  - **quantity** (u64, optional): the quantity ordered
  - **recurrence\_counter** (u32, optional): the 0-based counter for a recurring payment
  - **recurrence\_start** (u32, optional): the optional start period for a recurring payment
  - **payer\_info** (hex, optional): the payer-provided blob to derive payer_key
  - **recurrence\_signature** (bip340sig, optional): the payer key signature

If **type** is "bolt12 invoice_request", and **valid** is *false*:

  - the following warnings are possible:
    - **warning\_invoice\_request\_missing\_offer\_id**: No **offer_id**
    - **warning\_invoice\_request\_missing\_payer\_key**: No **payer_key**
    - **warning\_invoice\_request\_missing\_recurrence\_signature**: No **recurrence_signature**
    - **warning\_invoice\_request\_invalid\_recurrence\_signature**: **recurrence_signature** incorrect

If **type** is "bolt11 invoice", and **valid** is *true*:

  - **currency** (string): the BIP173 name for the currency
  - **created\_at** (u64): the UNIX-style timestamp of the invoice
  - **expiry** (u64): the number of seconds this is valid after *timestamp*
  - **payee** (pubkey): the public key of the recipient
  - **payment\_hash** (hex): the hash of the *payment_preimage* (always 64 characters)
  - **signature** (signature): signature of the *payee* on this invoice
  - **min\_final\_cltv\_expiry** (u32): the minimum CLTV delay for the final node
  - **amount\_msat** (msat, optional): Amount the invoice asked for
  - **description** (string, optional): the description of the purpose of the purchase
  - **description\_hash** (hex, optional): the hash of the description, in place of *description* (always 64 characters)
  - **payment\_secret** (hex, optional): the secret to hand to the payee node (always 64 characters)
  - **features** (hex, optional): the features bitmap for this invoice
  - **payment\_metadata** (hex, optional): the payment_metadata to put in the payment
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

[BOLT #11](https://github.com/lightningnetwork/bolts/blob/master/11-payment-encoding.md).

[BOLT #12](https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md).


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:bbe57fd87e729e1203055d983a72757b9647ea67dca23c254a05b38b7b7020d9)
