lightning-decode -- Command for decoding an invoice string (low-level)
=======================================================================

SYNOPSIS
--------

**decode** *string*

DESCRIPTION
-----------

The **decode** RPC command checks and parses a *bolt11* or *bolt12*
string (optionally prefixed by `lightning:` or `LIGHTNING:`) as
specified by the BOLT 11 and BOLT 12 specifications.  It may decode
other formats in future.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **type** (string): what kind of object it decoded to (one of "bolt12 offer", "bolt12 invoice", "bolt12 invoice_request", "bolt11 invoice")
- **valid** (boolean): if this is false, you *MUST* not use the result except for diagnostics!

If **type** is "bolt12 offer", and **valid** is *true*:
  - **offer_id** (hex): the id of this offer (merkle hash of non-signature fields) (always 64 characters)
  - **node_id** (point32): x-only public key of the offering node
  - **description** (string): the description of the purpose of the offer
  - **signature** (bip340sig, optional): BIP-340 signature of the *node_id* on this offer
  - **chains** (array of hexs, optional): which blockchains this offer is for (missing implies bitcoin mainnet only):
    - the genesis blockhash (always 64 characters)
  - **currency** (string, optional): ISO 4217 code of the currency (missing implies Bitcoin) (always 3 characters)
  - **minor_unit** (u32, optional): the number of decimal places to apply to amount (if currency known)
  - **amount** (u64, optional): the amount in the *currency* adjusted by *minor_unit*, if any
  - **amount_msat** (msat, optional): the amount in bitcoin (if specified, and no *currency*)
  - **send_invoice** (boolean, optional): present if this is a send_invoice offer (always *true*)
  - **refund_for** (hex, optional): the *payment_preimage* of invoice this is a refund for (always 64 characters)
  - **vendor** (string, optional): the name of the vendor for this offer
  - **features** (hex, optional): the array of feature bits for this offer
  - **absolute_expiry** (u64, optional): UNIX timestamp of when this offer expires
  - **paths** (array of objects, optional): Paths to the destination:
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **node_id** (pubkey): node_id of the hop
      - **encrypted_recipient_data** (hex): encrypted TLV entry for this hop
  - **quantity_min** (u64, optional): the minimum quantity
  - **quantity_max** (u64, optional): the maximum quantity
  - **recurrence** (object, optional): how often to this offer should be used:
    - **time_unit** (u32): the BOLT12 time unit
    - **period** (u32): how many *time_unit* per payment period
    - **time_unit_name** (string, optional): the name of *time_unit* (if valid)
    - **basetime** (u64, optional): period starts at this UNIX timestamp
    - **start_any_period** (u64, optional): you can start at any period (only if **basetime** present)
    - **limit** (u32, optional): maximum period number for recurrence
    - **paywindow** (object, optional): when within a period will payment be accepted (default is prior and during the period):
      - **seconds_before** (u32): seconds prior to period start
      - **seconds_after** (u32): seconds after to period start
      - **proportional_amount** (boolean, optional): amount should be scaled if payed after period start (always *true*)
  - the following warnings are possible:
    - **warning_offer_unknown_currency**: The currency code is unknown (so no **minor_unit**)

If **type** is "bolt12 offer", and **valid** is *false*:
  - the following warnings are possible:
    - **warning_offer_missing_description**: No **description**

If **type** is "bolt12 invoice", and **valid** is *true*:
  - **node_id** (point32): x-only public key of the offering node
  - **signature** (bip340sig): BIP-340 signature of the *node_id* on this offer
  - **amount_msat** (msat): the amount in bitcoin
  - **description** (string): the description of the purpose of the offer
  - **created_at** (u64): the UNIX timestamp of invoice creation
  - **payment_hash** (hex): the hash of the *payment_preimage* (always 64 characters)
  - **relative_expiry** (u32): the number of seconds after *created_at* when this expires
  - **min_final_cltv_expiry** (u32): the number of blocks required by destination
  - **offer_id** (hex, optional): the id of this offer (merkle hash of non-signature fields) (always 64 characters)
  - **chain** (hex, optional): which blockchain this invoice is for (missing implies bitcoin mainnet only) (always 64 characters)
  - **send_invoice** (boolean, optional): present if this offer was a send_invoice offer (always *true*)
  - **refund_for** (hex, optional): the *payment_preimage* of invoice this is a refund for (always 64 characters)
  - **vendor** (string, optional): the name of the vendor for this offer
  - **features** (hex, optional): the array of feature bits for this offer
  - **paths** (array of objects, optional): Paths to the destination:
    - **blinding** (pubkey): blinding factor for this path
    - **path** (array of objects): an individual path:
      - **node_id** (pubkey): node_id of the hop
      - **encrypted_recipient_data** (hex): encrypted TLV entry for this hop
  - **quantity** (u64, optional): the quantity ordered
  - **recurrence_counter** (u32, optional): the 0-based counter for a recurring payment
  - **recurrence_start** (u32, optional): the optional start period for a recurring payment
  - **recurrence_basetime** (u32, optional): the UNIX timestamp of the first recurrence period start
  - **payer_key** (point32, optional): the transient key which identifies the payer
  - **payer_info** (hex, optional): the payer-provided blob to derive payer_key
  - **fallbacks** (array of objects, optional): onchain addresses:
    - **version** (u8): Segwit address version
    - **hex** (hex): Raw encoded segwit address
    - **address** (string, optional): bech32 segwit address
  - **refund_signature** (bip340sig, optional): the payer key signature to get a refund

If **type** is "bolt12 invoice", and **valid** is *false*:
  - **fallbacks** (array of objects, optional):
    - the following warnings are possible:
      - **warning_invoice_fallbacks_version_invalid**: **version** is > 16
  - the following warnings are possible:
    - **warning_invoice_missing_amount**: **amount_msat* missing
    - **warning_invoice_missing_description**: No **description**
    - **warning_invoice_missing_blinded_payinfo**: Has **paths** without payinfo
    - **warning_invoice_invalid_blinded_payinfo**: Does not have exactly one payinfo for each of **paths**
    - **warning_invoice_missing_recurrence_basetime**: Has **recurrence_counter** without **recurrence_basetime**
    - **warning_invoice_missing_created_at**: Missing **created_at**
    - **warning_invoice_missing_payment_hash**: Missing **payment_hash**
    - **warning_invoice_refund_signature_missing_payer_key**: Missing **payer_key** for refund_signature
    - **warning_invoice_refund_signature_invalid**: **refund_signature** incorrect
    - **warning_invoice_refund_missing_signature**: No **refund_signature**

If **type** is "bolt12 invoice_request", and **valid** is *true*:
  - **offer_id** (hex): the id of the offer this is requesting (merkle hash of non-signature fields) (always 64 characters)
  - **payer_key** (point32): the transient key which identifies the payer
  - **chain** (hex, optional): which blockchain this invoice_request is for (missing implies bitcoin mainnet only) (always 64 characters)
  - **amount_msat** (msat, optional): the amount in bitcoin
  - **features** (hex, optional): the array of feature bits for this offer
  - **quantity** (u64, optional): the quantity ordered
  - **recurrence_counter** (u32, optional): the 0-based counter for a recurring payment
  - **recurrence_start** (u32, optional): the optional start period for a recurring payment
  - **payer_info** (hex, optional): the payer-provided blob to derive payer_key
  - **recurrence_signature** (bip340sig, optional): the payer key signature

If **type** is "bolt12 invoice_request", and **valid** is *false*:
  - the following warnings are possible:
    - **warning_invoice_request_missing_offer_id**: No **offer_id**
    - **warning_invoice_request_missing_payer_key**: No **payer_key**
    - **warning_invoice_request_missing_recurrence_signature**: No **recurrence_signature**
    - **warning_invoice_request_invalid_recurrence_signature**: **recurrence_signature** incorrect

If **type** is "bolt11 invoice", and **valid** is *true*:
  - **currency** (string): the BIP173 name for the currency
  - **created_at** (u64): the UNIX-style timestamp of the invoice
  - **expiry** (u64): the number of seconds this is valid after *timestamp*
  - **payee** (pubkey): the public key of the recipient
  - **payment_hash** (hex): the hash of the *payment_preimage* (always 64 characters)
  - **signature** (signature): signature of the *payee* on this invoice
  - **min_final_cltv_expiry** (u32): the minimum CLTV delay for the final node
  - **amount_msat** (msat, optional): Amount the invoice asked for
  - **description** (string, optional): the description of the purpose of the purchase
  - **description_hash** (hex, optional): the hash of the description, in place of *description* (always 64 characters)
  - **payment_secret** (hex, optional): the secret to hand to the payee node (always 64 characters)
  - **features** (hex, optional): the features bitmap for this invoice
  - **fallbacks** (array of objects, optional): onchain addresses:
    - **type** (string): the address type (if known) (one of "P2PKH", "P2SH", "P2WPKH", "P2WSH")
    - **hex** (hex): Raw encoded address
    - **addr** (string, optional): the address in appropriate format for *type*
  - **routes** (array of arrays, optional): Route hints to the *payee*:
    - hops in the route:
      - **pubkey** (pubkey): the public key of the node
      - **short_channel_id** (short_channel_id): a channel to the next peer
      - **fee_base_msat** (u32): the base fee for payments
      - **fee_proportional_millionths** (u32): the parts-per-million fee for payments
      - **cltv_expiry_delta** (u32): the CLTV delta across this hop
  - **extra** (array of objects, optional): Any extra fields we didn't know how to parse:
    - **tag** (string): The bech32 letter which identifies this field (always 1 characters)
    - **data** (string): The bech32 data for this field

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-offer(7), lightning-offerout(7), lightning-fetchinvoice(7), lightning-sendinvoice(7)

[BOLT \#11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md).

[BOLT \#12](https://github.com/lightningnetwork/lightning-rfc/blob/master/12-offer-encoding.md).


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:d05b5fc1bf230b3bbd03e2023fb0c6bbefb700f7c3cfb43512da48dbce45f005)
