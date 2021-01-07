lightning-decode -- Command for decoding an invoice string (low-level)
=======================================================================

SYNOPSIS
--------

*EXPERIMENTAL_FEATURES only*

**decode** *string*

DESCRIPTION
-----------

The **decode** RPC command checks and parses a *bolt11* or *bolt12*
string (optionally prefixed by `lightning:` or `LIGHTNING:`) as
specified by the BOLT 11 and BOLT 12 specifications.  It may decode
other formats in future.

RETURN VALUE
------------

On success, an object is returned with a *type* member indicating the
type of the decoding:

*type*: "bolt12 offer"
    - *offer_id*: the id of this offer (merkle hash of non-signature fields)
    - *chains* (optional): if set, an array of genesis hashes of supported chains.  (Unset implies bitcoin mainnet).
	- *currency* (optional): ISO 4217 code of the currency.
	- *minor_unit* (optional): the number of decimal places to apply to amount (if currency known)
	- *amount* (optional): the amount in the *currency* adjusted by *minor_unit*, if any.
	- *amount_msat* (optional): the amount (with "msat" appended) if there is no *currency*.
	- *send_invoice* (optional): `true` if this is  a send_invoice offer.
	- *refund_for* (optional): the sha256 payment_preimage of invoice this is a refund for.
    - *description* (optional): the UTF-8 description of the purpose of the offer.
    - *vendor* (optional): the UTF-8 name of the vendor for this offer.
	- *features* (optional): hex array of feature bits.
	- *absolute_expiry* (optional): UNIX timestamp of when this offer expires.
	- *paths* (optional): Array of objects containing *blinding*, *path* array; each *path* entry contains an object with *node_id* and *enctlv*.
	- *quantity_min* (optional): minimum valid quantity for offer responses
	- *quantity_max* (optional): maximum valid quantity for offer responses
	- *recurrence* (optional): an object containing *time_unit*, *time_unit_name* (optional, a string), *period*, *basetime* (optional), *start_any_period* (optional), *limit* (optional), and *paywindow* (optional) object containing *seconds_before*, *seconds_after* and *proportional_amount* (optional).
	- *node_id*: 32-byte (x-only) public key of the offering node.
	- *signature*: BIP-340 signature of the *node_id* on this offer.

*type*: "bolt12 invoice"
    - *chains* (optional): if set, an array of genesis hashes of supported chains.  (Unset implies bitcoin mainnet).
    - *offer_id* (optional): id of the offer this invoice is for.
	- *amount_msat* (optional): the amount (with "msat" appended).
    - *description* (optional): the UTF-8 description of the purpose of the offer.
    - *vendor* (optional): the UTF-8 name of the vendor for this offer.
	- *features* (optional): hex array of feature bits.
	- *paths* (optional): Array of objects containing *blinding*, *path* array; each *path* entry contains an object with *node_id*, *enctlv*, *fee_base_msat* (optional), *fee_proportional_millionths* (optional), *cltv_expiry_delta* (optional), and *features* (optional).
	- *quantity* (optional): quantity of items.
	- *send_invoice* (optional): `true` if this is a response to a send_invoice offer.
	- *refund_for* (optional): the sha256 payment_preimage of invoice this is a refund for.	
	- *recurrence_counter* (optional): the zero-based number of the invoice for a recurring offer.
	- *recurrence_start* (optional): the zero-based offet of the first invoice for the recurring offer.
	- *recurrence_basetime* (optional): the UNIX timestamp of the first period of the offer.
	- *payer_key* (optional): the 32-byte (x-only) id of the payer.
	- *payer_info* (optional): a variable-length blob for the payer to derive their key.
	- *timestamp* (optional): the UNIX timestamp of the invoice.
	- *payment_hash* (optional): the hex SHA256 of the payment_preimage.
	- *expiry* (optional): seconds from *timestamp* when invoice expires.
	- *min_final_cltv_expiry*: required CLTV for final hop.
	- *fallbacks* (optional): an array containing objects with *version*, and *hex* fields for each fallback address, and *address* (optional) if it's parsable.
	- *refund_signature* (optional): BIP-340 signature of the *payer_key* on this offer.
	- *node_id*: 32-byte (x-only) public key of the invoicing node.
	- *signature*: BIP-340 signature of the *node_id* on this invoice.

*type*: "bolt12 invoice_request"
    - *chains* (optional): if set, an array of genesis hashes of supported chains.  (Unset implies bitcoin mainnet).
    - *offer_id* (optional): id of the offer this invoice is for.
	- *amount_msat* (optional): the amount (with "msat" appended).
	- *features* (optional): hex array of feature bits.
	- *quantity* (optional): quantity of items.
	- *recurrence_counter* (optional): the zero-based number of the invoice for a recurring offer.
	- *recurrence_start* (optional): the zero-based offet of the first invoice for the recurring offer.
	- *payer_key* (optional): the 32-byte (x-only) id of the payer.
	- *payer_info* (optional): a variable-length blob for the payer to derive their key.
	- *recurrence_signature* (optional): BIP-340 signature of the *payer_key* on this offer.

*type*: "bolt11 invoice"
    -   *currency*: the BIP173 name for the currency.
    -   *timestamp*: the UNIX-style timestamp of the invoice.
    -   *expiry*: the number of seconds this is valid after *timestamp*.
    -   *payee*: the public key of the recipient.
    -   *payment_hash*: the payment hash of the request.
    -   *signature*: the DER-encoded signature.
    -   *description*: the UTF-8 description of the purpose of the purchase.
    -   *msatoshi* (optional): the number of millisatoshi requested (if any).
    -   *amount_msat* (optional): the same as above, with *msat* appended (if any).
    -   *fallbacks* (optional): array of fallback address object containing a *hex* string, and both *type* and *addr* if it is recognized as one of *P2PKH*, *P2SH*, *P2WPKH*, or *P2WSH*.
    -   *routes* (optional): an array of routes. Each route is an arrays of objects, each containing *pubkey*, *short_channel_id*, *fee_base_msat*, *fee_proportional_millionths* and *cltv_expiry_delta*.
    - *extra* (optional): an array of objects representing unknown fields, each with one-character *tag* and a *data* bech32 string.

Some invalid strings can still be parsed, and warnings will be given:
    - "warning_offer_unknown_currency": unknown or invalid *currency* code.
    - "warning_offer_missing_description": invalid due to missing description.
    - "warning_invoice_invalid_blinded_payinfo": blinded_payinfo does not match paths.
    - "warning_invoice_fallbacks_version_invalid": a fallback version is not a valid segwit version
    - "warning_invoice_fallbacks_address_invalid": a fallback address is not a valid segwit address (within an object in the *fallback* array)
    - "warning_invoice_missing_amount": amount field is missing.
    - "warning_invoice_missing_description": description field is missing.
    - "warning_invoice_missing_blinded_payinfo": blindedpay is missing.
    - "warning_invoice_missing_recurrence_basetime: recurrence_basetime is missing.
    - "warning_invoice_missing_timestamp": timestamp is missing.
    - "warning_invoice_missing_payment_hash": payment hash is missing.
    - "warning_invoice_refund_signature_missing_payer_key": payer_key is missing for refund_signature.
    - "warning_invoice_refund_signature_invalid": refund_signature does not match.
    - "warning_invoice_refund_missing_signature": refund_signature is missing.
    - "warning_invoice_request_missing_offer_id": offer_id is missing.
    - "warning_invoice_request_missing_payer_key": payer_key is missing.
    - "warning_invoice_request_invalid_recurrence_signature": recurrence_signature does not match.
    - "warning_invoice_request_missing_recurrence_signature": recurrence_signature is missing.

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

