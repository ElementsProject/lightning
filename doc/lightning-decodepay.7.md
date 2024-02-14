lightning-decodepay -- Command for decoding a bolt11 string (low-level)
=======================================================================

SYNOPSIS
--------

**decodepay** *bolt11* [*description*] 

DESCRIPTION
-----------

Command *added* in v23.05.

The **decodepay** RPC command checks and parses a *bolt11* string as specified by the BOLT 11 specification.

- **bolt11** (string): Bolt11 invoice to decode.
- **description** (string, optional): Description of the invoice to decode.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:decodepay#1",
  "method": "decodepay",
  "params": {
    "bolt11": "lnbcrt110u1pjmr5lzsp5sfjyj3xn7ux592k36hmmt4ax98n6lgct22wvj54yck0upcmep63qpp5qu436g855lr40ftdt7csatk5pdvtdzzfmfqluwtvm0fds95jsadqdpq0pzk7s6j8y69xjt6xe25j5j4g44hsatdxqyjw5qcqp99qxpqysgquwma3zrw4cd8e8j4u9uh4gxukaacckse64kx2l9dqv8rvrysdq5r5dt38t9snqj9u5ar07h2exr4fg56wpudkhkk7gtxlyt72ku5fpqqd4fnlk",
    "description": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **currency** (string): The BIP173 name for the currency.
- **created\_at** (u64): The UNIX-style timestamp of the invoice.
- **expiry** (u64): The number of seconds this is valid after *timestamp*.
- **payee** (pubkey): The public key of the recipient.
- **payment\_hash** (hash): The hash of the *payment\_preimage*.
- **signature** (signature): Signature of the *payee* on this invoice.
- **min\_final\_cltv\_expiry** (u32): The minimum CLTV delay for the final node.
- **amount\_msat** (msat, optional): Amount the invoice asked for.
- **description** (string, optional): The description of the purpose of the purchase.
- **description\_hash** (hash, optional): The hash of the description, in place of *description*.
- **payment\_secret** (hash, optional): The secret to hand to the payee node.
- **features** (hex, optional): The features bitmap for this invoice.
- **payment\_metadata** (hex, optional): The payment\_metadata to put in the payment.
- **fallbacks** (array of objects, optional): Onchain addresses.:
  - **type** (string) (one of "P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR"): The address type (if known).
  - **hex** (hex): Raw encoded address.
  - **addr** (string, optional): The address in appropriate format for *type*.
- **routes** (array of arrays, optional): Route hints to the *payee*.:
  - (array of objects): Hops in the route.
    - **pubkey** (pubkey): The public key of the node.
    - **short\_channel\_id** (short\_channel\_id): A channel to the next peer.
    - **fee\_base\_msat** (msat): The base fee for payments.
    - **fee\_proportional\_millionths** (u32): The parts-per-million fee for payments.
    - **cltv\_expiry\_delta** (u32): The CLTV delta across this hop.
- **extra** (array of objects, optional): Any extra fields we didn't know how to parse.:
  - **tag** (string) (always 1 characters): The bech32 letter which identifies this field.
  - **data** (string): The bech32 data for this field.

Technically, the *description* field is optional if a *description\_hash* field is given, but in this case **decodepay** will only succeed if the optional *description* field is passed and matches the *description\_hash*. In practice, these are currently unused.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "currency": "bcrt",
  "created_at": 1706152930,
  "expiry": 604800,
  "payee": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
  "amount_msat": 11000000,
  "description": [
    "XEoCR94SIz6UIRUEkxum."
  ],
  "min_final_cltv_expiry": 5,
  "payment_secret": "82644944d3f70d42aad1d5f7b5d7a629e7afa30b529cc952a4c59fc0e3790ea2",
  "features": "02024100",
  "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
  "signature": "3045022100e3b7d8886eae1a7c9e55e1797aa0dcb77b8c5a19d56c657cad030e360c90682802203a35713acb098245e53a37faeac98754a29a7078db5ed6f2166f917e55b94484"
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-getroute(7), lightning-sendpay(7)

RESOURCES
---------

[BOLT #11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)

Main web site: <https://github.com/ElementsProject/lightning>
