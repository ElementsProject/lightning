lightning-decodepay -- Command for decoding a bolt11 string (low-level)
=======================================================================

SYNOPSIS
--------

**decodepay** *bolt11* [*description*]

DESCRIPTION
-----------

The **decodepay** RPC command checks and parses a *bolt11* string as
specified by the BOLT 11 specification.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **currency** (string): the BIP173 name for the currency
- **created\_at** (u64): the UNIX-style timestamp of the invoice
- **expiry** (u64): the number of seconds this is valid after *timestamp*
- **payee** (pubkey): the public key of the recipient
- **payment\_hash** (hash): the hash of the *payment\_preimage*
- **signature** (signature): signature of the *payee* on this invoice
- **min\_final\_cltv\_expiry** (u32): the minimum CLTV delay for the final node
- **amount\_msat** (msat, optional): Amount the invoice asked for
- **description** (string, optional): the description of the purpose of the purchase
- **description\_hash** (hash, optional): the hash of the description, in place of *description*
- **payment\_secret** (hash, optional): the secret to hand to the payee node
- **features** (hex, optional): the features bitmap for this invoice
- **payment\_metadata** (hex, optional): the payment\_metadata to put in the payment
- **fallbacks** (array of objects, optional): onchain addresses:
  - **type** (string): the address type (if known) (one of "P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR")
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

[comment]: # (GENERATE-FROM-SCHEMA-END)

Technically, the *description* field is optional if a
*description\_hash* field is given, but in this case **decodepay** will
only succeed if the optional *description* field is passed and matches
the *description\_hash*. In practice, these are currently unused.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-getroute(7), lightning-sendpay(7).

[BOLT
\#11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:14c7dd565178078d7073e2837ad283a1e811affb5017e72c69e69d9f8c2baabd)
