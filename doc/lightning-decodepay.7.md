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

- **currency** (string): the BIP173 name for the currency *(added v23.05)*
- **created\_at** (u64): the UNIX-style timestamp of the invoice *(added v23.05)*
- **expiry** (u64): the number of seconds this is valid after *timestamp* *(added v23.05)*
- **payee** (pubkey): the public key of the recipient *(added v23.05)*
- **payment\_hash** (hash): the hash of the *payment\_preimage* *(added v23.05)*
- **signature** (signature): signature of the *payee* on this invoice *(added v23.05)*
- **min\_final\_cltv\_expiry** (u32): the minimum CLTV delay for the final node *(added v23.05)*
- **amount\_msat** (msat, optional): Amount the invoice asked for *(added v23.05)*
- **description** (string, optional): the description of the purpose of the purchase *(added v23.05)*
- **description\_hash** (hash, optional): the hash of the description, in place of *description* *(added v23.05)*
- **payment\_secret** (hash, optional): the secret to hand to the payee node *(added v23.05)*
- **features** (hex, optional): the features bitmap for this invoice *(added v23.05)*
- **payment\_metadata** (hex, optional): the payment\_metadata to put in the payment *(added v23.05)*
- **fallbacks** (array of objects, optional): onchain addresses *(added v23.05)*:
  - **type** (string): the address type (if known) (one of "P2PKH", "P2SH", "P2WPKH", "P2WSH") *(added v23.05)*
  - **hex** (hex): Raw encoded address *(added v23.05)*
  - **addr** (string, optional): the address in appropriate format for *type* *(added v23.05)*
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

[comment]: # ( SHA256STAMP:b521d45403a0e065cba5c6596425de8a02097371eaca7cebe4e0046debaed1ac)
