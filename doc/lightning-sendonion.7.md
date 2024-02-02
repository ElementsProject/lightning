lightning-sendonion -- Send a payment with a custom onion packet
================================================================

SYNOPSIS
--------

**sendonion** *onion* *first\_hop* *payment\_hash* [*label*] [*shared\_secrets*] [*partid*] [*bolt11*]
[*amount\_msat*] [*destination*]

DESCRIPTION
-----------

The **sendonion** RPC command can be used to initiate a payment attempt with a
custom onion packet. The onion packet is used to deliver instructions for hops
along the route on how to behave. Normally these instructions are indications
on where to forward a payment and what parameters to use, or contain details
of the payment for the final hop. However, it is possible to add arbitrary
information for hops in the custom onion, allowing for custom extensions that
are not directly supported by Core Lightning.

If the first element of *route* does not have "channel" set, a
suitable channel (if any) will be chosen, otherwise that specific
short-channel-id is used. The following is an example of a 3 hop onion:

```json
[
	"298606954e9de3e9d938d18a74fed794c440e8eda82e52dc08600953c8acf9c4",
	"2dc094de72adb03b90894192edf9f67919cb2691b37b1f7d4a2f4f31c108b087",
	"a7b82b240dbd77a4ac8ea07709b1395d8c510c73c17b4b392bb1f0605d989c85"
]
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **created\_index** (u64): 1-based index indicating order this payment was created in *(added v23.11)*
- **id** (u64): old synonym for created\_index
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): status of the payment (could be complete if already sent previously) (one of "pending", "complete")
- **created\_at** (u64): the UNIX timestamp showing when this payment was initiated
- **amount\_sent\_msat** (msat): The amount sent
- **amount\_msat** (msat, optional): The amount delivered to destination (if known)
- **destination** (pubkey, optional): the final destination of the payment if known
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if supplied)
- **bolt12** (string, optional): the bolt12 string (if supplied: **experimental-offers** only).
- **partid** (u64, optional): the partid (if supplied) to sendonion/sendpay

If **status** is "complete":

  - **payment\_preimage** (secret): the proof of payment: SHA256 of this **payment\_hash**
  - **updated\_index** (u64, optional): 1-based index indicating order this payment was changed *(added v23.11)*

If **status** is "pending":

  - **message** (string, optional): Monitor status with listpays or waitsendpay

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following error codes may occur:

- 202: an parseable onion
- the error details are decrypted and presented here, if *shared\_secrets* was provided and an error was returned by one of the
intermediate nodes

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-createonion(7), lightning-sendpay(7), lightning-listsendpays(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[bolt04]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md

[comment]: # ( SHA256STAMP:eb3725c7a47c32298ca9e13ad6ef3fc90a818354b21fc0b17abd16d8e9515a24)
