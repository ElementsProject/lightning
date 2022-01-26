lightning-sendonion -- Send a payment with a custom onion packet
================================================================

SYNOPSIS
--------

**sendonion** *onion* *first_hop* *payment_hash* [*label*] [*shared_secrets*] [*partid*] [*bolt11*]
[*msatoshi*] [*destination*]

DESCRIPTION
-----------

The **sendonion** RPC command can be used to initiate a payment attempt with a
custom onion packet. The onion packet is used to deliver instructions for hops
along the route on how to behave. Normally these instructions are indications
on where to forward a payment and what parameters to use, or contain details
of the payment for the final hop. However, it is possible to add arbitrary
information for hops in the custom onion, allowing for custom extensions that
are not directly supported by c-lightning.

The onion is specific to the route that is being used and the *payment_hash*
used to construct, and therefore cannot be reused for other payments or to
attempt a separate route. The custom onion can generally be created using the
`devtools/onion` CLI tool, or the **createonion** RPC command.

The *onion* parameter is a hex-encoded 1366 bytes long blob that was returned
by either of the tools that can generate onions. It contains the payloads
destined for each hop and some metadata. Please refer to [BOLT 04][bolt04] for
further details.

The *first_hop* parameter instructs c-lightning which peer to send the onion
to. It is a JSON dictionary that corresponds to the first element of the route
array returned by *getroute*. The following is a minimal example telling
c-lightning to use any available channel to `022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59`
to add an HTLC for 1002 millisatoshis and a delay of 21 blocks on top of the current blockheight:

```json
{
  "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
  "amount_msat": "1002msat",
  "delay": 21,
}
```

The *payment_hash* parameter specifies the 32 byte hex-encoded hash to use as
a challenge to the HTLC that we are sending. It is specific to the onion and
has to match the one the onion was created with.

The *label* parameter can be used to provide a human readable reference to
retrieve the payment at a later time.

The *shared_secrets* parameter is a JSON list of 32 byte hex-encoded secrets
that were used when creating the onion. c-lightning can send a payment with a
custom onion without the knowledge of these secrets, however it will not be
able to parse an eventual error message since that is encrypted with the
shared secrets used in the onion. If *shared_secrets* is provided c-lightning
will decrypt the error, act accordingly, e.g., add a `channel_update` included
in the error to its network view, and set the details in *listsendpays*
correctly. If it is not provided c-lightning will store the encrypted onion,
and expose it in *listsendpays* allowing the caller to decrypt it
externally. The following is an example of a 3 hop onion:

```json
[
	"298606954e9de3e9d938d18a74fed794c440e8eda82e52dc08600953c8acf9c4",
	"2dc094de72adb03b90894192edf9f67919cb2691b37b1f7d4a2f4f31c108b087",
	"a7b82b240dbd77a4ac8ea07709b1395d8c510c73c17b4b392bb1f0605d989c85"
]
```

If *shared_secrets* is not provided the c-lightning node does not know how
long the route is, which channels or nodes are involved, and what an eventual
error could have been. It can therefore be used for oblivious payments.

The *partid* value, if provided and non-zero, allows for multiple parallel
partial payments with the same *payment_hash*.

The *bolt11* parameter, if provided, will be returned in
*waitsendpay* and *listsendpays* results.

The *destination* parameter, if provided, will be returned in **listpays** result.

The *msatoshi* parameter is used to annotate the payment, and is returned by
*waitsendpay* and *listsendpays*.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **id** (u64): unique ID for this payment attempt
- **payment_hash** (hex): the hash of the *payment_preimage* which will prove payment (always 64 characters)
- **status** (string): status of the payment (could be complete if already sent previously) (one of "pending", "complete")
- **created_at** (u64): the UNIX timestamp showing when this payment was initiated
- **amount_sent_msat** (msat): The amount sent
- **amount_msat** (msat, optional): The amount delivered to destination (if known)
- **destination** (pubkey, optional): the final destination of the payment if known
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if supplied)
- **bolt12** (string, optional): the bolt12 string (if supplied: **experimental-offers** only).

If **status** is "complete":
  - **payment_preimage** (hex): the proof of payment: SHA256 of this **payment_hash** (always 64 characters)

If **status** is "pending":
  - **message** (string, optional): Monitor status with listpays or waitsendpay

[comment]: # (GENERATE-FROM-SCHEMA-END)

If *shared_secrets* was provided and an error was returned by one of the
intermediate nodes the error details are decrypted and presented
here. Otherwise the error code is 202 for an unparseable onion.

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-createonion(7), lightning-sendpay(7), lightning-listsendpays(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[bolt04]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md
[comment]: # ( SHA256STAMP:d588d85b79f709a57441479504ee8761331c852284ebb8effeab91a557437517)
