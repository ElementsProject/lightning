lightning-pay -- Command for sending a payment to a BOLT11 invoice
==================================================================

SYNOPSIS
--------

**pay** *bolt11* [*amount\_msat*] [*label*] [*riskfactor*] [*maxfeepercent*] [*retry\_for*] [*maxdelay*] [*exemptfee*] [*localinvreqid*] [*exclude*] [*maxfee*] [*description*] 

DESCRIPTION
-----------

The **pay** RPC command attempts to find a route to the given destination, and send the funds it asks for. .

The response will occur when the payment fails or succeeds. Once a payment has succeeded, calls to **pay** with the same *bolt11* will succeed immediately.

When using *lightning-cli*, you may skip optional parameters by using *null*. Alternatively, use **-k** option to provide parameters by name.

- **bolt11** (string): Bolt11 invoice, if **experimental-offers** is enabled, it can actually be a bolt12 invoice, such as one received from lightningd-fetchinvoice(7). If it does not contain an amount, *amount\_msat* is required, otherwise if it is specified it must be *null*.
- **amount\_msat** (msat, optional): *amount\_msat* is in millisatoshi precision; it can be a whole number, or a whole number with suffix *msat* or *sat*, or a three decimal point number with suffix *sat*, or an 1 to 11 decimal point number suffixed by *btc*.
- **label** (string, optional): It is used to attach a label to payments, and is returned in lightning- listpays(7) and lightning-listsendpays(7).
- **riskfactor** (number, optional): The *riskfactor* is described in detail in lightning-getroute(7). The default is 10.
- **maxfeepercent** (number, optional): Percentage of the amount that is to be paid. The default is 0.5.
- **retry\_for** (u16, optional): Until *retry\_for* seconds passes, the command will keep finding routes and retrying the payment. The default is 60 seconds.
- **maxdelay** (u16, optional): A payment may be delayed for up to `maxdelay` blocks by another node; clients should be prepared for this worst case.
- **exemptfee** (msat, optional): This option can be used for tiny payments which would be dominated by the fee leveraged by forwarding nodes. Setting `exemptfee` allows the  `maxfeepercent` check to be skipped on fees that are smaller than `exemptfee`. The default is 5000 millisatoshi.
- **localinvreqid** (hex, optional): `localinvreqid` is used by offers to link a payment attempt to a local `invoice_request` offer created by lightningd-invoicerequest(7). This  ensures that we only make a single payment for an offer, and that the offer is marked `used` once paid.
- **exclude** (array, optional): *exclude* is a JSON array of short-channel-id/direction (e.g. [ '564334x877x1/0', '564195x1292x0/1' ]) or pubkey which should be excluded from consideration for routing. The default is not to exclude any channels or nodes.:
    - (short\_channel\_id\_dir)
    - (pubkey)
- **maxfee** (msat, optional): *maxfee* overrides both *maxfeepercent* and *exemptfee* defaults (and if you specify *maxfee* you cannot specify either of those), and creates an absolute limit on what fee we will pay. This allows you to implement your own heuristics rather than the primitive ones used here.
- **description** (string, optional): It is only required for bolt11 invoices which do not contain a description themselves, but contain a description hash: in this case *description* is required. *description* is then checked against the hash inside the invoice before it will be paid.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:pay#1",
  "method": "pay",
  "params": {
    "bolt11": "lni1qqgxr7gha7gusyg83lsr8qcqg4axgq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqtypg3hgetnwsszycn0d36rzv3zypjx2umrwf5hqarfdahzcg8sn7jmpuyl423pvggzvmj9nrga83q474e2sjygxzmq7ln5fmvjxh4skxafx2pmx9wqx5v9qgqxyfhyvyg6pdvu4tcjvpp7kkal9rp57wj7xv4pl3ajku70rzy3pavzzqjz06c8s2vvmrpjlkcse0txx0gmc6jalqqxmeyjm75qcnfnqxwyt2sfsqnxu3vc68fug904w25y3zpskc8huazwmy34av93h2fjswe3tsp4rqpe8qlx9xssexfc0aguke3q6u0jgw2qmn008mzu04mkmqmjmhes3gcpqdqdnzl270s48vsp635rd4jm04snvgkcp65qlkgp8qztu2mdp7c5uqpj2rll3pzu56st537rct3v62gfqeamzthjuwkr0pkvsdnnffpn4sq9sz0lryaufktx0nfxlffum3yesqev5gwqqqqqqqqqqqqqqqzsqqqqqqqqqqqqr5jt9hav2gqqqqqq5szxtvwkyz5zq2000hlwvadejz366lqjt9sd2j4rf5tfd9rgmmyegt4dqd34cf6v4gqkfvppqfnwgkvdr57yzh6h92zg3qctvrm7w38djg67kzcm4yeg8vc4cq633uzqn3n74ccym4wcvq20vsx7lmk450kprpvlrh4cukk8xy9ptjcef4rnhytnkyn4vnxxtd57yeaksze2s30y26cs6u3rjd9322eg9puk24q",
    "amount_msat": null,
    "label": null,
    "riskfactor": null,
    "maxfeepercent": null,
    "retry_for": null,
    "maxdelay": null,
    "exemptfee": null,
    "localinvreqid": null,
    "exclude": null,
    "maxfee": null,
    "description": null
  }
}
```

RANDOMIZATION
-------------

To protect user privacy, the payment algorithm performs some randomization.

1: Route Randomization

Route randomization means the payment algorithm does not always use the lowest-fee or shortest route. This prevents some highly-connected node from learning all of the user payments by reducing their fees below the network average.

2: Shadow Route

Shadow route means the payment algorithm will virtually extend the route by adding delays and fees along it, making it appear to intermediate nodes that the route is longer than it actually is. This prevents intermediate nodes from reliably guessing their distance from the payee.

Route randomization will never exceed *maxfeepercent* of the payment. Route randomization and shadow routing will not take routes that would exceed *maxdelay*.

RETURN VALUE
------------

On success, an object is returned, containing:

- **payment\_preimage** (secret): The proof of payment: SHA256 of this **payment\_hash**.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **created\_at** (number): The UNIX timestamp showing when this payment was initiated.
- **parts** (u32): How many attempts this took.
- **amount\_msat** (msat): Amount the recipient received.
- **amount\_sent\_msat** (msat): Total amount we sent (including fees).
- **status** (string) (one of "complete", "pending", "failed"): Status of payment.
- **destination** (pubkey, optional): The final destination of the payment.

The following warnings may also be returned:

- **warning\_partial\_completion**: Not all parts of a multi-part payment have completed.

You can monitor the progress and retries of a payment using the lightning-paystatus(7) command.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "destination": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
  "payment_hash": "29ef7dfee675b990a3ad7c125960d54aa34d16969468dec9942ead03635c274c",
  "created_at": 1706153504.76628,
  "parts": 1,
  "amount_msat": 100,
  "amount_sent_msat": 100,
  "payment_preimage": "6634c1b549c6615d234832f377e06d5a5ab088c40cebdc5cfb8c1262030abcad",
  "status": "complete"
}
```

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.
- 201: Already paid with this *hash* using different amount or destination.
- 203: Permanent failure at destination. The *data* field of the error will be routing failure object (except for self-payment, which currently returns the error directly from lightning-sendpay(7)).
- 205: Unable to find a route.
- 206: Route too expensive. Either the fee or the needed total locktime for the route exceeds your *maxfeepercent* or *maxdelay* settings, respectively. The *data* field of the error will indicate the actual *fee* as well as the *feepercent* percentage that the fee has of the destination payment amount. It will also indicate the actual *delay* along the route.
- 207: Invoice expired. Payment took too long before expiration, or already expired at the time you initiated payment. The *data* field of the error indicates *now* (the current time) and *expiry* (the invoice expiration) as UNIX epoch time in seconds.
- 210: Payment timed out without a payment in progress.

Error codes 202 and 204 will only get reported at **sendpay**; in **pay** we will keep retrying if we would have gotten those errors.

A routing failure object has the fields below:

*erring\_index*: The index of the node along the route that reported the error. 0 for the local node, 1 for the first hop, and so on.
*erring\_node*: The hex string of the pubkey id of the node that reported the error.
*erring\_channel*: The short channel ID of the channel that has the error, or *0:0:0* if the destination node raised the error.
*failcode*: The failure code, as per BOLT #4.
*channel\_update*: The hex string of the *channel\_update* message received from the remote node. Only present if error is from the remote node and the *failcode* has the UPDATE bit set, as per BOLT #4.

The *data* field of errors will include statistics *getroute\_tries* and *sendpay\_tries*. It will also contain a *failures* field with detailed data about routing errors.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-decodepay(7), lightning-listinvoice(7), lightning-delinvoice(7), lightning-getroute(7), lightning-invoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
