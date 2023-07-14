---
title: "Sending and receiving payments"
slug: "sending-and-receiving-payments"
hidden: false
createdAt: "2022-11-18T16:27:07.625Z"
updatedAt: "2023-01-31T15:06:02.214Z"
---
Payments in Lightning are invoice based.

The recipient creates an invoice with the expected `<amount>` in millisatoshi (or `"any"` for a donation), a unique `<label>` and a `<description>` the payer will see:

```shell
lightning-cli invoice <amount> <label> <description>
```

This returns some internal details, and a standard invoice string called `bolt11` (named after the [BOLT #11 lightning spec](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)).

The sender can feed this `bolt11` string to the `decodepay` command to see what it is, and pay it simply using the `pay` command:

```shell
lightning-cli pay <bolt11>
```

Note that there are lower-level interfaces (and more options to these interfaces) for more sophisticated use.