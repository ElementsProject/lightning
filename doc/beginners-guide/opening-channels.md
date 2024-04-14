---
title: "Opening channels"
slug: "opening-channels"
hidden: false
createdAt: "2022-11-18T16:26:57.798Z"
updatedAt: "2023-01-31T15:07:08.196Z"
---
First you need to transfer some funds to `lightningd` so that it can open a channel:

```shell
# Returns an address <address>
lightning-cli newaddr
```



`lightningd` will register the funds once the transaction is confirmed.

Alternatively you can generate a taproot address should your source of funds support it:

```shell
# Return a taproot address
lightning-cli newaddr p2tr
```



Confirm `lightningd` got funds by:

```shell
# Returns an array of on-chain funds.
lightning-cli listfunds
```



Once `lightningd` has funds, we can connect to a node and open a channel. Let's assume the **remote** node is accepting connections at `<ip>` (and optional `<port>`, if not 9735) and has the node ID `<node_id>`:

```shell
lightning-cli connect <node_id> <ip> [<port>]
lightning-cli fundchannel <node_id> <amount_in_satoshis>
```



This opens a connection and, on top of that connection, then opens a channel. 

The funding transaction needs 3 confirmations in order for the channel to be usable, and 6 to be announced for others to use.

You can check the status of the channel using `lightning-cli listpeers`, which after 3 confirmations (1 on testnet) should say that `state` is `CHANNELD_NORMAL`; after 6 confirmations you can use `lightning-cli listchannels` to verify that the `public` field is now `true`.