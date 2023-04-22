---
title: "Watchtowers"
slug: "watchtowers"
excerpt: "Defend your node against breaches using a watchtower."
hidden: false
createdAt: "2022-11-18T16:28:27.054Z"
updatedAt: "2023-02-02T07:13:57.111Z"
---
The Lightning Network protocol assumes that a node is always online and synchronised with the network. Should your lightning node go offline for some time, it is possible that a node on the other side of your channel may attempt to force close the channel with an outdated state (also known as revoked commitment). This may allow them to steal funds from the channel that belonged to you. 

A watchtower is a third-party service that you can hire to defend your node against such breaches, whether malicious or accidental, in the event that your node goes offline. It will watch for breaches on the blockchain and punish the malicious peer by relaying a penalty transaction on your behalf.

There are a number of watchtower services available today. One of them is the [watchtower client plugin](https://github.com/talaia-labs/rust-teos/tree/master/watchtower-plugin) that works with the [Eye of Satoshi tower](https://github.com/talaia-labs/rust-teos) (or any [BOLT13](https://github.com/sr-gi/bolt13/blob/master/13-watchtowers.md) compliant watchtower).