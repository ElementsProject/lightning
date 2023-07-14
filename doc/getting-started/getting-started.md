---
title: "Set up your node"
slug: "getting-started"
excerpt: "This guide will help you set up a Core Lightning node. You'll be up and running in a jiffy!"
hidden: false
createdAt: "2022-11-07T15:26:37.081Z"
updatedAt: "2023-02-22T06:00:15.160Z"
---
The Core Lightning implementation has been in production use on the Bitcoin mainnet since early 2018, with the launch of the [Blockstream Store](https://blockstream.com/2018/01/16/en-lightning-charge/). We recommend getting started by experimenting on `testnet` (or `regtest`), but the implementation is considered stable and can be safely used on mainnet.

The following steps will get you up and running with Core Lightning:

## 1. Prerequisites

- [x] **Operating System**

  Core Lightning is available on Linux and macOS. To run Core Lightning on Windows, consider using [docker](doc:installation#docker).
- [x] **Hardware**

  The requirements to run a Core Lightning node, at a minimum, are 4 GB RAM, ~500 GB of storage if you're running a Bitcoin Core full node, or less than 5 GB of storage if you run a pruned Bitcoin Core node or connect to Bitcoin Core remotely. Finally, a trivial amount of reliable network bandwidth is expected.



  For a thorough understanding of the best hardware setup for your usage / scenario, see guidance at [hardware considerations](doc:hardware-considerations).
- [x] **Bitcoin Core**

  Core Lightning requires a locally (or remotely) running `bitcoind` (version 0.16 or above) that is fully caught up with the network you're running on, and relays transactions (ie with `blocksonly=0`). Pruning (`prune=n` option in `bitcoin.conf`) is partially supported, see [here](doc:bitcoin-core#using-a-pruned-bitcoin-core-node) for more details. You can also connect your Core Lightning node to a remotely running Bitcoin Core, see [here](doc:bitcoin-core#connecting-to-bitcoin-core-remotely) to learn how.

## 2. [Install](doc:installation) Core Lightning

## 3. [Configure your node](doc:configuration) as per your requirements (_optional_)

## 4. **[Run your node](doc:beginners-guide)**