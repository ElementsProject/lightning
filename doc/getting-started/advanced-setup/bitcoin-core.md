---
title: "Bitcoin Core"
slug: "bitcoin-core"
hidden: false
createdAt: "2023-01-31T13:24:19.300Z"
updatedAt: "2023-02-21T13:30:53.906Z"
---
# Using a pruned Bitcoin Core node

Core Lightning requires JSON-RPC access to a fully synchronized `bitcoind` in order to synchronize with the Bitcoin network.

Access to ZeroMQ is not required and `bitcoind` does not need to be run with `txindex` like other implementations.

The lightning daemon will poll `bitcoind` for new blocks that it hasn't processed yet, thus synchronizing itself with `bitcoind`.

If `bitcoind` prunes a block that Core Lightning has not processed yet, e.g., Core Lightning was not running for a prolonged period, then `bitcoind` will not be able to serve the missing blocks, hence Core Lightning will not be able to synchronize anymore and will be stuck.

In order to avoid this situation you should be monitoring the gap between Core Lightning's blockheight using `[lightning-cli](ref:lightning-cli) getinfo` and `bitcoind`'s blockheight using `bitcoin-cli getblockchaininfo`. If the two blockheights drift apart it might be necessary to intervene.

# Connecting to Bitcoin Core remotely

You can use _trusted_ third-party plugins as bitcoin backends instead of using your own node. 

- [sauron](https://github.com/lightningd/plugins/tree/master/sauron) is a bitcoin backend plugin relying on [Esplora](https://github.com/Blockstream/esplora).
- [trustedcoin](https://github.com/nbd-wtf/trustedcoin) is a plugin that uses block explorers (blockstream.info, mempool.space, blockchair.com and blockchain.info) as backends instead of your own bitcoin node.
- [bps](https://github.com/coinos/bps) is a proxy server that exposes just the RPC commands that lightning needs. There's a public endpoint at <https://coinos.io/proxy> or you can host your own.
