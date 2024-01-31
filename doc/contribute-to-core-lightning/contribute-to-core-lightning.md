---
title: "CLN Architecture"
slug: "contribute-to-core-lightning"
excerpt: "Familiarise yourself with the core components of Core Lightning."
hidden: false
createdAt: "2022-11-18T14:28:33.564Z"
updatedAt: "2023-02-21T15:12:37.888Z"
---
The Core Lightning project implements the lightning protocol as specified in [various BOLTs](https://github.com/lightning/bolts). It's broken into subdaemons, with the idea being that we can add more layers of separation between different clients and extra barriers to exploits.

To read the code, you should start from [lightningd.c](https://github.com/ElementsProject/lightning/blob/master/lightningd/lightningd.c) and hop your way through the '~' comments at the head of each daemon in the suggested order.

## The Components

Here's a list of parts, with notes:

- ccan - useful routines from <http://ccodearchive.net>
  - Use make update-ccan to update it.
  - Use make update-ccan CCAN_NEW="mod1 mod2..." to add modules
  - Do not edit this!  If you want a wrapper, add one to common/utils.h.

- bitcoin/ - bitcoin script, signature and transaction routines.
  - Not a complete set, but enough for our purposes.

- external/ - external libraries from other sources
  - libbacktrace - library to provide backtraces when things go wrong.
  - libsodium - encryption library (should be replaced soon with built-in)
  - libwally-core - bitcoin helper library
  - secp256k1 - bitcoin curve encryption library within libwally-core
  - jsmn - tiny JSON parsing helper

- tools/ - tools for building
  - check-bolt.c: check the source code contains correct BOLT quotes (as used by check-source)
  - generate-wire.py: generates wire marshal/un-marshaling routines for subdaemons and BOLT specs.
  - mockup.sh / update-mocks.sh: tools to generate mock functions for unit tests.

- tests/ - blackbox tests (mainly)
  - unit tests are in tests/ subdirectories in each other directory.

- doc/ - you are here

- devtools/ - tools for developers
  - Generally for decoding our formats.

- contrib/ - python support and other stuff which doesn't belong :)

- wire/ - basic marshalling/un for messages defined in the BOLTs

- common/ - routines needed by any two or more of the directories below

- cli/ - commandline utility to control lightning daemon.

- lightningd/ - master daemon which controls the subdaemons and passes peer file descriptors between them.

- wallet/ - database code used by master for tracking what's happening.

- hsmd/ - daemon which looks after the cryptographic secret, and performs commitment signing.

- gossipd/ - daemon to maintain routing information and broadcast gossip.

- connectd/ - daemon to connect to other peers, and receive incoming.

- openingd/ - daemon to open a channel for a single peer, and chat to a peer which doesn't have any channels/

- channeld/ - daemon to operate a single peer once channel is operating normally.

- closingd/ - daemon to handle mutual closing negotiation with a single peer.

- onchaind/ - daemon to handle a single channel which has had its funding transaction spent.

## Database

Core Lightning state is persisted in `lightning-dir`. It is a sqlite database stored in the `lightningd.sqlite3` file, typically under `~/.lightning/<network>/`.  
You can run queries against this file like so:

```shell
$ sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3 \
  "SELECT HEX(prev_out_tx), prev_out_index, status FROM outputs"
```



Or you can launch into the sqlite3 repl and check things out from there:

```shell
$ sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3
SQLite version 3.21.0 2017-10-24 18:55:49
Enter ".help" for usage hints.
sqlite> .tables
channel_configs  invoices         peers            vars
channel_htlcs    outputs          shachain_known   version
channels         payments         shachains
sqlite> .schema outputs
...
```



Some data is stored as raw bytes, use `HEX(column)` to pretty print these.

Make sure that clightning is not running when you query the database, as some queries may lock the database and cause crashes.

#### Common variables

Table `vars` contains global variables used by lightning node.

```shell
$ sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3
SQLite version 3.21.0 2017-10-24 18:55:49
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> select * from vars;
name|val
next_pay_index|2
bip32_max_index|4
...
```



Variables:

- `next_pay_index` next resolved invoice counter that will get assigned.
- `bip32_max_index` last wallet derivation counter.

Note: Each time `newaddr` command is called, `bip32_max_index` counter is increased to the last derivation index. Each address generated after `bip32_max_index` is not included as  
lightning funds.

# gossip_store: Direct Access To Lightning Gossip

The `lightning_gossipd` daemon stores the gossip messages, along with some internal data, in a file called the "gossip_store".  Various plugins and daemons access this (in a read-only manner), and the format is documented here.

## The File Header

```
u8 version;
```



The gossmap header consists of one byte.  The top 3 bits are the major version: if these are not all zero, you need to re-read this (updated) document to see what changed.  The lower 5 bits are the minor version, which won't worry you: currently they will be 11.

After the file header comes a number of records.

## The Record Header

```
be16 flags;
be16 len;
be32 crc;
be32 timestamp;
```



Each record consists of a header and a message.  The header is big-endian, containing flags, the length (of the following body), the crc32c (of the following message, starting with the timestamp field in the header) and a timestamp extracted from certain messages (zero where not relevant, but ignore it in those cases).

The flags currently defined are:

```
#define DELETED		 0x8000
#define PUSH		 0x4000
#define DYING		 0x0800
```



Deleted fields should be ignored: on restart, they will be removed as the gossip_store is rewritten.

The push flag indicates gossip which is generated locally: this is important for gossip timestamp filtering, where peers request gossip and we always send our own gossip messages even if the timestamp wasn't within their request.

The dying flag indicates that this channel has been spent, but we keep it around for 12 blocks in case it's actually a splice.

Other flags should be ignored.

## The Message

Each messages consists of a 16-bit big-endian "type" field (for efficiency, an implementation may read this along with the header), and optional data.  Some messages are defined by the BOLT 7 gossip protocol, others are for internal use.  Unknown message types should be skipped over.

### BOLT 7 Messages

These are the messages which gossipd has validated, and ensured are in order.

- `channel_announcement` (256): a complete, validated channel announcement.  This will always come before any `channel_update` which refers to it, or `node_announcement` which refers to a node.
- `channel_update` (258): a complete, validated channel update.  Note that you can see multiple of these (old ones will be deleted as they are replaced though).
- `node_announcement` (257): a complete, validated node announcement.  Note that you can also see multiple of these (old ones will be deleted as they are replaced).

### Internal Gossip Daemon Messages

These messages contain additional data, which may be useful.

- `gossip_store_channel_amount` (4101)
  - `satoshis`: u64

This always immediately follows `channel_announcement` messages, and contains the actual capacity of the channel.

- `gossip_store_private_channel` (4104)
  - `amount_sat`: u64
  - `len`: u16
  - `announcement`: u8[len]

This contains information about a private (could be made public later!) channel, with announcement in the same format as a normal `channel_announcement` with invalid signatures.

- `gossip_store_private_update` (4102)
  - `len`: u16
  - `update`: u8[len]

This contains a private `channel_update` (i.e. for a channel described by `gossip_store_private_channel`.

- `gossip_store_delete_chan` (4103)
  - `scid`: u64

This is added when a channel is deleted.  You won't often see this if you're reading the file once (as the channel record header will have been marked `deleted` first), but useful if you are polling the file for updates.

- `gossip_store_ended` (4105)
  - `equivalent_offset`: u64

This is only ever added as the final entry in the gossip_store.  It means the file has been deleted (usually because lightningd has been restarted), and you should re-open it.  As an optimization, the `equivalent_offset` in the new file reflects the point at which the new gossip_store is equivalent to this one (with deleted records removed).  However, if lightningd has been restarted multiple times it is possible that this offset is not valid, so it's really only useful if you're actively monitoring the file.

- `gossip_store_chan_dying` (4106)
  - `scid`: u64
  - `blockheight`: u32

This is placed in the gossip_store file when a funding transaction is spent.  `blockheight` is set to 12 blocks beyond the block containing the spend: at this point, gossipd will delete the channel.

## Using the Gossip Store File

- Always check the major version number!  We will increment it if the format changes in a way that breaks readers.
- Ignore unknown flags in the header.
- Ignore message types you don't know.
- You don't need to check the messages, as they have been validated.
- It is possible to see a partially-written record at the end.  Ignore it.

If you are keeping the file open to watch for changes:

- The file is append-only, so you can simply try reading more records using inotify (or equivalent) or simply checking every few seconds.
- If you see a `gossip_store_ended` message, reopen the file.
