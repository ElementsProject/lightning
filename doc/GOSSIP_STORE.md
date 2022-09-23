# gossip_store: Direct Access To Lightning Gossip

Hi!

The lightning_gossipd dameon stores the gossip messages, along with
some internal data, in a file called the "gossip_store".  Various
plugins and daemons access this (in a read-only manner), and the
format is documented here.

## The File Header

```
u8 version;
```

The gossmap header consists of one byte.  The top 3 bits are the major
version: if these are not all zero, you need to re-read this (updated)
document to see what changed.  The lower 5 bits are the minor version,
which won't worry you: currently they will be 11.

After the file header comes a number of records.

## The Record Header

```
be16 flags;
be16 len;
be32 crc;
be32 timestamp;
```

Each record consists of a header and a message.  The header is
big-endian, containing flags, the length (of the following body), the
crc32c (of the following message, starting with the timestamp field in
the header) and a timestamp extracted from certain messages (zero
where not relevant, but ignore it in those cases).

The flags currently defined are:

```
#define DELETED		 0x8000
#define PUSH		 0x4000
#define RATELIMIT	 0x2000
```

Deleted fields should be ignored: on restart, they will be removed as
the gossip_store is rewritten.

The push flag indicates gossip which is generated locally: this is
important for gossip timestamp filtering, where peers request gossip
and we always send our own gossip messages even if the timestamp
wasn't within their request.

The ratelimit flag indicates that this gossip message came too fast:
we record it, but don't relay it to peers.

Other flags should be ignored.

## The Message

Each messages consists of a 16-bit big-endian "type" field (for
efficiency, an implementation may read this along with the header),
and optional data.  Some messages are defined by the BOLT 7 gossip
protocol, others are for internal use.  Unknown message types should be
skipped over.

### BOLT 7 Messages

These are the messages which gossipd has validated, and ensured are in
order.

* `channel_announcement` (256): a complete, validated channel announcement.  This will always come before any `channel_update` which refers to it, or `node_announcement` which refers to a node.
* `channel_update` (258): a complete, validated channel update.  Note that you can see multiple of these (old ones will be deleted as they are replaced though).
* `node_announcement` (257): a complete, validated node announcement.  Note that you can also see multiple of these (old ones will be deleted as they are replaced).

### Internal Gossip Daemon Messages

These messages contain additional data, which may be useful.

* `gossip_store_channel_amount` (4101)
  * `satoshis`: u64

This always immediately follows `channel_announcement` messages, and
contains the actual capacity of the channel.

* `gossip_store_private_channel` (4104)
  * `amount_sat`: u64
  * `len`: u16
  * `announcement`: u8[len]

This contains information about a private (could be made public
later!) channel, with announcement in the same format as a normal
`channel_announcement` with invalid signatures.

* `gossip_store_private_update` (4102)
  * `len`: u16
  * `update`: u8[len]

This contains a private `channel_update` (i.e. for a channel described
by `gossip_store_private_channel`.

* `gossip_store_delete_chan` (4103)
  * `scid`: u64

This is added when a channel is deleted.  You won't often see this if
you're reading the file once (as the channel record header will have
been marked `deleted` first), but useful if you are polling the file
for updates.

* `gossip_store_ended` (4105)
  * `equivalent_offset`: u64
  
This is only ever added as the final entry in the gossip_store.  It
means the file has been deleted (usually because lightningd has been
restarted), and you should re-open it.  As an optimization, the
`equivalent_offset` in the new file reflects the point at which the
new gossip_store is equivalent to this one (with deleted records
removed).  However, if lightningd has been restarted multiple times it
is possible that this offset is not valid, so it's really only useful
if you're actively monitoring the file.

* `gossip_store_chan_dying` (4106)
  * `scid`: u64
  * `blockheight`: u32

This is placed in the gossip_store file when a funding transaction is
spent.  `blockheight` is set to 12 blocks beyond the block containing
the spend: at this point, gossipd will delete the channel.

## Using the Gossip Store File

- Always check the major version number!  We will increment it if the format
  changes in a way that breaks readers.
- Ignore unknown flags in the header.
- Ignore message types you don't know.
- You don't need to check the messages, as they have been validated.
- It is possible to see a partially-written record at the end.  Ignore it.

If you are keeping the file open to watch for changes:

- The file is append-only, so you can simply try reading more records 
  using inotify (or equivalent) or simply checking every few seconds.
- If you see a `gossip_store_ended` message, reopen the file.

Happy hacking!
Rusty.
