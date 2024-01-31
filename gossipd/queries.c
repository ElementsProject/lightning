/* Routines to generate and handle gossip query messages */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/crc32c/crc32c.h>
#include <common/daemon_conn.h>
#include <common/decode_array.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <zlib.h>

static u32 dev_max_encoding_bytes = -1U;

/* BOLT #7:
 *
 * There are several messages which contain a long array of
 * `short_channel_id`s (called `encoded_short_ids`) so we include an encoding
 *  byte which allows for different encoding schemes to be defined in the future
 */
static u8 *encoding_start(const tal_t *ctx, bool prepend_encoding)
{
	u8 *ret;
	if (prepend_encoding) {
		ret = tal_arr(ctx, u8, 1);
		ret[0] = ARR_UNCOMPRESSED;
	} else
		ret = tal_arr(ctx, u8, 0);
	return ret;
}

/* Marshal a single short_channel_id */
static void encoding_add_short_channel_id(u8 **encoded,
					  const struct short_channel_id *scid)
{
	towire_short_channel_id(encoded, scid);
}

/* Marshal a single channel_update_timestamps */
static void encoding_add_timestamps(u8 **encoded,
				    const struct channel_update_timestamps *ts)
{
	towire_channel_update_timestamps(encoded, ts);
}

/* Marshal a single query flag (we don't query, so not currently used) */
static void encoding_add_query_flag(u8 **encoded, bigsize_t flag)
{
	towire_bigsize(encoded, flag);
}

static bool encoding_end(const u8 *encoded, size_t max_bytes)
{
	if (tal_count(encoded) > dev_max_encoding_bytes)
		return false;
	return tal_count(encoded) <= max_bytes;
}

/* Query this peer for these short-channel-ids. */
bool query_short_channel_ids(struct daemon *daemon,
			     struct peer *peer,
			     const struct short_channel_id *scids,
			     const u8 *query_flags,
			     void (*cb)(struct peer *peer, bool complete))
{
	u8 *encoded, *msg;
	struct tlv_query_short_channel_ids_tlvs *tlvs;
	/* BOLT #7:
	 *
	 * 1. type: 261 (`query_short_channel_ids`) (`gossip_queries`)
	 * 2. data:
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`u16`:`len`]
	 *     * [`len*byte`:`encoded_short_ids`]
	 */
	const size_t reply_overhead = 32 + 2;
	size_t max_encoded_bytes = 65535 - 2 - reply_overhead;

	/* Can't query if they don't have gossip_queries_feature */
	if (!peer->gossip_queries_feature)
		return false;

	/* BOLT #7:
	 *   - MAY include an optional `query_flags`. If so:
	 *    - MUST set `encoding_type`, as for `encoded_short_ids`.
	 *    - Each query flag is a minimally-encoded bigsize.
	 *    - MUST encode one query flag per `short_channel_id`.
	 */
	if (query_flags)
		assert(tal_count(query_flags) == tal_count(scids));

	/* BOLT #7:
	 *
	 * The sender:
	 *  - MUST NOT send `query_short_channel_ids` if it has sent a previous
	 *   `query_short_channel_ids` to this peer and not received
	 *   `reply_short_channel_ids_end`.
	 */
	if (peer->scid_query_outstanding)
		return false;

	encoded = encoding_start(tmpctx, true);
	for (size_t i = 0; i < tal_count(scids); i++) {
		/* BOLT #7:
		 *
		 * Encoding types:
		 * * `0`: uncompressed array of `short_channel_id` types, in
		 *   ascending order.
		 */
		assert(i == 0 || scids[i].u64 > scids[i-1].u64);
		encoding_add_short_channel_id(&encoded, &scids[i]);
	}

	if (!encoding_end(encoded, max_encoded_bytes)) {
		status_broken("query_short_channel_ids: %zu is too many",
			      tal_count(scids));
		return false;
	}

	if (query_flags) {
		struct tlv_query_short_channel_ids_tlvs_query_flags *tlvq;
		tlvs = tlv_query_short_channel_ids_tlvs_new(tmpctx);
		tlvq = tlvs->query_flags = tal(tlvs,
			   struct tlv_query_short_channel_ids_tlvs_query_flags);
		tlvq->encoding_type = ARR_UNCOMPRESSED;
		tlvq->encoded_query_flags = encoding_start(tlvq, false);
		for (size_t i = 0; i < tal_count(query_flags); i++)
			encoding_add_query_flag(&tlvq->encoded_query_flags,
						query_flags[i]);

		max_encoded_bytes -= tal_bytelen(encoded);
		if (!encoding_end(tlvq->encoded_query_flags,
				  max_encoded_bytes)) {
			status_broken("query_short_channel_ids:"
				      " %zu query_flags is too many",
				      tal_count(query_flags));
			return false;
		}
	} else
		tlvs = NULL;

	msg = towire_query_short_channel_ids(NULL,
					     &chainparams->genesis_blockhash,
					     encoded, tlvs);
	queue_peer_msg(daemon, &peer->id, take(msg));
	peer->scid_query_outstanding = true;
	peer->scid_query_cb = cb;

	status_peer_debug(&peer->id, "sending query for %zu scids",
			  tal_count(scids));
	return true;
}

/* The peer can ask about an array of short channel ids: we don't assemble the
 * reply immediately but process them one at a time in dump_gossip which is
 * called when there's nothing more important to send. */
const u8 *handle_query_short_channel_ids(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 *encoded;
	struct short_channel_id *scids;
	bigsize_t *flags;
	struct tlv_query_short_channel_ids_tlvs *tlvs;

	if (!fromwire_query_short_channel_ids(tmpctx, msg, &chain, &encoded,
					      &tlvs)) {
		return towire_warningfmt(peer, NULL,
					 "Bad query_short_channel_ids w/tlvs %s",
					 tal_hex(tmpctx, msg));
	}
	if (tlvs->query_flags) {
		/* BOLT #7:
		 *
		 * The receiver:
		 *...
		 *  - if the incoming message includes
		 *    `query_short_channel_ids_tlvs`:
		 *    - if `encoding_type` is not a known encoding type:
		 *      - MAY send a `warning`.
		 *      - MAY close the connection.
		 */
		flags = decode_scid_query_flags(tmpctx, tlvs->query_flags);
		if (!flags) {
			return towire_warningfmt(peer, NULL,
						 "Bad query_short_channel_ids query_flags %s",
						 tal_hex(tmpctx, msg));
		}
	} else
		flags = NULL;

	/* BOLT #7
	 *
	 * The receiver:
	 * ...
	 *   - if does not maintain up-to-date channel information for `chain_hash`:
	 *     - MUST set `complete` to 0.
	 */
	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain)) {
		status_peer_debug(&peer->id,
				  "sent query_short_channel_ids chainhash %s",
				  type_to_string(tmpctx, struct bitcoin_blkid, &chain));
		return towire_reply_short_channel_ids_end(peer, &chain, 0);
	}

	/* BOLT #7:
	 *
	 * - if it has not sent `reply_short_channel_ids_end` to a
	 *   previously received `query_short_channel_ids` from this
	 *   sender:
	 *    - MAY send a `warning`.
	 *    - MAY close the connection.
	 */
	if (peer->scid_queries || peer->scid_query_nodes) {
		return towire_warningfmt(peer, NULL,
					 "Bad concurrent query_short_channel_ids");
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		return towire_warningfmt(peer, NULL,
					 "Bad query_short_channel_ids encoding %s",
					 tal_hex(tmpctx, encoded));
	}

	/* BOLT #7:
	 *
	 * The receiver:
	 *...
	 *    - if `encoded_query_flags` does not decode to exactly one flag per
	 *      `short_channel_id`:
	 *     - MAY send a `warning`.
	 *     - MAY close the connection.
	 */
	if (!flags) {
		/* Pretend they asked for everything. */
		flags = tal_arr(tmpctx, bigsize_t, tal_count(scids));
		memset(flags, 0xFF, tal_bytelen(flags));
	} else {
		if (tal_count(flags) != tal_count(scids)) {
			return towire_warningfmt(peer, NULL,
						 "Bad query_short_channel_ids flags count %zu scids %zu",
						 tal_count(flags), tal_count(scids));
		}
	}

	/* BOLT #7:
	 *
	 * - MUST respond to each known `short_channel_id`:
	 *...
	 *    - SHOULD NOT wait for the next outgoing gossip flush to send
	 *      these.
	 */
	peer->scid_queries = tal_steal(peer, scids);
	peer->scid_query_flags = tal_steal(peer, flags);
	peer->scid_query_idx = 0;
	peer->scid_query_nodes = tal_arr(peer, struct node_id, 0);

	/* Notify the daemon_conn-write loop to invoke maybe_send_query_responses_peer */
	daemon_conn_wake(peer->daemon->connectd);
	return NULL;
}

/*~ We can send multiple replies when the peer queries for all channels in
 * a given range of blocks; each one indicates the range of blocks it covers. */
static void send_reply_channel_range(struct peer *peer,
				     u32 first_blocknum, u32 number_of_blocks,
				     const struct short_channel_id *scids,
				     const struct channel_update_timestamps *tstamps,
				     const struct channel_update_checksums *csums,
				     size_t num_scids,
				     bool final)
{
	/* BOLT #7:
	 *
	 * - MUST respond with one or more `reply_channel_range`:
	 *   - MUST set with `chain_hash` equal to that of `query_channel_range`,
	 *   - MUST limit `number_of_blocks` to the maximum number of blocks
	 *     whose results could fit in `encoded_short_ids`
	 */
	u8 *encoded_scids = encoding_start(tmpctx, true);
	u8 *encoded_timestamps = encoding_start(tmpctx, false);
 	struct tlv_reply_channel_range_tlvs *tlvs
 		= tlv_reply_channel_range_tlvs_new(tmpctx);

	/* Encode them all */
	for (size_t i = 0; i < num_scids; i++)
		encoding_add_short_channel_id(&encoded_scids, &scids[i]);
	encoding_end(encoded_scids, tal_bytelen(encoded_scids));

	if (tstamps) {
		for (size_t i = 0; i < num_scids; i++)
			encoding_add_timestamps(&encoded_timestamps, &tstamps[i]);

		tlvs->timestamps_tlv = tal(tlvs, struct tlv_reply_channel_range_tlvs_timestamps_tlv);
		tlvs->timestamps_tlv->encoding_type = ARR_UNCOMPRESSED;
		encoding_end(encoded_timestamps,
			     tal_bytelen(encoded_timestamps));
		tlvs->timestamps_tlv->encoded_timestamps
			= tal_steal(tlvs, encoded_timestamps);
	}

	/* Must be a tal object! */
	if (csums)
		tlvs->checksums_tlv = tal_dup_arr(tlvs,
						  struct channel_update_checksums,
						  csums, num_scids, 0);

	/* BOLT #7:
	 *
	 * - MUST set `sync_complete` to `false` if this is not the final
	 *   `reply_channel_range`.
	 */
	u8 *msg = towire_reply_channel_range(NULL,
					     &chainparams->genesis_blockhash,
					     first_blocknum,
					     number_of_blocks,
					     final, encoded_scids, tlvs);
	queue_peer_msg(peer->daemon, &peer->id, take(msg));
}

/* Helper to get non-signature, non-timestamp parts of (valid!) channel_update */
void get_cupdate_parts(const u8 *channel_update,
		       const u8 *parts[2],
		       size_t sizes[2])
{
	/* BOLT #7:
	 *
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`chain_hash`:`chain_hash`]
	 *    * [`short_channel_id`:`short_channel_id`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* Note: 2 bytes for `type` field */
	/* We already checked it's valid before accepting */
	assert(tal_count(channel_update) > 2 + 64 + 32 + 8 + 4);
	parts[0] = channel_update + 2 + 64;
	sizes[0] = 32 + 8;
	parts[1] = channel_update + 2 + 64 + 32 + 8 + 4;
	sizes[1] = tal_count(channel_update) - (64 + 2 + 32 + 8 + 4);
}

/* BOLT #7:
 *
 * The checksum of a `channel_update` is the CRC32C checksum as specified in
 * [RFC3720](https://tools.ietf.org/html/rfc3720#appendix-B.4) of this
 * `channel_update` without its `signature` and `timestamp` fields.
 */
static u32 crc32_of_update(const u8 *channel_update)
{
	u32 sum;
	const u8 *parts[2];
	size_t sizes[ARRAY_SIZE(parts)];

	get_cupdate_parts(channel_update, parts, sizes);

	sum = 0;
	for (size_t i = 0; i < ARRAY_SIZE(parts); i++)
		sum = crc32c(sum, parts[i], sizes[i]);
	return sum;
}

static void get_checksum_and_timestamp(struct routing_state *rstate,
				       const struct chan *chan,
				       int direction,
				       u32 *tstamp, u32 *csum)
{
	const struct half_chan *hc = &chan->half[direction];

	if (!is_halfchan_defined(hc)) {
		*tstamp = *csum = 0;
	} else {
		const u8 *update = gossip_store_get(tmpctx, rstate->daemon->gs,
						    hc->bcast.index);
		*tstamp = hc->bcast.timestamp;
		*csum = crc32_of_update(update);
	}
}

/* FIXME: This assumes that the tlv type encodes into 1 byte! */
static size_t tlv_overhead(size_t num_entries, size_t size)
{
	return 1 + bigsize_len(num_entries * size);
}

/* How many entries can I fit in a reply? */
static size_t max_entries(enum query_option_flags query_option_flags)
{
	/* BOLT #7:
	 *
	 * 1. type: 264 (`reply_channel_range`) (`gossip_queries`)
	 * 2. data:
	 *   * [`chain_hash`:`chain_hash`]
	 *   * [`u32`:`first_blocknum`]
	 *   * [`u32`:`number_of_blocks`]
	 *   * [`byte`:`sync_complete`]
	 *   * [`u16`:`len`]
	 *   * [`len*byte`:`encoded_short_ids`]
	 */
	const size_t reply_overhead = 32 + 4 + 4 + 1 + 2;
	size_t max_encoded_bytes = 65535 - 2 - reply_overhead;
	size_t per_entry_size, max_num;

	per_entry_size = sizeof(struct short_channel_id);

	/* Upper bound to start. */
	max_num = max_encoded_bytes / per_entry_size;

	/* If we add timestamps, we need to encode tlv */
	if (query_option_flags & QUERY_ADD_TIMESTAMPS) {
		max_encoded_bytes -= tlv_overhead(max_num,
						  sizeof(struct channel_update_timestamps));
		per_entry_size += sizeof(struct channel_update_timestamps);
	}

	if (query_option_flags & QUERY_ADD_CHECKSUMS) {
		max_encoded_bytes -= tlv_overhead(max_num,
						  sizeof(struct channel_update_checksums));
		per_entry_size += sizeof(struct channel_update_checksums);
	}

	if (max_encoded_bytes > dev_max_encoding_bytes)
		max_encoded_bytes = dev_max_encoding_bytes;
	/* Always let one through! */
	if (max_encoded_bytes < per_entry_size)
		max_encoded_bytes = per_entry_size;

	return max_encoded_bytes / per_entry_size;
}

/* This gets all the scids they asked for, and optionally the timestamps and checksums */
static struct short_channel_id *gather_range(const tal_t *ctx,
					     struct routing_state *rstate,
					     u32 first_blocknum, u32 number_of_blocks,
					     enum query_option_flags query_option_flags,
					     struct channel_update_timestamps **tstamps,
					     struct channel_update_checksums **csums)
{
	struct short_channel_id scid, *scids;
	u32 end_block;
	bool scid_ok;

	scids = tal_arr(ctx, struct short_channel_id, 0);
	if (query_option_flags & QUERY_ADD_TIMESTAMPS)
		*tstamps = tal_arr(ctx, struct channel_update_timestamps, 0);
	else
		*tstamps = NULL;
	if (query_option_flags & QUERY_ADD_CHECKSUMS)
		*csums = tal_arr(ctx, struct channel_update_checksums, 0);
	else
		*csums = NULL;

	/* Avoid underflow: we don't use block 0 anyway */
	if (first_blocknum == 0)
		scid_ok = mk_short_channel_id(&scid, 1, 0, 0);
	else
		scid_ok = mk_short_channel_id(&scid, first_blocknum, 0, 0);
	scid.u64--;
	/* Out of range?  No blocks then. */
	if (!scid_ok)
		return NULL;

	if (number_of_blocks == 0)
		return NULL;

	/* Fix up number_of_blocks to avoid overflow. */
	end_block = first_blocknum + number_of_blocks - 1;
	if (end_block < first_blocknum)
		end_block = UINT_MAX;

	/* We keep a `uintmap` of `short_channel_id` to `struct chan *`.
	 * Unlike a htable, it's efficient to iterate through, but it only
	 * works because each short_channel_id is basically a 64-bit unsigned
	 * integer.
	 *
	 * First we iterate and gather all the short channel ids. */
	while (uintmap_after(&rstate->chanmap, &scid.u64)) {
		struct chan *chan;
		struct channel_update_timestamps ts;
		struct channel_update_checksums cs;

		if (short_channel_id_blocknum(&scid) > end_block)
			break;

		/* FIXME: Store csum in header. */
		chan = get_channel(rstate, &scid);
		tal_arr_expand(&scids, scid);

		/* Don't calc csums if we don't even care */
		if (!(query_option_flags
		      & (QUERY_ADD_TIMESTAMPS|QUERY_ADD_CHECKSUMS)))
			continue;

		get_checksum_and_timestamp(rstate, chan, 0,
					   &ts.timestamp_node_id_1,
					   &cs.checksum_node_id_1);
		get_checksum_and_timestamp(rstate, chan, 1,
					   &ts.timestamp_node_id_2,
					   &cs.checksum_node_id_2);
		if (query_option_flags & QUERY_ADD_TIMESTAMPS)
			tal_arr_expand(tstamps, ts);
		if (query_option_flags & QUERY_ADD_CHECKSUMS)
			tal_arr_expand(csums, cs);
	}

	return scids;
}

/*~ When we need to send an array of channels, it might go over our 64k packet
 * size.  But because we use compression, we can't actually tell how much
 * we'll use.  We pack them into the maximum amount for uncompressed, then
 * compress afterwards.
 */
static void queue_channel_ranges(struct peer *peer,
				 u32 first_blocknum, u32 number_of_blocks,
				 enum query_option_flags query_option_flags)
{
	struct routing_state *rstate = peer->daemon->rstate;
	struct channel_update_timestamps *tstamps;
	struct channel_update_checksums *csums;
	struct short_channel_id *scids;
	size_t off, limit;

	scids = gather_range(tmpctx, rstate, first_blocknum, number_of_blocks,
			     query_option_flags, &tstamps, &csums);

	limit = max_entries(query_option_flags);
	off = 0;

	/* We need to send an empty msg if we have nothing! */
	do {
		size_t n = tal_count(scids) - off;
		u32 this_num_blocks;

		if (n > limit) {
			status_debug("reply_channel_range: splitting %zu-%zu of %zu",
				     off, off + limit, tal_count(scids));
			n = limit;

			/* ... and reduce to a block boundary. */
			while (short_channel_id_blocknum(&scids[off + n - 1])
			       == short_channel_id_blocknum(&scids[off + limit])) {
				/* We assume one block doesn't have limit #
				 * channels.  If it does, we have to violate
				 * spec and send over multiple blocks. */
				if (n == 0) {
					status_broken("reply_channel_range: "
						      "could not fit %zu scids for %u!",
						      limit,
						      short_channel_id_blocknum(&scids[off + n - 1]));
					n = limit;
					break;
				}
				n--;
			}
			/* Get *next* channel, add num blocks */
			this_num_blocks
				= short_channel_id_blocknum(&scids[off + n])
				- first_blocknum;
		} else
			/* Last one must end with correct total */
			this_num_blocks = number_of_blocks;

		send_reply_channel_range(peer, first_blocknum, this_num_blocks,
					 scids + off,
					 query_option_flags & QUERY_ADD_TIMESTAMPS
					 ? tstamps + off : NULL,
					 query_option_flags & QUERY_ADD_CHECKSUMS
					 ? csums + off : NULL,
					 n,
					 this_num_blocks == number_of_blocks);
		first_blocknum += this_num_blocks;
		number_of_blocks -= this_num_blocks;
		off += n;
	} while (number_of_blocks);
}

/*~ The peer can ask for all channels in a series of blocks.  We reply with one
 * or more messages containing the short_channel_ids. */
const u8 *handle_query_channel_range(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum, number_of_blocks;
	enum query_option_flags query_option_flags;
	struct tlv_query_channel_range_tlvs *tlvs;

	if (!fromwire_query_channel_range(msg, msg, &chain_hash,
					  &first_blocknum, &number_of_blocks,
					  &tlvs)) {
		return towire_warningfmt(peer, NULL,
					 "Bad query_channel_range w/tlvs %s",
					 tal_hex(tmpctx, msg));
	}
	if (tlvs->query_option)
		query_option_flags = *tlvs->query_option;
	else
		query_option_flags = 0;

	/* BOLT #7
	 *
	 * The receiver of `query_channel_range`:
	 * ...
	 *   - if does not maintain up-to-date channel information for `chain_hash`:
	 *     - MUST set `complete` to 0.
	 */
	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain_hash)) {
		status_peer_debug(&peer->id,
				  "query_channel_range with chainhash %s",
				  type_to_string(tmpctx, struct bitcoin_blkid,
						 &chain_hash));
		u8 *end = towire_reply_channel_range(NULL, &chain_hash, first_blocknum,
		                                     number_of_blocks, false, NULL, NULL);
		queue_peer_msg(peer->daemon, &peer->id, take(end));
		return NULL;
	}

	/* Fix up number_of_blocks to avoid overflow. */
	if (first_blocknum + number_of_blocks < first_blocknum)
		number_of_blocks = UINT_MAX - first_blocknum;

	queue_channel_ranges(peer, first_blocknum, number_of_blocks,
			     query_option_flags);
	return NULL;
}

/* Append these scids (and optional timestamps) to our pending replies */
static u8 *append_range_reply(struct peer *peer,
			      const struct short_channel_id *scids,
			      const struct tlv_reply_channel_range_tlvs_timestamps_tlv
			      *timestamps_tlv)
{
	u16 i, old_num, added;
	const struct channel_update_timestamps *ts;
	/* Zero means "no timestamp" */
	const static struct channel_update_timestamps zero_ts = { 0, 0 };

	if (timestamps_tlv) {
		ts = decode_channel_update_timestamps(tmpctx,
						      timestamps_tlv);
		if (!ts)
			return towire_warningfmt(peer, NULL,
						 "reply_channel_range can't decode timestamps.");
		if (tal_count(ts) != tal_count(scids)) {
			return towire_warningfmt(peer, NULL,
						 "reply_channel_range %zu timestamps when %zu scids?",
						 tal_count(ts),
						 tal_count(scids));
		}
	} else
		ts = NULL;

	old_num = tal_count(peer->range_replies);
	added = tal_count(scids);
	for (i = 0; i < added; i++) {
		tal_resize(&peer->range_replies, old_num + i + 1);
		peer->range_replies[old_num + i].scid = scids[i];
		if (ts)
			peer->range_replies[old_num + i].ts = ts[i];
		else
			peer->range_replies[old_num + i].ts = zero_ts;
	}

	return NULL;
}

/*~ This is the reply we get when we send query_channel_range; we keep
 * expecting them until the entire range we asked for is covered. */
const u8 *handle_reply_channel_range(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 sync_complete;
	u32 first_blocknum, number_of_blocks, start, end;
	u8 *encoded;
	struct short_channel_id *scids;
	const struct range_query_reply *replies;
	const u8 *err;
	void (*cb)(struct peer *peer,
		   u32 first_blocknum, u32 number_of_blocks,
		   const struct range_query_reply *replies);
	struct tlv_reply_channel_range_tlvs *tlvs;

	if (!fromwire_reply_channel_range(tmpctx, msg, &chain, &first_blocknum,
					  &number_of_blocks, &sync_complete,
					  &encoded, &tlvs)) {
		return towire_warningfmt(peer, NULL,
					 "Bad reply_channel_range w/tlvs %s",
					 tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain)) {
		return towire_warningfmt(peer, NULL,
					 "reply_channel_range for bad chain: %s",
					 tal_hex(tmpctx, msg));
	}

	if (!peer->range_replies) {
		return towire_warningfmt(peer, NULL,
					 "reply_channel_range without query: %s",
					 tal_hex(tmpctx, msg));
	}

	/* Beware overflow! */
	if (first_blocknum + number_of_blocks < first_blocknum) {
		return towire_warningfmt(peer, NULL,
					 "reply_channel_range invalid %u+%u",
					 first_blocknum, number_of_blocks);
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		return towire_warningfmt(peer, NULL,
					 "Bad reply_channel_range encoding %s",
					 tal_hex(tmpctx, encoded));
	}

	status_peer_debug(&peer->id,
			  "reply_channel_range %u+%u (of %u+%u) %zu scids",
			  first_blocknum, number_of_blocks,
			  peer->range_first_blocknum,
			  peer->range_end_blocknum - peer->range_first_blocknum,
			  tal_count(scids));

	/* BOLT #7:
	 * The receiver of `query_channel_range`:
	 *...
	 * - the first `reply_channel_range` message:
	 *   - MUST set `first_blocknum` less than or equal to the
	 *     `first_blocknum` in `query_channel_range`
	 *   - MUST set `first_blocknum` plus `number_of_blocks` greater than
	 *     `first_blocknum` in `query_channel_range`.
	 * - successive `reply_channel_range` message:
	 *    - MUST have `first_blocknum` equal or greater than the previous
	 *     `first_blocknum`.
	 *    - MUST set `sync_complete` to `false` if this is not the final `reply_channel_range`.
	 * - the final `reply_channel_range` message:
	 *   - MUST have `first_blocknum` plus `number_of_blocks` equal or
	 *     greater than the `query_channel_range` `first_blocknum` plus
	 *     `number_of_blocks`.
	 *   - MUST set `sync_complete` to `true`.
	 */
	/* ie. They can be outside range we asked, but they must overlap! */
	if (first_blocknum + number_of_blocks <= peer->range_first_blocknum
	    || first_blocknum >= peer->range_end_blocknum) {
		return towire_warningfmt(peer, NULL,
					 "reply_channel_range invalid %u+%u for query %u+%u",
					 first_blocknum, number_of_blocks,
					 peer->range_first_blocknum,
					 peer->range_end_blocknum
					 - peer->range_first_blocknum);
	}

	start = first_blocknum;
	end = first_blocknum + number_of_blocks;
	/* Trim to make it a subset of what we want. */
	if (start < peer->range_first_blocknum)
		start = peer->range_first_blocknum;
	if (end > peer->range_end_blocknum)
		end = peer->range_end_blocknum;

	/* Have a seat.  It's time for a history lesson in Rusty Screws Up.
	 *
	 * Part 1
	 * ------
	 * The original spec had a field called "complete" which meant
	 * "I believe I have complete knowledge of gossip", with the idea
	 * that lite nodes in future would not set this.
	 *
	 * But I chose a terrible name, and LND mis-implemented the spec,
	 * thinking this was an "end of replies".  If they have multiple
	 * replies, set each one to the *whole* range, with complete=0 except
	 * the last.
	 *
	 * Here we try to accomodate that (pretend we make no progress
	 * until the end)! */
	if (first_blocknum == peer->range_first_blocknum
	    && first_blocknum + number_of_blocks == peer->range_end_blocknum
	    && !sync_complete
	    && tal_bytelen(msg) == 64046) {
		status_unusual("Old LND reply_channel_range detected: result will be truncated!");
	}

	 /*
	  * Part 2
	  * ------
	  * You were supposed to use the first_blocknum + number_of_blocks
	  * to tell when gossip was finished, with the rule being no replies
	  * could overlap, so you could say "I asked for blocks 100-199" and if
	  * you got a reply saying it covered blocks 50-150, you knew that you
	  * still had 49 blocks to receive.
	  *
	  * The field was renamed to `full_information`, and since everyone
	  * did it this way anyway, we insisted the replies be in
	  * non-overlapping ascending order.
	  *
	  * But LND didn't do this, and can actually overlap, since they just
	  * chop them up when they reach length, not by block boundary, so
	  * we had to allow that.
	  *
	  * Reading this implementation gave me envy: it was much simpler than
	  * backing out to a block boundary!
	  *
	  * And what if a single block had so many channel openings that you
	  * couldn't fit it in a single reply?  (This was originally
	  * inconceivable, but with the addition of timestamps and checksums,
	  * is now possible).
	  *
	  * So we decided to make the lie into a truth.  `full_information`
	  * was re-renamed to `sync_complete`, and once everyone has upgraded
	  * we can use that, rather than tallying the block numbers, to
	  * tell if replies are finished.
	  */
	err = append_range_reply(peer, scids, tlvs->timestamps_tlv);
	if (err)
		return err;

	/* Credit peer for answering gossip, so seeker doesn't get upset:
	 * since scids are only 8 bytes, use a discount over normal gossip. */
	peer_supplied_good_gossip(peer->daemon, &peer->id, tal_count(scids) / 20);

	/* Old code used to set this to 1 all the time; not setting it implies
	 * we're talking to an upgraded node. */
	if (!sync_complete) {
		/* We no longer need old heuristic counter. */
		peer->range_blocks_outstanding = 0;
		return NULL;
	}

	/* FIXME: This "how many blocks do we have answers for?" heuristic
	 * can go away once everyone uses sync_complete properly. */
	if (end - start < peer->range_blocks_outstanding) {
		peer->range_blocks_outstanding -= end - start;
		return NULL;
	}

	/* Clear these immediately in case cb want to queue more */
	replies = tal_steal(tmpctx, peer->range_replies);
	cb = peer->query_channel_range_cb;

	peer->range_replies = NULL;
	peer->query_channel_range_cb = NULL;

	cb(peer, first_blocknum, number_of_blocks, replies);
	return NULL;
}

/*~ When we ask about an array of short_channel_ids, we get all channel &
 * node announcements and channel updates which the peer knows.  There's an
 * explicit end packet; this is needed to differentiate between 'I'm slow'
 * and 'I don't know those channels'. */
const u8 *handle_reply_short_channel_ids_end(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 complete;

	if (!fromwire_reply_short_channel_ids_end(msg, &chain, &complete)) {
		return towire_warningfmt(peer, NULL,
					 "Bad reply_short_channel_ids_end %s",
					 tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain)) {
		return towire_warningfmt(peer, NULL,
					 "reply_short_channel_ids_end for bad chain: %s",
					 tal_hex(tmpctx, msg));
	}

	if (!peer->scid_query_outstanding) {
		return towire_warningfmt(peer, NULL,
					 "unexpected reply_short_channel_ids_end: %s",
					 tal_hex(tmpctx, msg));
	}

	peer->scid_query_outstanding = false;
	if (peer->scid_query_cb)
		peer->scid_query_cb(peer, complete);

	/* All good, no error. */
	return NULL;
}

/*~ Arbitrary ordering function of pubkeys.
 *
 * Note that we could use memcmp() here: even if they had somehow different
 * bitwise representations for the same key, we copied them all from struct
 * node which should make them unique.  Even if not (say, a node vanished
 * and reappeared) we'd just end up sending two node_announcement for the
 * same node.
 */
static int pubkey_order(const struct node_id *k1,
			const struct node_id *k2,
			void *unused UNUSED)
{
	return node_id_cmp(k1, k2);
}

static void uniquify_node_ids(struct node_id **ids)
{
	size_t dst, src;

	/* BOLT #7:
	 *   - SHOULD avoid sending duplicate `node_announcements` in
	 *     response to a single `query_short_channel_ids`.
	 */
	/* ccan/asort is a typesafe qsort wrapper: like most ccan modules
	 * it eschews exposing 'void *' pointers and ensures that the
	 * callback function and its arguments match types correctly. */
	asort(*ids, tal_count(*ids), pubkey_order, NULL);

	/* Compact the array */
	for (dst = 0, src = 0; src < tal_count(*ids); src++) {
		if (dst && node_id_eq(&(*ids)[dst-1], &(*ids)[src]))
			continue;
		(*ids)[dst++] = (*ids)[src];
	}

	/* And trim to length, so tal_count() gives correct answer. */
	tal_resize(ids, dst);
}

/* We are fairly careful to avoid the peer DoSing us with channel queries:
 * this routine sends information about a single short_channel_id, unless
 * it's finished all of them. */
static bool maybe_send_query_responses_peer(struct peer *peer)
{
	struct routing_state *rstate = peer->daemon->rstate;
	size_t i, num;
	bool sent = false;

	/* BOLT #7:
	 *
	 *   - MUST respond to each known `short_channel_id`:
	 */
	/* Search for next short_channel_id we know about. */
	num = tal_count(peer->scid_queries);
	for (i = peer->scid_query_idx; !sent && i < num; i++) {
		struct chan *chan;

		chan = get_channel(rstate, &peer->scid_queries[i]);
		if (!chan)
			continue;

		/* BOLT #7:
		 * - if bit 0 of `query_flag` is set:
		 *   - MUST reply with a `channel_announcement`
		 */
		if (peer->scid_query_flags[i] & SCID_QF_ANNOUNCE) {
			queue_peer_from_store(peer, &chan->bcast);
			sent = true;
		}

		/* BOLT #7:
		 * - if bit 1 of `query_flag` is set and it has received a
		 *   `channel_update` from `node_id_1`:
		 *   - MUST reply with the latest `channel_update` for
		 *   `node_id_1`
		 * - if bit 2 of `query_flag` is set and it has received a
		 *   `channel_update` from `node_id_2`:
		 *   - MUST reply with the latest `channel_update` for
		 *   `node_id_2` */
		if ((peer->scid_query_flags[i] & SCID_QF_UPDATE1)
		    && is_halfchan_defined(&chan->half[0])) {
			queue_peer_from_store(peer, &chan->half[0].bcast);
			sent = true;
		}
		if ((peer->scid_query_flags[i] & SCID_QF_UPDATE2)
		    && is_halfchan_defined(&chan->half[1])) {
			queue_peer_from_store(peer, &chan->half[1].bcast);
			sent = true;
		}

		/* BOLT #7:
		 * - if bit 3 of `query_flag` is set and it has received
		 *   a `node_announcement` from `node_id_1`:
		 *   - MUST reply with the latest `node_announcement` for
		 *   `node_id_1`
		 * - if bit 4 of `query_flag` is set and it has received a
		 *    `node_announcement` from `node_id_2`:
		 *   - MUST reply with the latest `node_announcement` for
		 *   `node_id_2` */
		/* Save node ids for later transmission of node_announcement */
		if (peer->scid_query_flags[i] & SCID_QF_NODE1)
			tal_arr_expand(&peer->scid_query_nodes,
				       chan->nodes[0]->id);
		if (peer->scid_query_flags[i] & SCID_QF_NODE2)
			tal_arr_expand(&peer->scid_query_nodes,
				       chan->nodes[1]->id);
	}

	/* Just finished channels?  Remove duplicate nodes. */
	if (peer->scid_query_idx != num && i == num)
		uniquify_node_ids(&peer->scid_query_nodes);

	/* Update index for next time we're called. */
	peer->scid_query_idx = i;

	/* BOLT #7:
	 *
	 *    - if the incoming message does not include `encoded_query_flags`:
	 *      ...
	 *      - MUST follow with any `node_announcement`s for each
	 *      `channel_announcement`
	 *    - otherwise:
	 *      ...
	 *      - if bit 3 of `query_flag` is set and it has received a
	 *        `node_announcement` from `node_id_1`:
	 *        - MUST reply with the latest `node_announcement` for
	 *          `node_id_1`
	 *      - if bit 4 of `query_flag` is set and it has received a
	 *        `node_announcement` from `node_id_2`:
	 *        - MUST reply with the latest `node_announcement` for
	 *          `node_id_2`
	 */
	/* If we haven't sent anything above, we look for the next
	 * node_announcement to send. */
	num = tal_count(peer->scid_query_nodes);
	for (i = peer->scid_query_nodes_idx; !sent && i < num; i++) {
		const struct node *n;

		/* Not every node announces itself (we know it exists because
		 * of a channel_announcement, however) */
		n = get_node(rstate, &peer->scid_query_nodes[i]);
		if (!n || !n->bcast.index)
			continue;

		queue_peer_from_store(peer, &n->bcast);
		sent = true;
	}
	peer->scid_query_nodes_idx = i;

	/* All finished? */
	if (peer->scid_queries
	    && peer->scid_query_idx == tal_count(peer->scid_queries)
	    && peer->scid_query_nodes_idx == num) {
		/* BOLT #7:
		 *
		 * - MUST follow these responses with
		 *   `reply_short_channel_ids_end`.
		 *   - if does not maintain up-to-date channel information for
		 *     `chain_hash`:
		 *      - MUST set `full_information` to 0.
		 *   - otherwise:
		 *      - SHOULD set `full_information` to 1.
		 */
		/* FIXME: We consider ourselves to have complete knowledge. */
		u8 *end = towire_reply_short_channel_ids_end(peer,
							     &chainparams->genesis_blockhash,
							     true);
		queue_peer_msg(peer->daemon, &peer->id, take(end));

		/* We're done!  Clean up so we simply pass-through next time. */
		peer->scid_queries = tal_free(peer->scid_queries);
		peer->scid_query_flags = tal_free(peer->scid_query_flags);
		peer->scid_query_idx = 0;
		peer->scid_query_nodes = tal_free(peer->scid_query_nodes);
		peer->scid_query_nodes_idx = 0;
	}
	return sent;
}

void maybe_send_query_responses(struct daemon *daemon)
{
	struct peer *first, *p;
	struct peer_node_id_map_iter it;

	/* Rotate through, so we don't favor a single peer. */
	p = first = first_random_peer(daemon, &it);
	while (p) {
		if (maybe_send_query_responses_peer(p))
			break;
		p = next_random_peer(daemon, first, &it);
	}
}

bool query_channel_range(struct daemon *daemon,
			 struct peer *peer,
			 u32 first_blocknum, u32 number_of_blocks,
			 enum query_option_flags qflags,
			 void (*cb)(struct peer *,
				    u32, u32,
				    const struct range_query_reply *))
{
	u8 *msg;
	struct tlv_query_channel_range_tlvs *tlvs;

	assert((qflags & ~(QUERY_ADD_TIMESTAMPS|QUERY_ADD_CHECKSUMS)) == 0);
	assert(peer->gossip_queries_feature);
	assert(!peer->range_replies);
	assert(!peer->query_channel_range_cb);

	if (qflags) {
		tlvs = tlv_query_channel_range_tlvs_new(tmpctx);
		tlvs->query_option = tal(tlvs, bigsize_t);
		*tlvs->query_option = qflags;
	} else
		tlvs = NULL;
	status_peer_debug(&peer->id,
			  "sending query_channel_range for blocks %u+%u",
			  first_blocknum, number_of_blocks);

	msg = towire_query_channel_range(NULL, &chainparams->genesis_blockhash,
					 first_blocknum, number_of_blocks,
					 tlvs);
	queue_peer_msg(peer->daemon, &peer->id, take(msg));
	peer->range_first_blocknum = first_blocknum;
	peer->range_end_blocknum = first_blocknum + number_of_blocks;
	peer->range_blocks_outstanding = number_of_blocks;
	peer->range_replies = tal_arr(peer, struct range_query_reply, 0);
	peer->query_channel_range_cb = cb;

	return true;
}

/* This is a testing hack to allow us to artificially lower the maximum bytes
 * of short_channel_ids we'll encode, using dev_set_max_scids_encode_size. */
void dev_set_max_scids_encode_size(struct daemon *daemon, const u8 *msg)
{
	assert(daemon->developer);
	if (!fromwire_gossipd_dev_set_max_scids_encode_size(msg,
							   &dev_max_encoding_bytes))
		master_badmsg(WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE, msg);

	status_debug("Set max_scids_encode_bytes to %u", dev_max_encoding_bytes);
}
