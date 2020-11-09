/* Routines to generate and handle gossip query messages */
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/tal/tal.h>
#include <common/daemon_conn.h>
#include <common/decode_array.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <gossipd/gossip_generation.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/queries.h>
#include <gossipd/routing.h>
#include <gossipd/seeker.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <zlib.h>

#if DEVELOPER
static u32 max_encoding_bytes = -1U;
#endif

/* BOLT #7:
 *
 * There are several messages which contain a long array of
 * `short_channel_id`s (called `encoded_short_ids`) so we utilize a
 * simple compression scheme: the first byte indicates the encoding, the
 * rest contains the data.
 */
static u8 *encoding_start(const tal_t *ctx)
{
	return tal_arr(ctx, u8, 0);
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

/* Greg Maxwell asked me privately about using zlib for communicating a set,
 * and suggested that we'd be better off using Golomb-Rice coding a-la BIP
 * 158.  However, naively using Rice encoding isn't a win: we have to get
 * more complex and use separate streams.  The upside is that it's between
 * 2 and 5 times smaller (assuming optimal Rice encoding + gzip).  We can add
 * that later. */
static u8 *zencode(const tal_t *ctx, const u8 *scids, size_t len)
{
	u8 *z;
	int err;
	unsigned long compressed_len = len;

#ifdef ZLIB_EVEN_IF_EXPANDS
	/* Needed for test vectors */
	compressed_len = 128 * 1024;
#endif
	/* Prefer to fail if zlib makes it larger */
	z = tal_arr(ctx, u8, compressed_len);
	err = compress2(z, &compressed_len, scids, len, Z_DEFAULT_COMPRESSION);
	if (err == Z_OK) {
		tal_resize(&z, compressed_len);
		return z;
	}
	return NULL;
}

/* Try compressing *encoded: fails if result would be longer.
 * @off is offset to place result in *encoded.
 */
static bool encoding_end_zlib(u8 **encoded, size_t off)
{
	u8 *z;
	size_t len = tal_count(*encoded);

	z = zencode(tmpctx, *encoded, len);
	if (!z)
		return false;

	/* Successful: copy over and trim */
	tal_resize(encoded, off + tal_count(z));
	memcpy(*encoded + off, z, tal_count(z));

	tal_free(z);
	return true;
}

static void encoding_end_no_compress(u8 **encoded, size_t off)
{
	size_t len = tal_count(*encoded);

	tal_resize(encoded, off + len);
	memmove(*encoded + off, *encoded, len);
}

/* Once we've assembled it, try compressing.
 * Prepends encoding type to @encoding. */
static bool encoding_end_prepend_type(u8 **encoded, size_t max_bytes)
{
	if (encoding_end_zlib(encoded, 1))
		**encoded = ARR_ZLIB;
	else {
		encoding_end_no_compress(encoded, 1);
		**encoded = ARR_UNCOMPRESSED;
	}

#if DEVELOPER
	if (tal_count(*encoded) > max_encoding_bytes)
		return false;
#endif
	return tal_count(*encoded) <= max_bytes;
}

/* Try compressing, leaving type external */
static bool encoding_end_external_type(u8 **encoded, u8 *type, size_t max_bytes)
{
	if (encoding_end_zlib(encoded, 0))
		*type = ARR_ZLIB;
	else {
		encoding_end_no_compress(encoded, 0);
		*type = ARR_UNCOMPRESSED;
	}

	return tal_count(*encoded) <= max_bytes;
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

	encoded = encoding_start(tmpctx);
	for (size_t i = 0; i < tal_count(scids); i++) {
		/* BOLT #7:
		 *
		 * Encoding types:
		 * * `0`: uncompressed array of `short_channel_id` types, in
		 *   ascending order.
		 * * `1`: array of `short_channel_id` types, in ascending order
		 */
		assert(i == 0 || scids[i].u64 > scids[i-1].u64);
		encoding_add_short_channel_id(&encoded, &scids[i]);
	}

	if (!encoding_end_prepend_type(&encoded, max_encoded_bytes)) {
		status_broken("query_short_channel_ids: %zu is too many",
			      tal_count(scids));
		return false;
	}

	if (query_flags) {
		struct tlv_query_short_channel_ids_tlvs_query_flags *tlvq;
		tlvs = tlv_query_short_channel_ids_tlvs_new(tmpctx);
		tlvq = tlvs->query_flags = tal(tlvs,
			   struct tlv_query_short_channel_ids_tlvs_query_flags);
 		tlvq->encoded_query_flags = encoding_start(tlvq);
		for (size_t i = 0; i < tal_count(query_flags); i++)
			encoding_add_query_flag(&tlvq->encoded_query_flags,
						query_flags[i]);

		max_encoded_bytes -= tal_bytelen(encoded);
		if (!encoding_end_external_type(&tlvq->encoded_query_flags,
						&tlvq->encoding_type,
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
	queue_peer_msg(peer, take(msg));
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
	struct tlv_query_short_channel_ids_tlvs *tlvs
		= tlv_query_short_channel_ids_tlvs_new(tmpctx);

	if (!fromwire_query_short_channel_ids(tmpctx, msg, &chain, &encoded,
					      tlvs)) {
		return towire_errorfmt(peer, NULL,
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
		 *      - MAY fail the connection
		 */
		flags = decode_scid_query_flags(tmpctx, tlvs->query_flags);
		if (!flags) {
			return towire_errorfmt(peer, NULL,
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
	 *    - MAY fail the connection.
	 */
	if (peer->scid_queries || peer->scid_query_nodes) {
		return towire_errorfmt(peer, NULL,
				       "Bad concurrent query_short_channel_ids");
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		return towire_errorfmt(peer, NULL,
				       "Bad query_short_channel_ids encoding %s",
				       tal_hex(tmpctx, encoded));
	}

	/* BOLT #7:
	 *
	 * The receiver:
	 *...
	 *    - if `encoded_query_flags` does not decode to exactly one flag per
	 *      `short_channel_id`:
	 *      - MAY fail the connection.
	 */
	if (!flags) {
		/* Pretend they asked for everything. */
		flags = tal_arr(tmpctx, bigsize_t, tal_count(scids));
		memset(flags, 0xFF, tal_bytelen(flags));
	} else {
		if (tal_count(flags) != tal_count(scids)) {
			return towire_errorfmt(peer, NULL,
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

	/* Notify the daemon_conn-write loop to invoke create_next_scid_reply */
	daemon_conn_wake(peer->dc);
	return NULL;
}

/*~ We can send multiple replies when the peer queries for all channels in
 * a given range of blocks; each one indicates the range of blocks it covers. */
static void reply_channel_range(struct peer *peer,
				u32 first_blocknum, u32 number_of_blocks,
				const u8 *encoded_scids,
				struct tlv_reply_channel_range_tlvs_timestamps_tlv *timestamps,
				struct channel_update_checksums *checksums)
{
	/* BOLT #7:
	 *
	 * - MUST respond with one or more `reply_channel_range`:
	 *   - MUST set with `chain_hash` equal to that of `query_channel_range`,
	 *   - MUST limit `number_of_blocks` to the maximum number of blocks
	 *     whose results could fit in `encoded_short_ids`
	 *   - if does not maintain up-to-date channel information for
	 *     `chain_hash`:
	 *     - MUST set `full_information` to 0.
	 *   - otherwise:
	 *     - SHOULD set `full_information` to 1.
	 */
 	struct tlv_reply_channel_range_tlvs *tlvs
 		= tlv_reply_channel_range_tlvs_new(tmpctx);
	tlvs->timestamps_tlv = timestamps;
	tlvs->checksums_tlv = checksums;

	u8 *msg = towire_reply_channel_range(NULL,
					     &chainparams->genesis_blockhash,
					     first_blocknum,
					     number_of_blocks,
					     1, encoded_scids, tlvs);
	queue_peer_msg(peer, take(msg));
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

	if (!is_chan_public(chan) || !is_halfchan_defined(hc)) {
		*tstamp = *csum = 0;
	} else {
		const u8 *update = gossip_store_get(tmpctx, rstate->gs,
						    hc->bcast.index);
		*tstamp = hc->bcast.timestamp;
		*csum = crc32_of_update(update);
	}
}

/* FIXME: This assumes that the tlv type encodes into 1 byte! */
static size_t tlv_len(const tal_t *msg)
{
	return 1 + bigsize_len(tal_count(msg)) + tal_count(msg);
}

/*~ When we need to send an array of channels, it might go over our 64k packet
 * size.  If it doesn't, we recurse, splitting in two, etc.  Each message
 * indicates what blocks it contains, so the recipient knows when we're
 * finished.
 *
 * tail_blocks is the empty blocks at the end, in case they asked for all
 * blocks to 4 billion.
 */
static bool queue_channel_ranges(struct peer *peer,
				 u32 first_blocknum, u32 number_of_blocks,
				 u32 tail_blocks,
				 enum query_option_flags query_option_flags)
{
	struct routing_state *rstate = peer->daemon->rstate;
	u8 *encoded_scids = encoding_start(tmpctx);
	struct tlv_reply_channel_range_tlvs_timestamps_tlv *tstamps;
	struct channel_update_checksums *csums;
	struct short_channel_id scid;
	bool scid_ok;

	/* BOLT #7:
	 *
	 * 1. type: 264 (`reply_channel_range`) (`gossip_queries`)
	 * 2. data:
	 *   * [`chain_hash`:`chain_hash`]
	 *   * [`u32`:`first_blocknum`]
	 *   * [`u32`:`number_of_blocks`]
	 *   * [`byte`:`full_information`]
	 *   * [`u16`:`len`]
	 *   * [`len*byte`:`encoded_short_ids`]
	 */
	const size_t reply_overhead = 32 + 4 + 4 + 1 + 2;
	const size_t max_encoded_bytes = 65535 - 2 - reply_overhead;
	size_t extension_bytes;

	if (query_option_flags & QUERY_ADD_TIMESTAMPS) {
		tstamps = tal(tmpctx,
			      struct tlv_reply_channel_range_tlvs_timestamps_tlv);
		tstamps->encoded_timestamps = encoding_start(tstamps);
	} else
		tstamps = NULL;

	if (query_option_flags & QUERY_ADD_CHECKSUMS) {
		csums = tal_arr(tmpctx, struct channel_update_checksums, 0);
	} else
		csums = NULL;

	/* Avoid underflow: we don't use block 0 anyway */
	if (first_blocknum == 0)
		scid_ok = mk_short_channel_id(&scid, 1, 0, 0);
	else
		scid_ok = mk_short_channel_id(&scid, first_blocknum, 0, 0);
	scid.u64--;
	if (!scid_ok)
		return false;

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
		u32 blocknum = short_channel_id_blocknum(&scid);
		if (blocknum >= first_blocknum + number_of_blocks)
			break;

		/* FIXME: Store csum in header. */
		chan = get_channel(rstate, &scid);
		if (!is_chan_public(chan))
			continue;

		encoding_add_short_channel_id(&encoded_scids, &scid);

		get_checksum_and_timestamp(rstate, chan, 0,
					   &ts.timestamp_node_id_1,
					   &cs.checksum_node_id_1);
		get_checksum_and_timestamp(rstate, chan, 1,
					   &ts.timestamp_node_id_2,
					   &cs.checksum_node_id_2);

		if (csums)
			tal_arr_expand(&csums, cs);
		if (tstamps)
			encoding_add_timestamps(&tstamps->encoded_timestamps,
						&ts);
	}

	extension_bytes = 0;

	/* If either of these can't fit in max_encoded_bytes by itself,
	 * it's over. */
	if (csums) {
		extension_bytes += tlv_len(csums);
	}

	if (tstamps) {
		if (!encoding_end_external_type(&tstamps->encoded_timestamps,
						&tstamps->encoding_type,
						max_encoded_bytes))
			goto wont_fit;
		/* 1 byte for encoding_type, too */
		extension_bytes += 1 + tlv_len(tstamps->encoded_timestamps);
	}

	/* If we can encode that, fine: send it */
	if (extension_bytes <= max_encoded_bytes
	    && encoding_end_prepend_type(&encoded_scids,
					 max_encoded_bytes - extension_bytes)) {
		reply_channel_range(peer, first_blocknum,
				    number_of_blocks + tail_blocks,
				    encoded_scids,
				    tstamps, csums);
		return true;
	}

wont_fit:
	/* It wouldn't all fit: divide in half */
	/* We assume we can always send one block! */
	if (number_of_blocks <= 1) {
		/* We always assume we can send 1 blocks worth */
		status_broken("Could not fit scids for single block %u",
			      first_blocknum);
		return false;
	}
	status_debug("queue_channel_ranges full: splitting %u+%u and %u+%u(+%u)",
		     first_blocknum,
		     number_of_blocks / 2,
		     first_blocknum + number_of_blocks / 2,
		     number_of_blocks - number_of_blocks / 2,
		     tail_blocks);
	return queue_channel_ranges(peer, first_blocknum, number_of_blocks / 2,
				    0, query_option_flags)
		&& queue_channel_ranges(peer, first_blocknum + number_of_blocks / 2,
					number_of_blocks - number_of_blocks / 2,
					tail_blocks, query_option_flags);
}

/*~ The peer can ask for all channels in a series of blocks.  We reply with one
 * or more messages containing the short_channel_ids. */
const u8 *handle_query_channel_range(struct peer *peer, const u8 *msg)
{
	struct routing_state *rstate = peer->daemon->rstate;
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum, number_of_blocks, tail_blocks;
	struct short_channel_id last_scid;
	enum query_option_flags query_option_flags;
	struct tlv_query_channel_range_tlvs *tlvs
		= tlv_query_channel_range_tlvs_new(msg);

	if (!fromwire_query_channel_range(msg, &chain_hash,
					  &first_blocknum, &number_of_blocks,
					  tlvs)) {
		return towire_errorfmt(peer, NULL,
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
		queue_peer_msg(peer, take(end));
		return NULL;
	}

	/* If they ask for number_of_blocks UINTMAX, and we have to divide
	 * and conquer, we'll do a lot of unnecessary work.  Cap it at the
	 * last value we have, then send an empty reply. */
	if (uintmap_last(&rstate->chanmap, &last_scid.u64)) {
		u32 last_block = short_channel_id_blocknum(&last_scid);

		/* u64 here avoids overflow on number_of_blocks
		   UINTMAX for example */
		if ((u64)first_blocknum + number_of_blocks > last_block) {
			tail_blocks = first_blocknum + number_of_blocks
				- last_block - 1;
			number_of_blocks -= tail_blocks;
		} else
			tail_blocks = 0;
	} else
		tail_blocks = 0;

	if (!queue_channel_ranges(peer, first_blocknum, number_of_blocks,
				  tail_blocks, query_option_flags))
		return towire_errorfmt(peer, NULL,
				       "Invalid query_channel_range %u+%u",
				       first_blocknum, number_of_blocks + tail_blocks);

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
	const static struct channel_update_timestamps zero_ts;

	if (timestamps_tlv) {
		ts = decode_channel_update_timestamps(tmpctx,
						      timestamps_tlv);
		if (!ts || tal_count(ts) != tal_count(scids)) {
			return towire_errorfmt(peer, NULL,
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
	u8 complete;
	u32 first_blocknum, number_of_blocks, start, end;
	u8 *encoded;
	struct short_channel_id *scids;
	const struct range_query_reply *replies;
	const u8 *err;
	void (*cb)(struct peer *peer,
		   u32 first_blocknum, u32 number_of_blocks,
		   const struct range_query_reply *replies,
		   bool complete);
	struct tlv_reply_channel_range_tlvs *tlvs
		= tlv_reply_channel_range_tlvs_new(tmpctx);

	if (!fromwire_reply_channel_range(tmpctx, msg, &chain, &first_blocknum,
					  &number_of_blocks, &complete,
					  &encoded, tlvs)) {
		return towire_errorfmt(peer, NULL,
				       "Bad reply_channel_range w/tlvs %s",
				       tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain)) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range for bad chain: %s",
				       tal_hex(tmpctx, msg));
	}

	if (!peer->range_replies) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range without query: %s",
				       tal_hex(tmpctx, msg));
	}

	/* Beware overflow! */
	if (first_blocknum + number_of_blocks < first_blocknum) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range invalid %u+%u",
				       first_blocknum, number_of_blocks);
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		return towire_errorfmt(peer, NULL,
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
	 *
	 * The receiver of `query_channel_range`:
	 *...
	 * - the first `reply_channel_range` message:
	 *   - MUST set `first_blocknum` less than or equal to the
	 *     `first_blocknum` in `query_channel_range`
	 *   - MUST set `first_blocknum` plus `number_of_blocks` greater than
	 *     `first_blocknum` in `query_channel_range`.
	 * - successive `reply_channel_range` message:
	 *   - MUST set `first_blocknum` to the previous `first_blocknum`
	 *     plus `number_of_blocks`.
	 * - the final `reply_channel_range` message:
	 *   - MUST have `first_blocknum` plus `number_of_blocks` equal or
	 *     greater than the `query_channel_range` `first_blocknum` plus
	 *     `number_of_blocks`.
	 */
	/* ie. They can be outside range we asked, but they must overlap! */
	if (first_blocknum + number_of_blocks <= peer->range_first_blocknum
	    || first_blocknum >= peer->range_end_blocknum) {
		return towire_errorfmt(peer, NULL,
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

	/* LND mis-implemented the spec.  If they have multiple replies, set
	 * each one to the *whole* range, with complete=0 except the last.
	 * Try to accomodate that (pretend we make no progress until the
	 * end)! */
	if (first_blocknum == peer->range_first_blocknum
	    && first_blocknum + number_of_blocks == peer->range_end_blocknum
	    && !complete
	    && tal_bytelen(msg) == 64046) {
		status_unusual("Old LND reply_channel_range detected: result will be truncated!");
	}

	/* They're supposed to send them in order, but LND actually
	 * can overlap. */
	if (first_blocknum != peer->range_prev_end_blocknum + 1
	    && first_blocknum != peer->range_prev_end_blocknum) {
		return towire_errorfmt(peer, NULL,
				       "reply_channel_range %u+%u previous end was block %u",
				       first_blocknum, number_of_blocks,
				       peer->range_prev_end_blocknum);
	}
	peer->range_prev_end_blocknum = end;

	err = append_range_reply(peer, scids, tlvs->timestamps_tlv);
	if (err)
		return err;

	/* Credit peer for answering gossip, so seeker doesn't get upset:
	 * since scids are only 8 bytes, use a discount over normal gossip. */
	peer_supplied_good_gossip(peer, tal_count(scids) / 20);

	/* Still more to go? */
	if (peer->range_prev_end_blocknum < peer->range_end_blocknum)
		return NULL;

	/* Clear these immediately in case cb want to queue more */
	replies = tal_steal(tmpctx, peer->range_replies);
	cb = peer->query_channel_range_cb;

	peer->range_replies = NULL;
	peer->query_channel_range_cb = NULL;

	cb(peer, first_blocknum, number_of_blocks, replies, complete);
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
		return towire_errorfmt(peer, NULL,
				       "Bad reply_short_channel_ids_end %s",
				       tal_hex(tmpctx, msg));
	}

	if (!bitcoin_blkid_eq(&chainparams->genesis_blockhash, &chain)) {
		return towire_errorfmt(peer, NULL,
				       "reply_short_channel_ids_end for bad chain: %s",
				       tal_hex(tmpctx, msg));
	}

	if (!peer->scid_query_outstanding) {
		return towire_errorfmt(peer, NULL,
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
void maybe_send_query_responses(struct peer *peer)
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
		if (!chan || !is_chan_public(chan))
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
		queue_peer_msg(peer, take(end));

		/* We're done!  Clean up so we simply pass-through next time. */
		peer->scid_queries = tal_free(peer->scid_queries);
		peer->scid_query_flags = tal_free(peer->scid_query_flags);
		peer->scid_query_idx = 0;
		peer->scid_query_nodes = tal_free(peer->scid_query_nodes);
		peer->scid_query_nodes_idx = 0;
	}
}

bool query_channel_range(struct daemon *daemon,
			 struct peer *peer,
			 u32 first_blocknum, u32 number_of_blocks,
			 enum query_option_flags qflags,
			 void (*cb)(struct peer *peer,
				    u32 first_blocknum, u32 number_of_blocks,
				    const struct range_query_reply *replies,
				    bool complete))
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
	queue_peer_msg(peer, take(msg));
	peer->range_first_blocknum = first_blocknum;
	peer->range_end_blocknum = first_blocknum + number_of_blocks;
	peer->range_prev_end_blocknum = first_blocknum-1;
	peer->range_replies = tal_arr(peer, struct range_query_reply, 0);
	peer->query_channel_range_cb = cb;

	return true;
}

#if DEVELOPER
/* This is a testing hack to allow us to artificially lower the maximum bytes
 * of short_channel_ids we'll encode, using dev_set_max_scids_encode_size. */
struct io_plan *dev_set_max_scids_encode_size(struct io_conn *conn,
					      struct daemon *daemon,
					      const u8 *msg)
{
	if (!fromwire_gossipd_dev_set_max_scids_encode_size(msg,
							   &max_encoding_bytes))
		master_badmsg(WIRE_GOSSIPD_DEV_SET_MAX_SCIDS_ENCODE_SIZE, msg);

	status_debug("Set max_scids_encode_bytes to %u", max_encoding_bytes);
	return daemon_conn_read_next(conn, daemon->master);
}
#endif /* DEVELOPER */
