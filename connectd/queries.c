/* Routines to handle gossip query messages */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/crc32c/crc32c.h>
#include <common/daemon_conn.h>
#include <common/decode_array.h>
#include <common/gossmap.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/multiplex.h>
#include <connectd/queries.h>
#include <wire/peer_wire.h>

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
					  struct short_channel_id scid)
{
	towire_short_channel_id(encoded, scid);
}

/* Marshal a single channel_update_timestamps */
static void encoding_add_timestamps(u8 **encoded,
				    const struct channel_update_timestamps *ts)
{
	towire_channel_update_timestamps(encoded, ts);
}

static bool encoding_end(const u8 *encoded, size_t max_bytes)
{
	if (tal_count(encoded) > dev_max_encoding_bytes)
		return false;
	return tal_count(encoded) <= max_bytes;
}

/* Convenience function to send warning to a peer */
static void warning_to_peer(struct peer *peer, const char *fmt, ...)
{
	va_list ap;
	u8 *msg;

	va_start(ap, fmt);
	msg = towire_warningfmtv(NULL, NULL, fmt, ap);
	va_end(ap);

	inject_peer_msg(peer, take(msg));
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
bool maybe_send_query_responses(struct peer *peer, struct gossmap *gossmap)
{
	size_t i, num;
	bool sent = false;
	const u8 *msg;

	/* BOLT #7:
	 *
	 *   - MUST respond to each known `short_channel_id`:
	 */
	/* Search for next short_channel_id we know about. */
	num = tal_count(peer->scid_queries);
	for (i = peer->scid_query_idx; !sent && i < num; i++) {
		struct gossmap_chan *chan;
		struct gossmap_node *node;
		struct node_id node_id;

		chan = gossmap_find_chan(gossmap, &peer->scid_queries[i]);
		if (!chan)
			continue;

		/* BOLT #7:
		 * - if bit 0 of `query_flag` is set:
		 *   - MUST reply with a `channel_announcement`
		 */
		if (peer->scid_query_flags[i] & SCID_QF_ANNOUNCE) {
			msg = gossmap_chan_get_announce(NULL, gossmap, chan);
			inject_peer_msg(peer, take(msg));
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
		    && gossmap_chan_set(chan, 0)) {
			msg = gossmap_chan_get_update(NULL, gossmap, chan, 0);
			inject_peer_msg(peer, take(msg));
			sent = true;
		}
		if ((peer->scid_query_flags[i] & SCID_QF_UPDATE2)
		    && gossmap_chan_set(chan, 1)) {
			msg = gossmap_chan_get_update(NULL, gossmap, chan, 1);
			inject_peer_msg(peer, take(msg));
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
		if (peer->scid_query_flags[i] & SCID_QF_NODE1) {
			node = gossmap_nth_node(gossmap, chan, 0);
			gossmap_node_get_id(gossmap, node, &node_id);
			tal_arr_expand(&peer->scid_query_nodes, node_id);
		}
		if (peer->scid_query_flags[i] & SCID_QF_NODE2) {
			node = gossmap_nth_node(gossmap, chan, 1);
			gossmap_node_get_id(gossmap, node, &node_id);
			tal_arr_expand(&peer->scid_query_nodes, node_id);
		}
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
		const struct gossmap_node *n;

		/* Not every node announces itself (we know it exists because
		 * of a channel_announcement, however) */
		n = gossmap_find_node(gossmap, &peer->scid_query_nodes[i]);
		if (!n || !gossmap_node_announced(n))
			continue;

		msg = gossmap_node_get_announce(NULL, gossmap, n);
		inject_peer_msg(peer, take(msg));
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
		inject_peer_msg(peer, take(end));

		/* We're done!  Clean up so we simply pass-through next time. */
		peer->scid_queries = tal_free(peer->scid_queries);
		peer->scid_query_flags = tal_free(peer->scid_query_flags);
		peer->scid_query_idx = 0;
		peer->scid_query_nodes = tal_free(peer->scid_query_nodes);
		peer->scid_query_nodes_idx = 0;
	}
	return sent;
}

/* The peer can ask about an array of short channel ids: we don't assemble the
 * reply immediately but process them one at a time in dump_gossip which is
 * called when there's nothing more important to send. */
void handle_query_short_channel_ids(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain;
	u8 *encoded;
	struct short_channel_id *scids;
	bigsize_t *flags;
	struct tlv_query_short_channel_ids_tlvs *tlvs;

	if (!fromwire_query_short_channel_ids(tmpctx, msg, &chain, &encoded,
					      &tlvs)) {
		warning_to_peer(peer,
				"Bad query_short_channel_ids w/tlvs %s",
				tal_hex(tmpctx, msg));
		return;
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
			warning_to_peer(peer,
					"Bad query_short_channel_ids query_flags %s",
					tal_hex(tmpctx, msg));
			return;
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
				  fmt_bitcoin_blkid(tmpctx, &chain));
		inject_peer_msg(peer,
				take(towire_reply_short_channel_ids_end(NULL, &chain, 0)));
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
		warning_to_peer(peer, "Bad concurrent query_short_channel_ids");
		return;
	}

	scids = decode_short_ids(tmpctx, encoded);
	if (!scids) {
		warning_to_peer(peer, "Bad query_short_channel_ids encoding %s",
				tal_hex(tmpctx, encoded));
		return;
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
			warning_to_peer(peer,
					"Bad query_short_channel_ids flags count %zu scids %zu",
					tal_count(flags), tal_count(scids));
			return;
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

	/* Notify the write loop to invoke maybe_send_query_responses */
	io_wake(peer->peer_outq);
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
		encoding_add_short_channel_id(&encoded_scids, scids[i]);
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
	inject_peer_msg(peer, take(msg));
}

/* Helper to get non-signature, non-timestamp parts of (valid!) channel_update */
static void get_cupdate_parts(const u8 *channel_update,
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

/* BOLT #7:
 * Where:
 * * `timestamp_node_id_1` is the timestamp of the `channel_update` for `node_id_1`, or 0 if there was no `channel_update` from that node.
 * * `timestamp_node_id_2` is the timestamp of the `channel_update` for `node_id_2`, or 0 if there was no `channel_update` from that node.
 */
static u32 get_timestamp(struct gossmap *gossmap,
			 const struct gossmap_chan *chan,
			 int dir)
{
	u32 timestamp;
	if (!gossmap_chan_set(chan, dir))
		return 0;

	gossmap_chan_get_update_details(gossmap, chan, dir, &timestamp,
					NULL, NULL, NULL, NULL, NULL, NULL);
	return timestamp;
}

/* BOLT #7:
 * Where:
 * * `checksum_node_id_1` is the checksum of the `channel_update` for
 *   `node_id_1`, or 0 if there was no `channel_update` from that
 *   node.
 * * `checksum_node_id_2` is the checksum of the `channel_update` for
 *   `node_id_2`, or 0 if there was no `channel_update` from that
 *   node.
 */
static u32 get_checksum(struct gossmap *gossmap,
			const struct gossmap_chan *chan,
			int dir)
{
	u8 *cupdate;

	cupdate = gossmap_chan_get_update(tmpctx, gossmap, chan, dir);
	if (!cupdate)
		return 0;
	return crc32_of_update(cupdate);
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
	 * 1. type: 264 (`reply_channel_range`)
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
					     struct daemon *daemon,
					     u32 first_blocknum, u32 number_of_blocks,
					     enum query_option_flags query_option_flags,
					     struct channel_update_timestamps **tstamps,
					     struct channel_update_checksums **csums)
{
	struct short_channel_id *scids;
	u32 end_block;
	struct gossmap *gossmap = get_gossmap(daemon);

	scids = tal_arr(ctx, struct short_channel_id, 0);
	if (query_option_flags & QUERY_ADD_TIMESTAMPS)
		*tstamps = tal_arr(ctx, struct channel_update_timestamps, 0);
	else
		*tstamps = NULL;
	if (query_option_flags & QUERY_ADD_CHECKSUMS)
		*csums = tal_arr(ctx, struct channel_update_checksums, 0);
	else
		*csums = NULL;

	if (number_of_blocks == 0)
		return NULL;

	/* Fix up number_of_blocks to avoid overflow. */
	end_block = first_blocknum + number_of_blocks - 1;
	if (end_block < first_blocknum)
		end_block = UINT_MAX;

	/* We used to maintain a uintmap of channels by scid, but
	 * we no longer do, making this more expensive.  But still
	 * not too bad, since it's usually in-mem */
	for (size_t i = 0; i < gossmap_max_chan_idx(gossmap); i++) {
		struct gossmap_chan *chan = gossmap_chan_byidx(gossmap, i);
		struct short_channel_id scid;

		if (!chan)
			continue;

		/* By policy, we don't give announcements here with no
		 * channel_updates */
		if (!gossmap_chan_set(chan, 0) && !gossmap_chan_set(chan, 1)) {
			continue;
		}

		scid = gossmap_chan_scid(gossmap, chan);
		if (short_channel_id_blocknum(scid) < first_blocknum
		    || short_channel_id_blocknum(scid) > end_block) {
			continue;
		}

		tal_arr_expand(&scids, scid);

		if (*tstamps) {
			struct channel_update_timestamps ts;

			ts.timestamp_node_id_1 = get_timestamp(gossmap, chan, 0);
			ts.timestamp_node_id_2 = get_timestamp(gossmap, chan, 1);
			tal_arr_expand(tstamps, ts);
		}

		if (*csums) {
			struct channel_update_checksums cs;
			cs.checksum_node_id_1 = get_checksum(gossmap, chan, 0);
			cs.checksum_node_id_2 = get_checksum(gossmap, chan, 1);
			tal_arr_expand(csums, cs);
		}
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
	struct daemon *daemon = peer->daemon;
	struct channel_update_timestamps *tstamps;
	struct channel_update_checksums *csums;
	struct short_channel_id *scids;
	size_t off, limit;

	scids = gather_range(tmpctx, daemon, first_blocknum, number_of_blocks,
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
			while (short_channel_id_blocknum(scids[off + n - 1])
			       == short_channel_id_blocknum(scids[off + limit])) {
				/* We assume one block doesn't have limit #
				 * channels.  If it does, we have to violate
				 * spec and send over multiple blocks. */
				if (n == 0) {
					status_broken("reply_channel_range: "
						      "could not fit %zu scids for %u!",
						      limit,
						      short_channel_id_blocknum(scids[off + n - 1]));
					n = limit;
					break;
				}
				n--;
			}
			/* Get *next* channel, add num blocks */
			this_num_blocks
				= short_channel_id_blocknum(scids[off + n])
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
void handle_query_channel_range(struct peer *peer, const u8 *msg)
{
	struct bitcoin_blkid chain_hash;
	u32 first_blocknum, number_of_blocks;
	enum query_option_flags query_option_flags;
	struct tlv_query_channel_range_tlvs *tlvs;

	if (!fromwire_query_channel_range(msg, msg, &chain_hash,
					  &first_blocknum, &number_of_blocks,
					  &tlvs)) {
		warning_to_peer(peer,
				"Bad query_channel_range w/tlvs %s",
				tal_hex(tmpctx, msg));
		return;
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
				  fmt_bitcoin_blkid(tmpctx, &chain_hash));
		u8 *end = towire_reply_channel_range(NULL, &chain_hash, first_blocknum,
		                                     number_of_blocks, false, NULL, NULL);
		inject_peer_msg(peer, take(end));
		return;
	}

	/* Fix up number_of_blocks to avoid overflow. */
	if (first_blocknum + number_of_blocks < first_blocknum)
		number_of_blocks = UINT_MAX - first_blocknum;

	queue_channel_ranges(peer, first_blocknum, number_of_blocks,
			     query_option_flags);
}

/* This is a testing hack to allow us to artificially lower the maximum bytes
 * of short_channel_ids we'll encode, using dev_set_max_scids_encode_size. */
void dev_set_max_scids_encode_size(struct daemon *daemon, const u8 *msg)
{
	assert(daemon->developer);
	if (!fromwire_connectd_dev_set_max_scids_encode_size(msg,
							   &dev_max_encoding_bytes))
		master_badmsg(WIRE_CONNECTD_DEV_SET_MAX_SCIDS_ENCODE_SIZE, msg);

	status_debug("Set max_scids_encode_bytes to %u", dev_max_encoding_bytes);
}
