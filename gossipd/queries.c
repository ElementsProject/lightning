/* Routines to generate gossip query messages */
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
#include <gossipd/gossip_store.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/gossmap_manage.h>
#include <gossipd/queries.h>

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

/* Marshal a single query flag (we don't query, so not currently used) */
static void encoding_add_query_flag(u8 **encoded, bigsize_t flag)
{
	towire_bigsize(encoded, flag);
}

static bool encoding_end(const u8 *encoded, size_t max_bytes)
{
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
	 * 1. type: 261 (`query_short_channel_ids`)
	 * 2. data:
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`u16`:`len`]
	 *     * [`len*byte`:`encoded_short_ids`]
	 */
	const size_t reply_overhead = 32 + 2;
	size_t max_encoded_bytes = 65535 - 2 - reply_overhead;

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
	 *  - SHOULD NOT send this to a peer which does not offer `gossip_queries`.
	 *  - MUST NOT send `query_short_channel_ids` if it has sent a previous
	 *   `query_short_channel_ids` to this peer and not received
	 *   `reply_short_channel_ids_end`.
	 */
	/* Don't query if they have no useful gossip */
	if (!peer->gossip_queries_feature)
		return false;

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
		encoding_add_short_channel_id(&encoded, scids[i]);
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
	peer_supplied_query_response(peer->daemon, &peer->id, tal_count(scids) / 20);

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
