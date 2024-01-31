#include "config.h"
#include <bitcoin/script.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/gossip_store.h>
#include <common/gossmap.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_wiregen.h>
#include <gossipd/gossmap_manage.h>
#include <gossipd/seeker.h>
#include <gossipd/sigcheck.h>
#include <gossipd/txout_failures.h>
#include <string.h>

struct pending_cannounce {
	const u8 *scriptpubkey;
	const u8 *channel_announcement;
	const struct node_id *source_peer;
};

struct pending_cupdate {
	struct short_channel_id scid;
	secp256k1_ecdsa_signature signature;
	u8 message_flags;
	u8 channel_flags;
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum_msat, htlc_maximum_msat;
	u32 fee_base_msat, fee_proportional_millionths;
	u32 timestamp;
	const u8 *update;
	const struct node_id *source_peer;
};

struct pending_nannounce {
	struct node_id node_id;
	u32 timestamp;
	const u8 *nannounce;
	const struct node_id *source_peer;
};

struct dying_channel {
	struct short_channel_id scid;
	/* Offset of dying marker in the gossip_store */
	u64 gossmap_offset;
	u32 deadline_blockheight;
};

struct cannounce_map {
	UINTMAP(struct pending_cannounce *) map;
	size_t count;

	/* Name, for flood reporting */
	const char *name;
	bool flood_reported;
};

struct gossmap_manage {
	struct daemon *daemon;

	/* For us to write to gossip_store */
	int fd;

	/* gossip map itself (access via gossmap_manage_get_gossmap, so it's fresh!) */
	struct gossmap *raw_gossmap;

	/* Announcements we're checking, indexed by scid */
	struct cannounce_map pending_ann_map;

	/* Updates we've deferred for above */
	struct pending_cupdate **pending_cupdates;

	/* Announcements which are too early to check. */
	struct cannounce_map early_ann_map;
	struct pending_cupdate **early_cupdates;

	/* Node announcements (waiting for a pending_cannounce maybe) */
	struct pending_nannounce **pending_nannounces;

	/* Lookups we've failed recently */
	struct txout_failures *txf;

	/* Blockheights of scids to remove */
	struct dying_channel *dying_channels;

	/* Occasional check for dead channels */
	struct oneshot *prune_timer;
};

/* Timer recursion */
static void start_prune_timer(struct gossmap_manage *gm);

static void enqueue_cupdate(struct pending_cupdate ***queue,
			    struct short_channel_id scid,
			    const secp256k1_ecdsa_signature *signature,
			    u8 message_flags,
			    u8 channel_flags,
			    u16 cltv_expiry_delta,
			    struct amount_msat htlc_minimum_msat,
			    struct amount_msat htlc_maximum_msat,
			    u32 fee_base_msat,
			    u32 fee_proportional_millionths,
			    u32 timestamp,
			    const u8 *update TAKES,
			    const struct node_id *source_peer TAKES)
{
	struct pending_cupdate *pcu = tal(*queue, struct pending_cupdate);

	pcu->scid = scid;
	pcu->signature = *signature;
	pcu->message_flags = message_flags;
	pcu->channel_flags = channel_flags;
	pcu->cltv_expiry_delta = cltv_expiry_delta;
	pcu->htlc_minimum_msat = htlc_minimum_msat;
	pcu->htlc_maximum_msat = htlc_maximum_msat;
	pcu->fee_base_msat = fee_base_msat;
	pcu->fee_proportional_millionths = fee_proportional_millionths;
	pcu->timestamp = timestamp;
	pcu->update = tal_dup_talarr(pcu, u8, update);
	pcu->source_peer = tal_dup_or_null(pcu, struct node_id, source_peer);

	tal_arr_expand(queue, pcu);
}

static void enqueue_nannounce(struct pending_nannounce ***queue,
			      const struct node_id *node_id,
			      u32 timestamp,
			      const u8 *nannounce TAKES,
			      const struct node_id *source_peer TAKES)
{
	struct pending_nannounce *pna = tal(*queue, struct pending_nannounce);

	pna->node_id = *node_id;
	pna->timestamp = timestamp;
	pna->nannounce = tal_dup_talarr(pna, u8, nannounce);
	pna->source_peer = tal_dup_or_null(pna, struct node_id, source_peer);

	tal_arr_expand(queue, pna);
}

/* Helpers to keep counters in sync with maps! */
static void map_init(struct cannounce_map *map, const char *name)
{
	uintmap_init(&map->map);
	map->count = 0;
	map->name = name;
	map->flood_reported = false;
}

static bool map_add(struct cannounce_map *map,
		    struct short_channel_id scid,
		    struct pending_cannounce *pca)
{
	/* More than 10000 pending things?  Stop! */
	if (map->count > 10000) {
		if (!map->flood_reported) {
			status_unusual("%s being flooded by %s: dropping some",
				       map->name,
				       pca->source_peer
				       ? node_id_to_hexstr(tmpctx, pca->source_peer)
				       : "unknown");
			map->flood_reported = true;
		}
		return false;
	}

	if (uintmap_add(&map->map, scid.u64, pca)) {
		map->count++;
		return true;
	}
	return false;
}

static struct pending_cannounce *map_del(struct cannounce_map *map,
					 struct short_channel_id scid)
{
	struct pending_cannounce *pca = uintmap_del(&map->map, scid.u64);
	if (pca) {
		assert(map->count);
		map->count--;
		if (map->flood_reported && uintmap_empty(&map->map)) {
			status_unusual("%s flood has subsided", map->name);
			map->flood_reported = false;
		}
	}
	return pca;
}

static bool map_empty(const struct cannounce_map *map)
{
	if (uintmap_empty(&map->map)) {
		assert(map->count == 0);
		return true;
	}
	assert(map->count != 0);
	return false;
}

static struct pending_cannounce *map_get(struct cannounce_map *map,
					 struct short_channel_id scid)
{
	return uintmap_get(&map->map, scid.u64);
}

/* Does any channel_announcement preceed this offset in the gossip_store? */
static bool any_cannounce_preceeds_offset(struct gossmap *gossmap,
					  const struct gossmap_node *node,
					  const struct gossmap_chan *exclude_chan,
					  u64 offset)
{
	for (size_t i = 0; i < node->num_chans; i++) {
		struct gossmap_chan *chan = gossmap_nth_chan(gossmap, node, i, NULL);

		if (chan == exclude_chan)
			continue;
		if (chan->cann_off < offset)
			return true;
	}
	return false;
}

/* To actually remove a channel:
 * - Suppress future lookups in case we receive another channel_update.
 * - Put deleted tombstone in gossip_store.
 * - Mark records deleted in gossip_store.
 * - See if node_announcement(s) need to be removed, or moved.
 */
static void remove_channel(struct gossmap_manage *gm,
			   struct gossmap *gossmap,
			   struct gossmap_chan *chan,
			   struct short_channel_id scid)
{
	/* Suppress any now-obsolete updates/announcements */
	txout_failures_add(gm->txf, scid);

	/* Cover race where we were looking up this UTXO as it was spent. */
	tal_free(map_del(&gm->pending_ann_map, scid));
	tal_free(map_del(&gm->early_ann_map, scid));

	/* Put in tombstone marker. */
	gossip_store_mark_channel_deleted(gm->daemon->gs, &scid);

	/* Delete from store */
	gossip_store_del(gm->daemon->gs, chan->cann_off, WIRE_CHANNEL_ANNOUNCEMENT);
	for (int dir = 0; dir < 2; dir++) {
		if (gossmap_chan_set(chan, dir))
			gossip_store_del(gm->daemon->gs, chan->cupdate_off[dir], WIRE_CHANNEL_UPDATE);
	}

	/* Check for node_announcements which should no longer be there */
	for (int dir = 0; dir < 2; dir++) {
		struct gossmap_node *node;
		const u8 *nannounce;
		u32 timestamp;

		node = gossmap_nth_node(gossmap, chan, dir);

		/* If there was a node announcement, we might need to fix things up. */
		if (!gossmap_node_announced(node))
			continue;

		/* Last channel?  Delete node announce */
		if (node->num_chans == 1) {
			gossip_store_del(gm->daemon->gs, node->nann_off, WIRE_NODE_ANNOUNCEMENT);
			continue;
		}

		/* Maybe this was the last channel_announcement which preceeded node_announcement? */
		if (chan->cann_off > node->nann_off)
			continue;

		if (any_cannounce_preceeds_offset(gossmap, node, chan, node->nann_off))
			continue;

		/* To maintain order, delete and re-add node_announcement */
		nannounce = gossmap_node_get_announce(tmpctx, gossmap, node);
		timestamp = gossip_store_get_timestamp(gm->daemon->gs, node->nann_off);
		gossip_store_del(gm->daemon->gs, node->nann_off, WIRE_NODE_ANNOUNCEMENT);
		gossip_store_add(gm->daemon->gs, nannounce, timestamp, false, NULL);
	}
}

static u32 get_timestamp(struct gossmap *gossmap,
			 const struct gossmap_chan *chan,
			 int dir)
{
	u32 timestamp;

	/* 0 is sufficient for our needs */
	if (!gossmap_chan_set(chan, dir))
		return 0;

	gossmap_chan_get_update_details(gossmap, chan, dir,
					&timestamp,
					NULL, NULL, NULL, NULL, NULL, NULL);
	return timestamp;
}

/* Every half a week we look for dead channels (faster in dev) */
static void prune_network(struct gossmap_manage *gm)
{
	u64 now = gossip_time_now(gm->daemon).ts.tv_sec;
	/* Anything below this highwater mark ought to be pruned */
	const s64 highwater = now - GOSSIP_PRUNE_INTERVAL(gm->daemon->dev_fast_gossip_prune);
	const struct gossmap_node *me;
	struct gossmap *gossmap;

	/* We reload this every time we delete a channel: that way we can tell if it's
	 * time to remove a node! */
	gossmap = gossmap_manage_get_gossmap(gm);
	me = gossmap_find_node(gossmap, &gm->daemon->id);

	/* Now iterate through all channels and see if it is still alive */
	for (size_t i = 0; i < gossmap_max_chan_idx(gossmap); i++) {
		struct gossmap_chan *chan = gossmap_chan_byidx(gossmap, i);
		u32 timestamp[2];
		struct short_channel_id scid;

		if (!chan)
			continue;

		/* BOLT #7:
		 * - if the `timestamp` of the latest `channel_update` in
		 *   either direction is older than two weeks (1209600 seconds):
		 *    - MAY prune the channel.
		 */
		/* This is a fancy way of saying "both ends must refresh!" */
		timestamp[0] = get_timestamp(gossmap, chan, 0);
		timestamp[1] = get_timestamp(gossmap, chan, 1);

		if (timestamp[0] >= highwater && timestamp[1] >= highwater)
			continue;

		scid = gossmap_chan_scid(gossmap, chan);

		/* Is it one of mine? */
		if (gossmap_nth_node(gossmap, chan, 0) == me
		    || gossmap_nth_node(gossmap, chan, 1) == me) {
			int local = (gossmap_nth_node(gossmap, chan, 1) == me);
			status_unusual("Pruning local channel %s from gossip_store: local channel_update time %u, remote %u",
				       type_to_string(tmpctx, struct short_channel_id,
						      &scid),
				       timestamp[local], timestamp[!local]);
		}

		status_debug("Pruning channel %s from network view (ages %u and %u)",
			     type_to_string(tmpctx, struct short_channel_id,
					    &scid),
			     timestamp[0], timestamp[1]);

		remove_channel(gm, gossmap, chan, scid);

		gossmap = gossmap_manage_get_gossmap(gm);
		me = gossmap_find_node(gossmap, &gm->daemon->id);
	}

	/* Note: some nodes may have been left with no channels!  Gossmap will
	 * remove them on next refresh. */
	start_prune_timer(gm);
}

static void start_prune_timer(struct gossmap_manage *gm)
{
	/* Schedule next run now */
	gm->prune_timer = new_reltimer(&gm->daemon->timers, gm,
				       time_from_sec(GOSSIP_PRUNE_INTERVAL(gm->daemon->dev_fast_gossip_prune)/4),
				       prune_network, gm);
}

static void reprocess_queued_msgs(struct gossmap_manage *gm);

static void report_bad_update(struct gossmap *map,
			      const struct short_channel_id_dir *scidd,
			      u16 cltv_expiry_delta,
			      u32 fee_base_msat,
			      u32 fee_proportional_millionths,
			      struct gossmap_manage *gm)
{
	status_debug("Update for %s has silly values, disabling (cltv=%u, fee=%u+%u)",
		     type_to_string(tmpctx, struct short_channel_id_dir, scidd),
		     cltv_expiry_delta, fee_base_msat, fee_proportional_millionths);
}

struct gossmap_manage *gossmap_manage_new(const tal_t *ctx,
					  struct daemon *daemon)
{
	struct gossmap_manage *gm = tal(ctx, struct gossmap_manage);

	gm->fd = open(GOSSIP_STORE_FILENAME, O_RDWR);
	if (gm->fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Opening gossip_store store: %s",
			      strerror(errno));
	gm->raw_gossmap = gossmap_load_fd(gm, gm->fd, report_bad_update, NULL, gm);
	assert(gm->raw_gossmap);
	gm->daemon = daemon;

	map_init(&gm->pending_ann_map, "pending announcements");
	gm->pending_cupdates = tal_arr(gm, struct pending_cupdate *, 0);
	map_init(&gm->early_ann_map, "too-early announcements");
	gm->early_cupdates = tal_arr(gm, struct pending_cupdate *, 0);
	gm->pending_nannounces = tal_arr(gm, struct pending_nannounce *, 0);
	gm->txf = txout_failures_new(gm, daemon);
	gm->dying_channels = tal_arr(gm, struct dying_channel, 0);

	start_prune_timer(gm);
	return gm;
}

/* Catch CI giving out-of-order gossip: definitely happens IRL though */
static void bad_gossip(const struct node_id *source_peer, const char *str)
{
	status_peer_debug(source_peer, "Bad gossip order: %s", str);
}

/* Minimal gossmap-only transition constructor */
struct gossmap_manage *gossmap_manage_new_gossmap_only(const tal_t *ctx,
						       struct daemon *daemon)
{
	struct gossmap_manage *gm = tal(ctx, struct gossmap_manage);

	gm->fd = open(GOSSIP_STORE_FILENAME, O_RDWR);
	if (gm->fd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Opening gossip_store store: %s",
			      strerror(errno));
	gm->raw_gossmap = gossmap_load_fd(gm, gm->fd, report_bad_update, NULL, gm);
	assert(gm->raw_gossmap);
	gm->daemon = daemon;

	return gm;
}

/* Send peer a warning message, if non-NULL. */
static void peer_warning(struct gossmap_manage *gm,
			 const struct node_id *source_peer,
			 const char *fmt, ...)
{
	va_list ap;
	char *formatted;

	va_start(ap, fmt);
	formatted = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	bad_gossip(source_peer, formatted);
	if (!source_peer)
		return;

	queue_peer_msg(gm->daemon, source_peer,
		       take(towire_warningfmt(NULL, NULL, "%s", formatted)));
}

const char *gossmap_manage_channel_announcement(const tal_t *ctx,
						struct gossmap_manage *gm,
						const u8 *announce TAKES,
						const struct node_id *source_peer TAKES,
						const struct amount_sat *known_amount)
{
	secp256k1_ecdsa_signature node_signature_1, node_signature_2;
	secp256k1_ecdsa_signature bitcoin_signature_1, bitcoin_signature_2;
	u8 *features;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	struct node_id node_id_1;
	struct node_id node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	struct pending_cannounce *pca;
	const char *warn;
	u32 blockheight = gm->daemon->current_blockheight;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	/* Make sure we own msg, even if we don't save it. */
	if (taken(announce))
		tal_steal(tmpctx, announce);

	if (!fromwire_channel_announcement(tmpctx, announce, &node_signature_1, &node_signature_2,
					   &bitcoin_signature_1, &bitcoin_signature_2, &features, &chain_hash,
					   &scid, &node_id_1, &node_id_2, &bitcoin_key_1, &bitcoin_key_2)) {
		return tal_fmt(ctx, "Malformed channel_announcement %s",
			       tal_hex(tmpctx, announce));
	}

	/* If a prior txout lookup failed there is little point it trying
	 * again. Just drop the announcement and walk away whistling.
	 *
	 * Happens quite a lot in CI on just-closed channels.
	 */
	if (in_txout_failures(gm->txf, scid)) {
		return NULL;
	}

	warn = sigcheck_channel_announcement(ctx, &node_id_1, &node_id_2,
					     &bitcoin_key_1, &bitcoin_key_2,
					     &node_signature_1, &node_signature_2,
					     &bitcoin_signature_1, &bitcoin_signature_2,
					     announce);
	if (warn)
		return warn;

	/* Already known? */
	if (gossmap_find_chan(gossmap, &scid))
		return NULL;

	pca = tal(gm, struct pending_cannounce);
	pca->scriptpubkey = scriptpubkey_p2wsh(pca,
					       bitcoin_redeem_2of2(tmpctx,
								   &bitcoin_key_1,
								   &bitcoin_key_2));
	pca->channel_announcement = tal_dup_talarr(pca, u8, announce);
	pca->source_peer = tal_dup_or_null(pca, struct node_id, source_peer);

	/* Are we supposed to add immediately without checking with lightningd?
	 * Unless we already got it from a peer and we're processing now!
	 */
	if (known_amount
	    && !map_get(&gm->pending_ann_map, scid)
	    && !map_get(&gm->early_ann_map, scid)) {
		/* Set with timestamp 0 (we will update once we have a channel_update) */
		gossip_store_add(gm->daemon->gs, announce, 0, false,
				 towire_gossip_store_channel_amount(tmpctx, *known_amount));
		tal_free(pca);
		return NULL;
	}

	/* Don't know blockheight yet, or not yet deep enough?  Don't even ask */
	if (!is_scid_depth_announceable(&scid, blockheight)) {
		/* Don't expect to be more than 12 blocks behind! */
		if (blockheight != 0
		    && short_channel_id_blocknum(&scid) > blockheight + 12) {
			return tal_fmt(ctx,
				       "Bad gossip order: ignoring channel_announcement %s at blockheight %u",
				       short_channel_id_to_str(tmpctx, &scid),
				       blockheight);
		}

		if (!map_add(&gm->early_ann_map, scid, pca)) {
			/* Already pending?  Ignore */
			tal_free(pca);
			return NULL;
		}

		/* We will retry in gossip_manage_new_block */
		return NULL;
	}

	status_debug("channel_announcement: Adding %s to pending...",
		     short_channel_id_to_str(tmpctx, &scid));
	if (!map_add(&gm->pending_ann_map, scid, pca)) {
		/* Already pending?  Ignore */
		tal_free(pca);
		return NULL;
	}

	/* Ask lightningd about this scid: see
	 * gossmap_manage_handle_get_txout_reply */
	daemon_conn_send(gm->daemon->master,
			 take(towire_gossipd_get_txout(NULL, &scid)));
	return NULL;
}

/*~ We queue incoming channel_announcement pending confirmation from lightningd
 * that it really is an unspent output.  Here's its reply. */
void gossmap_manage_handle_get_txout_reply(struct gossmap_manage *gm, const u8 *msg)
{
	struct short_channel_id scid;
	u8 *outscript;
	struct amount_sat sat;
	struct pending_cannounce *pca;

	if (!fromwire_gossipd_get_txout_reply(msg, msg, &scid, &sat, &outscript))
		master_badmsg(WIRE_GOSSIPD_GET_TXOUT_REPLY, msg);

	status_debug("channel_announcement: got reply for %s...",
		     short_channel_id_to_str(tmpctx, &scid));

	pca = map_del(&gm->pending_ann_map, scid);
	if (!pca) {
		/* If we looking specifically for this, we no longer
		 * are (but don't penalize sender: we don't know if it was
		 * good or bad). */
		remove_unknown_scid(gm->daemon->seeker, &scid, true);
		/* Was it deleted because we saw channel close? */
		if (!in_txout_failures(gm->txf, scid))
			status_broken("get_txout_reply with unknown scid %s?",
				      short_channel_id_to_str(tmpctx, &scid));
		return;
	}

	/* BOLT #7:
	 *
	 * The receiving node:
	 *...
	 *   - if the `short_channel_id`'s output... is spent:
	 *    - MUST ignore the message.
	 */
	if (tal_count(outscript) == 0) {
		peer_warning(gm, pca->source_peer,
			     "channel_announcement: no unspent txout %s",
			     short_channel_id_to_str(tmpctx, &scid));
		goto bad;
	}

	if (!memeq(outscript, tal_bytelen(outscript),
		   pca->scriptpubkey, tal_bytelen(pca->scriptpubkey))) {
		peer_warning(gm, pca->source_peer,
			     "channel_announcement: txout %s expected %s, got %s",
			     short_channel_id_to_str(tmpctx, &scid),
			     tal_hex(tmpctx, pca->scriptpubkey),
			     tal_hex(tmpctx, outscript));
		goto bad;
	}

	/* Set with timestamp 0 (we will update once we have a channel_update) */
	gossip_store_add(gm->daemon->gs, pca->channel_announcement, 0, false,
			 towire_gossip_store_channel_amount(tmpctx, sat));
	tal_free(pca);

	/* If we looking specifically for this, we no longer are. */
	remove_unknown_scid(gm->daemon->seeker, &scid, true);

	/* When all pending requests are done, we reconsider queued messages */
	reprocess_queued_msgs(gm);

	return;

bad:
	tal_free(pca);
	txout_failures_add(gm->txf, scid);
	/* If we looking specifically for this, we no longer are. */
	remove_unknown_scid(gm->daemon->seeker, &scid, false);
}

/* This is called both from when we receive the channel update, and if
 * we had to defer. */
static const char *process_channel_update(const tal_t *ctx,
					  struct gossmap_manage *gm,
					  struct short_channel_id scid,
					  const secp256k1_ecdsa_signature *signature,
					  u8 message_flags,
					  u8 channel_flags,
					  u16 cltv_expiry_delta,
					  struct amount_msat htlc_minimum_msat,
					  struct amount_msat htlc_maximum_msat,
					  u32 fee_base_msat,
					  u32 fee_proportional_millionths,
					  u32 timestamp,
					  const u8 *update,
 					  const struct node_id *source_peer)
{
	struct gossmap_chan *chan;
	struct node_id node_id, remote_id;
	const char *err;
	int dir = (channel_flags & ROUTING_FLAGS_DIRECTION);
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	chan = gossmap_find_chan(gossmap, &scid);
	if (!chan) {
		/* Did we explicitly reject announce?  Ignore completely. */
		if (in_txout_failures(gm->txf, scid))
			return NULL;

		/* Seeker may want to ask about this. */
		query_unknown_channel(gm->daemon, source_peer, scid);

		/* Don't send them warning, it can happen. */
		bad_gossip(source_peer,
			   tal_fmt(tmpctx, "Unknown channel %s",
				   short_channel_id_to_str(tmpctx, &scid)));
		return NULL;
	}

	/* Now we know node, we can check signature. */
	gossmap_node_get_id(gossmap,
			    gossmap_nth_node(gossmap, chan, dir),
			    &node_id);

	err = sigcheck_channel_update(ctx, &node_id, signature, update);
	if (err)
		return err;

	/* Don't allow private updates on public channels! */
	if (message_flags & ROUTING_OPT_DONT_FORWARD) {
		return tal_fmt(ctx, "Do not set DONT_FORWARD on public channel_updates (%s)",
			       short_channel_id_to_str(tmpctx, &scid));
	}

	/* Do we have same or earlier update? */
	if (gossmap_chan_set(chan, dir)) {
		u32 prev_timestamp
			= gossip_store_get_timestamp(gm->daemon->gs, chan->cupdate_off[dir]);
		if (prev_timestamp >= timestamp) {
			/* Too old, ignore */
			return NULL;
		}
	} else {
		/* Is this the first update in either direction?  If so,
		 * rewrite channel_announcement so timestamp is correct. */
		if (!gossmap_chan_set(chan, dir))
			gossip_store_set_timestamp(gm->daemon->gs, chan->cann_off, timestamp);
	}

	/* OK, apply the new one */
	gossip_store_add(gm->daemon->gs, update, timestamp, false, NULL);

	/* Now delete old */
	if (gossmap_chan_set(chan, dir))
		gossip_store_del(gm->daemon->gs, chan->cupdate_off[dir], WIRE_CHANNEL_UPDATE);

	/* Is this an update for an incoming channel?  If so, keep lightningd updated */
	gossmap_node_get_id(gossmap,
			    gossmap_nth_node(gossmap, chan, !dir),
			    &remote_id);
	if (node_id_eq(&remote_id, &gm->daemon->id)) {
		tell_lightningd_peer_update(gm->daemon, source_peer,
					    scid, fee_base_msat,
					    fee_proportional_millionths,
					    cltv_expiry_delta, htlc_minimum_msat,
					    htlc_maximum_msat);
	}

	status_peer_debug(source_peer,
			  "Received channel_update for channel %s/%d now %s",
			  type_to_string(tmpctx, struct short_channel_id,
					 &scid),
			  dir,
			  channel_flags & ROUTING_FLAGS_DISABLED ? "DISABLED" : "ACTIVE");
	return NULL;
}

const char *gossmap_manage_channel_update(const tal_t *ctx,
					  struct gossmap_manage *gm,
					  const u8 *update TAKES,
					  const struct node_id *source_peer TAKES)
{
	secp256k1_ecdsa_signature signature;
	struct short_channel_id scid;
	u32 timestamp;
	u8 message_flags, channel_flags;
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum_msat, htlc_maximum_msat;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	struct bitcoin_blkid chain_hash;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	if (taken(update))
		tal_steal(tmpctx, update);

	if (taken(source_peer))
		tal_steal(tmpctx, source_peer);

	if (!fromwire_channel_update(update, &signature,
				     &chain_hash, &scid,
				     &timestamp, &message_flags,
				     &channel_flags, &cltv_expiry_delta,
				     &htlc_minimum_msat, &fee_base_msat,
				     &fee_proportional_millionths,
				     &htlc_maximum_msat)) {
		return tal_fmt(ctx, "channel_update: malformed %s",
			       tal_hex(tmpctx, update));
	}

	/* Don't accept ancient or far-future timestamps. */
	if (!timestamp_reasonable(gm->daemon, timestamp))
		return NULL;

	/* Still waiting? */
	if (map_get(&gm->pending_ann_map, scid)) {
		enqueue_cupdate(&gm->pending_cupdates,
				scid,
				&signature,
				message_flags,
				channel_flags,
				cltv_expiry_delta,
				htlc_minimum_msat,
				htlc_maximum_msat,
				fee_base_msat,
				fee_proportional_millionths,
				timestamp,
				take(update),
				source_peer);
		return NULL;
	}

	/* Too early? */
	if (map_get(&gm->early_ann_map, scid)) {
		enqueue_cupdate(&gm->early_cupdates,
				scid,
				&signature,
				message_flags,
				channel_flags,
				cltv_expiry_delta,
				htlc_minimum_msat,
				htlc_maximum_msat,
				fee_base_msat,
				fee_proportional_millionths,
				timestamp,
				take(update),
				source_peer);
		return NULL;
	}

	/* Private channel_updates are not always marked as such.  So check if it's an unknown
	 * channel, and signed by the peer itself. */
	if (!gossmap_find_chan(gossmap, &scid)
	    && source_peer
	    && sigcheck_channel_update(tmpctx, source_peer, &signature, update) == NULL) {
		tell_lightningd_peer_update(gm->daemon, source_peer,
					    scid, fee_base_msat,
					    fee_proportional_millionths,
					    cltv_expiry_delta, htlc_minimum_msat,
					    htlc_maximum_msat);
		return NULL;
	}

	return process_channel_update(ctx, gm, scid, &signature,
				      message_flags, channel_flags,
				      cltv_expiry_delta,
				      htlc_minimum_msat,
				      htlc_maximum_msat,
				      fee_base_msat,
				      fee_proportional_millionths,
				      timestamp, update, source_peer);
}

static void process_node_announcement(struct gossmap_manage *gm,
				      const struct gossmap_node *node,
				      u32 timestamp,
				      const struct node_id *node_id,
				      const u8 *nannounce,
				      const struct node_id *source_peer)
{
	/* Do we have a later one?  If so, ignore */
	if (gossmap_node_announced(node)) {
		u32 prev_timestamp
			= gossip_store_get_timestamp(gm->daemon->gs, node->nann_off);
		if (prev_timestamp >= timestamp) {
			/* Too old, ignore */
			return;
		}
	}

	/* OK, apply the new one */
	gossip_store_add(gm->daemon->gs, nannounce, timestamp, false, NULL);

	/* Now delete old */
	if (gossmap_node_announced(node))
		gossip_store_del(gm->daemon->gs, node->nann_off, WIRE_NODE_ANNOUNCEMENT);

	status_peer_debug(source_peer,
			  "Received node_announcement for node %s",
			  type_to_string(tmpctx, struct node_id, node_id));
}

const char *gossmap_manage_node_announcement(const tal_t *ctx,
					     struct gossmap_manage *gm,
					     const u8 *nannounce TAKES,
					     const struct node_id *source_peer TAKES)
{
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	struct node_id node_id;
	u8 rgb_color[3];
	u8 alias[32];
	u8 *features, *addresses;
	struct wireaddr *wireaddrs;
	struct tlv_node_ann_tlvs *na_tlv;
	struct gossmap_node *node;
	const char *err;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	if (taken(nannounce))
		tal_steal(tmpctx, nannounce);

	if (taken(source_peer))
		tal_steal(tmpctx, source_peer);

	if (!fromwire_node_announcement(tmpctx, nannounce,
					&signature, &features, &timestamp,
					&node_id, rgb_color, alias,
					&addresses,
					&na_tlv)) {
		/* BOLT #7:
		 *
		 *   - if `node_id` is NOT a valid compressed public key:
		 *    - SHOULD send a `warning`.
		 *    - MAY close the connection.
		 *    - MUST NOT process the message further.
		 */
		return tal_fmt(ctx, "node_announcement: malformed %s",
			       tal_hex(tmpctx, nannounce));
	}

	wireaddrs = fromwire_wireaddr_array(tmpctx, addresses);
	if (!wireaddrs) {
		/* BOLT #7:
		 *
		 * - if `addrlen` is insufficient to hold the address
		 *  descriptors of the known types:
		 *    - SHOULD send a `warning`.
		 *    - MAY close the connection.
		 */
		return tal_fmt(ctx,
			       "node_announcement: malformed wireaddrs %s in %s",
			       tal_hex(tmpctx, wireaddrs),
			       tal_hex(tmpctx, nannounce));
	}

	err = sigcheck_node_announcement(ctx, &node_id, &signature,
					 nannounce);
	if (err)
		return err;

	node = gossmap_find_node(gossmap, &node_id);
	if (!node) {
		/* Still waiting for some channel_announcement? */
		if (!map_empty(&gm->pending_ann_map)
		    || !map_empty(&gm->early_ann_map)) {
			enqueue_nannounce(&gm->pending_nannounces,
					  &node_id,
					  timestamp,
					  take(nannounce),
					  source_peer);
			return NULL;
		}

		/* Seeker may want to ask about this. */
		query_unknown_node(gm->daemon, source_peer, &node_id);

		/* Don't complain to them: this can happen. */
		bad_gossip(source_peer,
			   tal_fmt(tmpctx,
				   "node_announcement: unknown node %s",
				   node_id_to_hexstr(tmpctx, &node_id)));
		return NULL;
	}

	process_node_announcement(gm, node, timestamp, &node_id, nannounce, source_peer);
	return NULL;
}

static void process_pending_cupdate(struct gossmap_manage *gm,
				    struct pending_cupdate *pcu)
{
	const char *err;

	err = process_channel_update(tmpctx, gm,
				     pcu->scid,
				     &pcu->signature,
				     pcu->message_flags,
				     pcu->channel_flags,
				     pcu->cltv_expiry_delta,
				     pcu->htlc_minimum_msat,
				     pcu->htlc_maximum_msat,
				     pcu->fee_base_msat,
				     pcu->fee_proportional_millionths,
				     pcu->timestamp,
				     pcu->update,
				     pcu->source_peer);
	if (err)
		peer_warning(gm, pcu->source_peer,
			     "channel_update: %s", err);
}

/* No channel_announcement now pending, so process every update which was waiting. */
static void reprocess_pending_cupdates(struct gossmap_manage *gm)
{
	/* Grab current array and reset to empty */
	struct pending_cupdate **pcus = gm->pending_cupdates;

	gm->pending_cupdates = tal_arr(gm, struct pending_cupdate *, 0);

	/* Now we can canonically process any pending channel_updates */
	for (size_t i = 0; i < tal_count(pcus); i++)
		process_pending_cupdate(gm, pcus[i]);

	tal_free(pcus);
}

/* No channel_announcement are early, so process every update which was for those. */
static void reprocess_early_cupdates(struct gossmap_manage *gm)
{
	/* Grab current array and reset to empty */
	struct pending_cupdate **pcus = gm->early_cupdates;

	gm->early_cupdates = tal_arr(gm, struct pending_cupdate *, 0);

	for (size_t i = 0; i < tal_count(pcus); i++) {
		/* Is announcement now pending?  Add directly to pending queue. */
		if (map_get(&gm->pending_ann_map, pcus[i]->scid)) {
			tal_arr_expand(&gm->pending_cupdates,
				       tal_steal(gm->pending_cupdates, pcus[i]));
			continue;
		}

		process_pending_cupdate(gm, pcus[i]);
	}
	tal_free(pcus);
}

static void reprocess_queued_msgs(struct gossmap_manage *gm)
{
	bool pending_ann_empty, early_ann_empty;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	pending_ann_empty = map_empty(&gm->pending_ann_map);
	early_ann_empty = map_empty(&gm->early_ann_map);

	if (pending_ann_empty) {
		reprocess_pending_cupdates(gm);
		/* This should have been final! */
		assert(map_empty(&gm->pending_ann_map));
	}

	if (early_ann_empty) {
		/* reprocess_pending_cupdates should not have added any! */
		assert(map_empty(&gm->early_ann_map));
		reprocess_early_cupdates(gm);
		/* Won't add any more */
		assert(map_empty(&gm->early_ann_map));
	}

	/* Nothing at all outstanding?  All node_announcements can now be processed */
	if (early_ann_empty && pending_ann_empty) {
		struct pending_nannounce **pnas = gm->pending_nannounces;

		gm->pending_nannounces = tal_arr(gm, struct pending_nannounce *, 0);

		for (size_t i = 0; i < tal_count(pnas); i++) {
			struct gossmap_node *node;

			node = gossmap_find_node(gossmap, &pnas[i]->node_id);
			if (!node) {
				/* Seeker may want to ask about this. */
				query_unknown_node(gm->daemon,
						   pnas[i]->source_peer, &pnas[i]->node_id);

				/* Don't complain to them: this can happen. */
				bad_gossip(pnas[i]->source_peer,
					   tal_fmt(tmpctx,
						   "node_announcement: unknown node %s",
						   node_id_to_hexstr(tmpctx, &pnas[i]->node_id)));
				continue;
			}

			process_node_announcement(gm, node,
						  pnas[i]->timestamp,
						  &pnas[i]->node_id,
						  pnas[i]->nannounce,
						  pnas[i]->source_peer);
		}

		/* Won't add any new ones */
		assert(map_empty(&gm->pending_ann_map));
		assert(map_empty(&gm->early_ann_map));

		tal_free(pnas);
	}
}

static void kill_spent_channel(struct gossmap_manage *gm,
			       struct gossmap *gossmap,
			       struct short_channel_id scid)
{
	struct gossmap_chan *chan;

	chan = gossmap_find_chan(gossmap, &scid);
	if (!chan) {
		status_broken("Dying channel %s already deleted?",
			      type_to_string(tmpctx, struct short_channel_id, &scid));
		return;
	}

	status_debug("Deleting channel %s due to the funding outpoint being "
		     "spent",
		     type_to_string(tmpctx, struct short_channel_id, &scid));

	remove_channel(gm, gossmap, chan, scid);
}

void gossmap_manage_new_block(struct gossmap_manage *gm, u32 new_blockheight)
{
	u64 idx;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	for (struct pending_cannounce *pca = uintmap_first(&gm->early_ann_map.map, &idx);
	     pca != NULL;
	     pca = uintmap_after(&gm->early_ann_map.map, &idx)) {
		struct short_channel_id scid;
		scid.u64 = idx;

		/* Stop when we are at unreachable heights */
		if (!is_scid_depth_announceable(&scid, new_blockheight))
			break;

		map_del(&gm->early_ann_map, scid);

		if (!map_add(&gm->pending_ann_map, scid, pca)) {
			/* Already pending?  Ignore */
			tal_free(pca);
			continue;
		}

		status_debug("gossmap_manage: new block, adding %s to pending...",
			     short_channel_id_to_str(tmpctx, &scid));

		/* Ask lightningd about this scid: see
		 * gossmap_manage_handle_get_txout_reply */
		daemon_conn_send(gm->daemon->master,
				 take(towire_gossipd_get_txout(NULL, &scid)));
	}

	for (size_t i = 0; i < tal_count(gm->dying_channels); i++) {
		if (gm->dying_channels[i].deadline_blockheight > new_blockheight)
			continue;

		kill_spent_channel(gm, gossmap, gm->dying_channels[i].scid);
		gossip_store_del(gm->daemon->gs,
				 /* FIXME: fix API to give us pre-hdr offsets! */
				 gm->dying_channels[i].gossmap_offset
				 + sizeof(struct gossip_hdr),
				 WIRE_GOSSIP_STORE_CHAN_DYING);
		tal_arr_remove(&gm->dying_channels, i);
	}
}

void gossmap_manage_channel_spent(struct gossmap_manage *gm,
				  u32 blockheight,
				  struct short_channel_id scid)
{
	struct gossmap_chan *chan;
	const struct gossmap_node *me;
	const u8 *msg;
	u32 deadline;
	u64 off;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	chan = gossmap_find_chan(gossmap, &scid);
	if (!chan)
		return;

	me = gossmap_find_node(gossmap, &gm->daemon->id);
	/* We delete our own channels immediately, since we have local knowledge */
	if (gossmap_nth_node(gossmap, chan, 0) == me
	    || gossmap_nth_node(gossmap, chan, 1) == me) {
		kill_spent_channel(gm, gossmap, scid);
		return;
	}

	/* BOLT #7:
	 *   - once its funding output has been spent OR reorganized out:
	 *     - SHOULD forget a channel after a 12-block delay.
	 */
	deadline = blockheight + 12;

	/* Remember locally so we can kill it in 12 blocks */
	status_debug("channel %s closing soon due"
		     " to the funding outpoint being spent",
		     type_to_string(tmpctx, struct short_channel_id, &scid));

	/* Save to gossip_store in case we restart */
	msg = towire_gossip_store_chan_dying(tmpctx, &scid, deadline);
	off = gossip_store_add(gm->daemon->gs, msg, 0, false, NULL);
	gossmap_manage_channel_dying(gm, off, deadline, scid);

	/* Mark it dying, so we don't gossip it */
	gossip_store_flag(gm->daemon->gs, chan->cann_off,
			  GOSSIP_STORE_DYING_BIT,
			  WIRE_CHANNEL_ANNOUNCEMENT);
	/* Channel updates too! */
	for (int dir = 0; dir < 2; dir++) {
		if (!gossmap_chan_set(chan, dir))
			continue;

		gossip_store_flag(gm->daemon->gs,
				  chan->cupdate_off[dir],
				  GOSSIP_STORE_DYING_BIT,
				  WIRE_CHANNEL_UPDATE);
	}
}

struct gossmap *gossmap_manage_get_gossmap(struct gossmap_manage *gm)
{
	gossmap_refresh(gm->raw_gossmap, NULL);
	return gm->raw_gossmap;
}

bool gossmap_manage_channel_dying(struct gossmap_manage *gm,
				  u64 gossmap_offset,
				  u32 deadline,
				  struct short_channel_id scid)
{
	struct dying_channel dead;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	/* Can't kill missing channels! */
	if (!gossmap_find_chan(gossmap, &scid))
		return false;

	dead.deadline_blockheight = deadline;
	dead.gossmap_offset = gossmap_offset;
	dead.scid = scid;

	tal_arr_expand(&gm->dying_channels, dead);
	return true;
}

/* BOLT #7:
 *   - if the `gossip_queries` feature is negotiated:
 *     - MUST NOT relay any gossip messages it did not generate itself,
 *       unless explicitly requested.
 */
/* i.e. the strong implication is that we spam our own gossip aggressively!
 * "Look at me!"  "Look at me!!!!".
 */
/* Statistically, how many peers to we tell about each channel? */
#define GOSSIP_SPAM_REDUNDANCY 5

void gossmap_manage_new_peer(struct gossmap_manage *gm,
			     const struct node_id *peer)
{
	struct gossmap_node *me;
	const u8 *msg;
	u64 send_threshold;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	/* Find ourselves; if no channels, nothing to send */
	me = gossmap_find_node(gossmap, &gm->daemon->id);
	if (!me)
		return;

	send_threshold = -1ULL;

	/* Just in case we have many peers and not all are connecting or
	 * some other corner case, send everything to first few. */
	if (peer_node_id_map_count(gm->daemon->peers) > GOSSIP_SPAM_REDUNDANCY
	    && me->num_chans > GOSSIP_SPAM_REDUNDANCY) {
		send_threshold = -1ULL / me->num_chans * GOSSIP_SPAM_REDUNDANCY;
	}

	for (size_t i = 0; i < me->num_chans; i++) {
		struct gossmap_chan *chan = gossmap_nth_chan(gossmap, me, i, NULL);

		/* We set this so we'll send a fraction of all our channels */
		if (pseudorand_u64() > send_threshold)
			continue;

		/* Send channel_announce */
		msg = gossmap_chan_get_announce(NULL, gossmap, chan);
		queue_peer_msg(gm->daemon, peer, take(msg));

		/* Send both channel_updates (if they exist): both help people
		 * use our channel, so we care! */
		for (int dir = 0; dir < 2; dir++) {
			if (!gossmap_chan_set(chan, dir))
				continue;
			msg = gossmap_chan_get_update(NULL, gossmap, chan, dir);
			queue_peer_msg(gm->daemon, peer, take(msg));
		}
	}

	/* If we have one, we should send our own node_announcement */
	msg = gossmap_node_get_announce(NULL, gossmap, me);
	if (msg)
		queue_peer_msg(gm->daemon, peer, take(msg));
}

void gossmap_manage_tell_lightningd_locals(struct daemon *daemon,
					   struct gossmap_manage *gm)
{
	struct gossmap_node *me;
	const u8 *nannounce;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	/* Find ourselves; if no channels, nothing to send */
	me = gossmap_find_node(gossmap, &gm->daemon->id);
	if (!me)
		return;

	for (size_t i = 0; i < me->num_chans; i++) {
		struct gossmap_chan *chan = gossmap_nth_chan(gossmap, me, i, NULL);
		struct short_channel_id scid;
		const u8 *cupdate;

		scid = gossmap_chan_scid(gossmap, chan);
		cupdate = gossmap_chan_get_update(tmpctx, gossmap, chan, 0);
		if (cupdate)
			daemon_conn_send(daemon->master,
					 take(towire_gossipd_init_cupdate(NULL,
									  &scid,
									  cupdate)));
		cupdate = gossmap_chan_get_update(tmpctx, gossmap, chan, 1);
		if (cupdate)
			daemon_conn_send(daemon->master,
					 take(towire_gossipd_init_cupdate(NULL,
									  &scid,
									  cupdate)));
	}

	/* Tell lightningd about our current node_announcement, if any */
	nannounce = gossmap_node_get_announce(tmpctx, gossmap, me);
	if (nannounce)
		daemon_conn_send(daemon->master,
				 take(towire_gossipd_init_nannounce(NULL,
								    nannounce)));
}

struct wireaddr *gossmap_manage_get_node_addresses(const tal_t *ctx,
						   struct gossmap_manage *gm,
						   const struct node_id *node_id)
{
	struct gossmap_node *node;
	u8 *nannounce;
	struct node_id id;
	secp256k1_ecdsa_signature signature;
	u32 timestamp;
	u8 *addresses, *features;
	u8 rgb_color[3], alias[32];
	struct tlv_node_ann_tlvs *na_tlvs;
	struct wireaddr *wireaddrs;
	struct gossmap *gossmap = gossmap_manage_get_gossmap(gm);

	node = gossmap_find_node(gossmap, node_id);
	if (!node)
		return NULL;

	nannounce = gossmap_node_get_announce(tmpctx, gossmap,
					      node);
	if (!nannounce)
		return NULL;

	if (!fromwire_node_announcement(tmpctx, nannounce,
					&signature, &features,
					&timestamp,
					&id, rgb_color, alias,
					&addresses,
					&na_tlvs)) {
		status_broken("Bad node_announcement for %s in gossip_store: %s",
			      node_id_to_hexstr(tmpctx, node_id),
			      tal_hex(tmpctx, nannounce));
		return NULL;
	}

	wireaddrs = fromwire_wireaddr_array(ctx, addresses);
	if (!wireaddrs) {
		status_broken("Bad wireaddrs in node_announcement in gossip_store: %s",
			      tal_hex(tmpctx, nannounce));
		return NULL;
	}

	return wireaddrs;
}
