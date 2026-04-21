#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <common/channel_config.h>
#include <common/htlc.h>
#include <common/json_parse.h>
#include <common/node_id.h>
#include <common/wireaddr.h>
#include <wallet/wallet.h>

struct channel_type;
struct peer_fd;
struct wally_psbt;

struct peer {
	/* Master context (we're in the hashtable ld->peers) */
	struct lightningd *ld;

	/* Database ID of the peer */
	u64 dbid;

	/* ID of peer */
	struct node_id id;

	/* Connection counter from connectd. */
	u64 connectd_counter;

	/* Last reconnect: if it's recent, we delay by reconnect_delay,
	 * doubling each time. */
	struct timeabs last_connect_attempt;
	u32 reconnect_delay;

	/* Our channels */
	struct list_head channels;

	/* Are we connected? */
	enum {
		/* Connectd said we're connecting, we called hooks... */
		PEER_CONNECTING,
		/* Hooks succeeded, we're connected. */
		PEER_CONNECTED,
		/* Start state, also connectd told us we're disconnected */
		PEER_DISCONNECTED,
	} connected;

	/* Our (only) uncommitted channel, still opening. */
	struct uncommitted_channel *uncommitted_channel;

	/* Where we connected to, or it connected from. */
	struct wireaddr_internal addr;
	bool connected_incoming;

	/* If we ever successfully connected out to an address, this is non-NULL */
	struct wireaddr *last_known_addr;

	/* They send what they see as our address as remote_addr */
	struct wireaddr *remote_addr;

	/* We keep a copy of their feature bits */
	const u8 *their_features;

	/* If we open a channel our direction will be this */
	u8 direction;

	/* Swallow incoming HTLCs (for testing) */
	bool dev_ignore_htlcs;
};

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid);

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct node_id *id,
		      const struct wireaddr_internal *addr,
		      const struct wireaddr *last_known_addr,
		      const u8 *their_features TAKES,
		      bool connected_incoming);

/* Last one out deletes peer.  Also removes from db. */
void maybe_delete_peer(struct peer *peer);

struct peer *peer_by_id(struct lightningd *ld, const struct node_id *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    const jsmntok_t *peeridtok);

/* connectd tells us what peer is doing */
void handle_peer_connected(struct lightningd *ld, const u8 *msg);
void handle_peer_disconnected(struct lightningd *ld, const u8 *msg);
void handle_peer_spoke(struct lightningd *ld, const u8 *msg);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

void channel_errmsg(struct channel *channel,
		    struct peer_fd *peer_fd,
		    const char *desc,
		    const u8 *err_for_them,
		    bool disconnect,
		    bool warning);

/* Helper to create a peer_fd and an other fd from socketpair.
 * Logs error to channel if it fails, and if warning non-NULL, creates
 * a warning message */
struct peer_fd *sockpair(const tal_t *ctx, struct channel *channel,
			 int *otherfd, const u8 **warning);

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx);
u8 *p2tr_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx);

/* We've loaded peers from database, set them going. */
void setup_peers(struct lightningd *ld);

/* When database first writes peer into db, it sets the dbid */
void peer_set_dbid(struct peer *peer, u64 dbid);

/* At startup, re-send any transactions we want bitcoind to have */
void resend_closing_transactions(struct lightningd *ld);

/* At startup, re-send any funding transactions we want bitcoind to have */
void resend_opening_transactions(struct lightningd *ld);

/* Initiate the close of a channel, maybe broadcast.  If we've seen a
 * unilateral close, pass it here (means we don't need to broadcast
 * our own, or any anchors). */
void drop_to_chain(struct lightningd *ld, struct channel *channel,
		   bool cooperative,
		   const struct bitcoin_tx *unilateral_tx);

void update_channel_from_inflight(struct lightningd *ld,
				  struct channel *channel,
				  const struct channel_inflight *inflight,
				  bool is_splice);

/* Watch for funding tx. */
void channel_watch_funding(struct lightningd *ld, struct channel *channel);
void channel_unwatch_funding(struct lightningd *ld, struct channel *channel);

/* bwatch handler for "channel/funding/<dbid>" (WATCH_SCRIPTPUBKEY): the
 * funding output script appeared in a tx, so the channel's funding tx has
 * been confirmed.  Records the SCID and starts a depth watch to drive
 * channeld's lock-in state machine. */
void channel_funding_watch_found(struct lightningd *ld,
				 const char *suffix,
				 const struct bitcoin_tx *tx,
				 size_t outnum,
				 u32 blockheight,
				 u32 txindex);

void channel_funding_watch_revert(struct lightningd *ld,
				  const char *suffix,
				  u32 blockheight);

/* bwatch handler for "channel/funding_depth/<dbid>" (WATCH_BLOCKDEPTH): fires
 * once per new block while the funding tx is accumulating confirmations.
 * Drives channeld's depth state machine and triggers lock-in once
 * minimum_depth is met.  Unwatches itself once depth reaches
 * max(minimum_depth, ANNOUNCE_MIN_DEPTH). */
void channel_funding_depth_found(struct lightningd *ld,
				 const char *suffix,
				 u32 depth,
				 u32 blockheight);

/* Reorg of the block that confirmed the funding tx: clear scid and, for
 * states past lock-in, fail the channel transiently so it reconnects once
 * the tx is re-mined. */
void channel_funding_depth_revert(struct lightningd *ld,
				  const char *suffix,
				  u32 blockheight);

/* Called from watchman's block_processed handler once per new block.
 * Iterates every channel whose funding tx has confirmed and drives its
 * depth-dependent state (lock-in, gossip announce, splice). */
void channel_block_processed(struct lightningd *ld, u32 blockheight);

/* Watch for spend of funding tx. */
void channel_watch_funding_out(struct lightningd *ld, struct channel *channel);

/* Watch block that funding tx is in */
void channel_watch_depth(struct lightningd *ld,
			 u32 blockheight,
			 struct channel *channel);

/* If this channel has a "wrong funding" shutdown, watch that too. */
void channel_watch_wrong_funding(struct lightningd *ld, struct channel *channel);

/* bwatch handler for "channel/funding_spent/<dbid>" (WATCH_OUTPOINT): the
 * funding output was spent.  If the spending tx is one of our own
 * inflights, this is a splice in progress and we just keep watching
 * (handing the memory-only inflight off to channel_splice_watch_found).
 * Otherwise the channel was closed/force-closed, so hand off to onchaind. */
void channel_funding_spent_watch_found(struct lightningd *ld,
				       const char *suffix,
				       const struct bitcoin_tx *tx,
				       size_t innum,
				       u32 blockheight,
				       u32 txindex);

/* Reorg of the funding-spend tx.  Full rollback (kill onchaind, restore
 * CHANNELD_NORMAL) lands once onchaind itself runs on bwatch; for now we
 * just log the event. */
void channel_funding_spent_watch_revert(struct lightningd *ld,
					const char *suffix,
					u32 blockheight);

/* bwatch handler for "channel/wrong_funding_spent/<dbid>": the
 * shutdown_wrong_funding outpoint we registered in channel_watch_wrong_funding
 * was spent.  Handed off to onchaind the same way as channel_funding_spent. */
void channel_wrong_funding_spent_watch_found(struct lightningd *ld,
					     const char *suffix,
					     const struct bitcoin_tx *tx,
					     size_t innum,
					     u32 blockheight,
					     u32 txindex);

/* Reorg of the wrong-funding-spend tx.  Same handling as channel_funding_spent
 * since both arrive at the same onchaind state machine. */
void channel_wrong_funding_spent_watch_revert(struct lightningd *ld,
					      const char *suffix,
					      u32 blockheight);

/* How much can we spend in this channel? */
struct amount_msat channel_amount_spendable(const struct channel *channel);

/* How much can we receive in this channel? */
struct amount_msat channel_amount_receivable(const struct channel *channel);

/* Pull peers, channels and HTLCs from db, and wire them up.
 * Returns any HTLCs we have to resubmit via htlcs_resubmit.
 *
 * As a side-effect, count total channels loaded into *num_channels.
 */
struct htlc_in_map *load_channels_from_wallet(struct lightningd *ld,
					      size_t *num_channels);


struct leak_detect;
void peer_dev_memleak(struct lightningd *ld, struct leak_detect *leaks);

/* Triggered at each new block.  */
void waitblockheight_notify_new_block(struct lightningd *ld);


/* JSON parameter by channel_id or scid (caller must check state!) */
struct command_result *
command_find_channel(struct command *cmd,
		     const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct channel **channel);

/* We do this lazily, when reconnecting */
void peer_channels_cleanup(struct peer *peer);

/* Ancient (0.7.0 and before) releases could create invalid commitment txs! */
bool invalid_last_tx(const struct bitcoin_tx *tx);

static const struct node_id *peer_node_id(const struct peer *peer)
{
	return &peer->id;
}

static bool peer_node_id_eq(const struct peer *peer,
			    const struct node_id *node_id)
{
	return node_id_eq(&peer->id, node_id);
}

/* Defines struct peer_node_id_map */
HTABLE_DEFINE_NODUPS_TYPE(struct peer,
			  peer_node_id, node_id_hash, peer_node_id_eq,
			  peer_node_id_map);

static inline size_t dbid_hash(u64 dbid)
{
	return siphash24(siphash_seed(), &dbid, sizeof(dbid));
}

static u64 peer_dbid(const struct peer *peer)
{
	assert(peer->dbid);
	return peer->dbid;
}

static bool peer_dbid_eq(const struct peer *peer, u64 dbid)
{
	return peer->dbid == dbid;
}
/* Defines struct peer_dbid_map */
HTABLE_DEFINE_NODUPS_TYPE(struct peer,
			  peer_dbid, dbid_hash, peer_dbid_eq,
			  peer_dbid_map);

#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
