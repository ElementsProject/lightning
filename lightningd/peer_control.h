#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <common/channel_config.h>
#include <common/htlc.h>
#include <common/json.h>
#include <common/node_id.h>
#include <common/wireaddr.h>
#include <lightningd/channel.h>
#include <lightningd/channel_state.h>
#include <stdbool.h>
#include <wallet/wallet.h>
#include <wire/peer_wire.h>

struct per_peer_state;

struct peer {
	/* Inside ld->peers. */
	struct list_node list;

	/* Master context */
	struct lightningd *ld;

	/* Database ID of the peer */
	u64 dbid;

	/* ID of peer */
	struct node_id id;

	/* Our channels */
	struct list_head channels;

	/* Our (only) uncommitted channel, still opening. */
	struct uncommitted_channel *uncommitted_channel;

	/* Where we connected to, or it connected from. */
	struct wireaddr_internal addr;

	/* We keep a copy of their feature bits */
	const u8 *their_features;

	/* If we open a channel our direction will be this */
	u8 direction;

#if DEVELOPER
	/* Swallow incoming HTLCs (for testing) */
	bool ignore_htlcs;
#endif
};

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid);

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct node_id *id,
		      const struct wireaddr_internal *addr);

/* Last one out deletes peer.  Also removes from db. */
void maybe_delete_peer(struct peer *peer);

struct peer *peer_by_id(struct lightningd *ld, const struct node_id *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    const jsmntok_t *peeridtok);

void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd, int gossip_store_fd);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

void channel_errmsg(struct channel *channel,
		    struct per_peer_state *pps,
		    const struct channel_id *channel_id,
		    const char *desc,
		    bool soft_error,
		    const u8 *err_for_them);

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx);

/* We've loaded peers from database, set them going. */
void activate_peers(struct lightningd *ld);

void drop_to_chain(struct lightningd *ld, struct channel *channel, bool cooperative);

void channel_watch_funding(struct lightningd *ld, struct channel *channel);

/* Pull peers, channels and HTLCs from db, and wire them up.
 * Returns any HTLCs we have to resubmit via htlcs_resubmit. */
struct htlc_in_map *load_channels_from_wallet(struct lightningd *ld);

#if DEVELOPER
void peer_dev_memleak(struct command *cmd);
void handle_custommsg_in(struct lightningd *ld, const struct node_id *peer_id,
			 const u8 *msg);
#endif /* DEVELOPER */

/* Triggered at each new block.  */
void waitblockheight_notify_new_block(struct lightningd *ld,
				      u32 block_height);

#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
