#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <common/channel_config.h>
#include <common/htlc.h>
#include <common/json.h>
#include <common/wireaddr.h>
#include <lightningd/channel.h>
#include <lightningd/channel_state.h>
#include <stdbool.h>
#include <wallet/wallet.h>
#include <wire/peer_wire.h>

struct crypto_state;

struct peer {
	/* Inside ld->peers. */
	struct list_node list;

	/* Master context */
	struct lightningd *ld;

	/* Database ID of the peer */
	u64 dbid;

	/* ID of peer */
	struct pubkey id;

	/* Our channels */
	struct list_head channels;

	/* Our (only) uncommitted channel, still opening. */
	struct uncommitted_channel *uncommitted_channel;

	/* History */
	struct log_book *log_book;

	/* Where we connected to, or it connected from. */
	struct wireaddr_internal addr;

	/* We keep a copy of their feature bits */
	const u8 *local_features, *global_features;

	/* If we open a channel our direction will be this */
	u8 direction;

#if DEVELOPER
	/* Swallow incoming HTLCs (for testing) */
	bool ignore_htlcs;
#endif
};

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid);

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct pubkey *id,
		      const struct wireaddr_internal *addr,
		      const u8 *gfeatures TAKES, const u8 *lfeatures TAKES);

/* Last one out deletes peer.  Also removes from db. */
void maybe_delete_peer(struct peer *peer);

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    const jsmntok_t *peeridtok);

/* The three ways peers enter from the network:
 *
 * peer_connected - when it first connects to gossipd (after init exchange).
 * peer_sent_nongossip - when it tries to fund a channel.
 * gossip_peer_released - when we tell gossipd to release it so we can fund
 *			  a channel.
*/
void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd);

void peer_sent_nongossip(struct lightningd *ld,
			 const struct pubkey *id,
			 const struct wireaddr_internal *addr,
			 const struct crypto_state *cs,
			 const u8 *gfeatures,
			 const u8 *lfeatures,
			 int peer_fd, int gossip_fd,
			 const u8 *in_msg);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

void channel_errmsg(struct channel *channel,
		    int peer_fd, int gossip_fd,
		    const struct crypto_state *cs,
		    const struct channel_id *channel_id,
		    const char *desc,
		    const u8 *err_for_them);

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx);

/* We've loaded peers from database, set them going. */
void activate_peers(struct lightningd *ld);

void drop_to_chain(struct lightningd *ld, struct channel *channel, bool cooperative);

/* Get range of feerates to insist other side abide by for normal channels. */
u32 feerate_min(struct lightningd *ld);
u32 feerate_max(struct lightningd *ld);

void channel_watch_funding(struct lightningd *ld, struct channel *channel);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
