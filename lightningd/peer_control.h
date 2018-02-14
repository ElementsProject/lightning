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
#include <lightningd/peer_state.h>
#include <stdbool.h>
#include <wallet/wallet.h>
#include <wire/peer_wire.h>

#define ANNOUNCE_MIN_DEPTH 6

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

	/* History */
	struct log_book *log_book;

	/* Where we connected to, or it connected from. */
	struct wireaddr addr;

	/* If we open a channel our direction will be this */
	u8 direction;
};

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid);

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct pubkey *id,
		      const struct wireaddr *addr);

/* Also removes from db. */
void delete_peer(struct peer *peer);

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    jsmntok_t *peeridtok);

/* The three ways peers enter from the network:
 *
 * peer_connected - when it first connects to gossipd (after init exchange).
 * peer_sent_nongossip - when it tries to fund a channel.
 * gossip_peer_released - when we tell gossipd to release it so we can fund
 *			  a channel.
*/
void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd);

/* This simply means we asked to reach a peer, but we already have it */
void peer_already_connected(struct lightningd *ld, const u8 *msg);

/* We were unable to connect to the peer */
void peer_connection_failed(struct lightningd *ld, const u8 *msg);

void peer_sent_nongossip(struct lightningd *ld,
			 const struct pubkey *id,
			 const struct wireaddr *addr,
			 const struct crypto_state *cs,
			 u64 gossip_index,
			 const u8 *gfeatures,
			 const u8 *lfeatures,
			 int peer_fd, int gossip_fd,
			 const u8 *in_msg);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

/* Peer has failed to open; return to gossipd. */
void opening_failed(struct peer *peer, const u8 *msg TAKES);

const char *peer_state_name(enum peer_state state);
void setup_listeners(struct lightningd *ld);

/* We've loaded peers from database, set them going. */
void activate_peers(struct lightningd *ld);

void drop_to_chain(struct lightningd *ld, struct channel *channel);

void free_htlcs(struct lightningd *ld, const struct channel *channel);

/* Get range of feerates to insist other side abide by for normal channels. */
u32 feerate_min(struct lightningd *ld);
u32 feerate_max(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
