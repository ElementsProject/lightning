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

struct peer_fd;
struct wally_psbt;

struct peer {
	/* Inside ld->peers. */
	struct list_node list;

	/* Master context */
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

	/* They send what they see as our address as remote_addr */
	struct wireaddr *remote_addr;

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
		      const struct wireaddr_internal *addr,
		      bool connected_incoming);

/* Last one out deletes peer.  Also removes from db. */
void maybe_delete_peer(struct peer *peer);

struct peer *peer_by_id(struct lightningd *ld, const struct node_id *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    const jsmntok_t *peeridtok);

/* connectd tells us what peer is doing */
void peer_connected(struct lightningd *ld, const u8 *msg);
void peer_disconnect_done(struct lightningd *ld, const u8 *msg);
void peer_spoke(struct lightningd *ld, const u8 *msg);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

void channel_errmsg(struct channel *channel,
		    struct peer_fd *peer_fd,
		    const struct channel_id *channel_id,
		    const char *desc,
		    bool warning,
		    const u8 *err_for_them);

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx);

/* We've loaded peers from database, set them going. */
void setup_peers(struct lightningd *ld);

/* At startup, re-send any transactions we want bitcoind to have */
void resend_closing_transactions(struct lightningd *ld);

void drop_to_chain(struct lightningd *ld, struct channel *channel, bool cooperative);

void channel_watch_funding(struct lightningd *ld, struct channel *channel);
/* If this channel has a "wrong funding" shutdown, watch that too. */
void channel_watch_wrong_funding(struct lightningd *ld, struct channel *channel);

/* How much can we spend in this channel? */
struct amount_msat channel_amount_spendable(const struct channel *channel);

/* How much can we receive in this channel? */
struct amount_msat channel_amount_receivable(const struct channel *channel);

/* Pull peers, channels and HTLCs from db, and wire them up.
 * Returns any HTLCs we have to resubmit via htlcs_resubmit. */
struct htlc_in_map *load_channels_from_wallet(struct lightningd *ld);

#if DEVELOPER
struct leak_detect;
void peer_dev_memleak(struct lightningd *ld, struct leak_detect *leaks);
#endif /* DEVELOPER */

/* Triggered at each new block.  */
void waitblockheight_notify_new_block(struct lightningd *ld,
				      u32 block_height);


/* JSON parameter by channel_id or scid */
struct command_result *
command_find_channel(struct command *cmd,
		     const char *buffer, const jsmntok_t *tok,
		     struct channel **channel);

/* Ancient (0.7.0 and before) releases could create invalid commitment txs! */
bool invalid_last_tx(const struct bitcoin_tx *tx);

#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
