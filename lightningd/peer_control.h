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
#include <lightningd/peer_state.h>
#include <stdbool.h>
#include <wallet/wallet.h>
#include <wire/peer_wire.h>

#define ANNOUNCE_MIN_DEPTH 6

struct crypto_state;

struct peer {
	struct lightningd *ld;

	/* Database ID of the peer */
	u64 dbid;

	/* ID of peer */
	struct pubkey id;

	/* Global and local features bitfields. */
	const u8 *gfeatures, *lfeatures;

	/* Error message (iff in error state) */
	u8 *error;

	/* Their shachain. */
	struct wallet_shachain their_shachain;

 	/* What's happening. */
 	enum peer_state state;

	/* Which side offered channel? */
	enum side funder;

	/* Command which ordered us to open channel, if any. */
	struct command *opening_cmd;
	
	/* Inside ld->peers. */
	struct list_node list;

	/* Is there a single subdaemon responsible for us? */
	struct subd *owner;

	/* History */
	struct log_book *log_book;
	struct log *log;

	/* Channel flags from opening message. */
	u8 channel_flags;

	/* Where we connected to, or it connected from. */
	struct wireaddr addr;

	/* Our channel config. */
	struct channel_config our_config;

	/* Minimum funding depth (specified by us if they fund). */
	u32 minimum_depth;

	/* Tracking commitment transaction numbers. */
	u64 next_index[NUM_SIDES];
	u64 next_htlc_id;

	/* Funding txid and amounts (once known) */
	struct sha256_double *funding_txid;
	u16 funding_outnum;
	u64 funding_satoshi, push_msat;
	bool remote_funding_locked;
	/* Channel if locked locally. */
	struct short_channel_id *scid;

	/* Amount going to us, not counting unfinished HTLCs; if we have one. */
	u64 *our_msatoshi;

	/* Last tx they gave us (if any). */
	struct bitcoin_tx *last_tx;
	secp256k1_ecdsa_signature *last_sig;
	secp256k1_ecdsa_signature *last_htlc_sigs;

	/* Keys for channel. */
	struct channel_info *channel_info;

	/* Secret seed (FIXME: Move to hsm!) */
	struct privkey *seed;

	/* Their scriptpubkey if they sent shutdown. */
	u8 *remote_shutdown_scriptpubkey;
	/* Our key for shutdown (-1 if not chosen yet) */
	s64 local_shutdown_idx;

	/* Reestablishment stuff: last sent commit and revocation details. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;

	struct wallet_channel *channel;
};

static inline bool peer_can_add_htlc(const struct peer *peer)
{
	return peer->state == CHANNELD_NORMAL;
}

static inline bool peer_fees_can_change(const struct peer *peer)
{
	return peer->state == CHANNELD_NORMAL
		|| peer->state == CHANNELD_SHUTTING_DOWN;
}

static inline bool peer_can_remove_htlc(const struct peer *peer)
{
	return peer->state == CHANNELD_NORMAL
		|| peer->state == CHANNELD_SHUTTING_DOWN
		|| peer->state == ONCHAIND_THEIR_UNILATERAL
		|| peer->state == ONCHAIND_OUR_UNILATERAL;
}

static inline bool peer_state_on_chain(enum peer_state state)
{
	return state == ONCHAIND_CHEATED
		|| state == ONCHAIND_THEIR_UNILATERAL
		|| state == ONCHAIND_OUR_UNILATERAL
		|| state == ONCHAIND_MUTUAL;
}

static inline bool peer_on_chain(const struct peer *peer)
{
	return peer_state_on_chain(peer->state);
}

static inline bool peer_wants_reconnect(const struct peer *peer)
{
	return peer->state >= CHANNELD_AWAITING_LOCKIN
		&& peer->state <= CLOSINGD_COMPLETE;
}

/* BOLT #2:
 *
 * On disconnection, the funder MUST remember the channel for
 * reconnection if it has broadcast the funding transaction, otherwise it
 * SHOULD NOT.
 *
 * On disconnection, the non-funding node MUST remember the channel for
 * reconnection if it has sent the `funding_signed` message, otherwise
 * it SHOULD NOT.
 */
static inline bool peer_persists(const struct peer *peer)
{
	return peer->state >= CHANNELD_AWAITING_LOCKIN;
}

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    jsmntok_t *peeridtok);

void peer_last_tx(struct peer *peer, struct bitcoin_tx *tx,
		  const secp256k1_ecdsa_signature *sig);

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
			 const struct wireaddr *addr,
			 const struct crypto_state *cs,
			 const u8 *gfeatures,
			 const u8 *lfeatures,
			 int peer_fd, int gossip_fd,
			 const u8 *in_msg);

/**
 * populate_peer -- Populate daemon fields in a peer
 *
 * @ld: the daemon to wire the peer into
 * @peer: the peer to populate
 *
 * Creating a new peer, or loading a peer from the database we need to
 * populate a number of fields, e.g., the logging handler and the
 * pointer to the daemon. populate_peer does exactly that.
 */
void populate_peer(struct lightningd *ld, struct peer *peer);

/* Returns true if these contain any unsupported features. */
bool unsupported_features(const u8 *gfeatures, const u8 *lfeatures);

/* For sending our features: tal_len() returns length. */
u8 *get_supported_global_features(const tal_t *ctx);
u8 *get_supported_local_features(const tal_t *ctx);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

/* Peer has failed, but try reconnected. */
PRINTF_FMT(2,3) void peer_fail_transient(struct peer *peer, const char *fmt,...);
/* Peer has failed, give up on it. */
void peer_fail_permanent(struct peer *peer, const u8 *msg TAKES);
/* Version where we supply the reason string. */
void peer_fail_permanent_str(struct peer *peer, const char *str TAKES);
/* Permanent error, but due to internal problems, not peer. */
void peer_internal_error(struct peer *peer, const char *fmt, ...);

/* Peer has failed to open; return to gossipd. */
void opening_failed(struct peer *peer, const u8 *msg TAKES);

const char *peer_state_name(enum peer_state state);
void peer_set_condition(struct peer *peer, enum peer_state oldstate,
			enum peer_state state);
void setup_listeners(struct lightningd *ld);

void free_htlcs(struct lightningd *ld, const struct peer *peer);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
