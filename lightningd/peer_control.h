#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <daemon/htlc.h>
#include <daemon/json.h>
#include <daemon/netaddr.h>
#include <lightningd/channel_config.h>
#include <lightningd/peer_state.h>
#include <stdbool.h>
#include <wire/peer_wire.h>

#define ANNOUNCE_MIN_DEPTH 6

struct crypto_state;

struct peer {
	struct lightningd *ld;

	/* Unique ID of connection (works even if we have multiple to same id) */
	u64 unique_id;

	/* ID of peer */
	struct pubkey id;

	/* Error message (iff in error state) */
	u8 *error;

	/* Their shachain. */
	struct shachain their_shachain;

 	/* What's happening. */
 	enum peer_state state;

	/* Which side offered channel? */
	enum side funder;

	/* Inside ld->peers. */
	struct list_node list;

	/* What stage is this in?  NULL during first creation. */
	struct subd *owner;

	/* History */
	struct log_book *log_book;
	struct log *log;

	/* Channel flags from opening message. */
	u8 channel_flags;

	/* If we've disconnected, this is set. */
	bool reconnected;

	/* Where we connected to, or it connected from. */
	struct netaddr netaddr;

	/* Our channel config. */
	struct channel_config our_config;

	/* Minimum funding depth (specified by us if they fund). */
	u32 minimum_depth;

	/* Tracking commitment transaction numbers. */
	u64 next_index[NUM_SIDES];
	u64 num_revocations_received;
	u64 next_htlc_id;

	/* Funding txid and amounts (once known) */
	struct sha256_double *funding_txid;
	u16 funding_outnum;
	u64 funding_satoshi, push_msat;
	bool remote_funding_locked;
	/* Channel if locked locally. */
	struct short_channel_id *scid;

	/* Amount going to us, not counting unfinished HTLCs; if we have one. */
	u64 *balance;

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
};

static inline bool peer_can_add_htlc(const struct peer *peer)
{
	return peer->state == CHANNELD_NORMAL;
}

static inline bool peer_can_remove_htlc(const struct peer *peer)
{
	return peer->state == CHANNELD_NORMAL
		|| peer->state == CHANNELD_SHUTTING_DOWN
		|| peer->state == ONCHAIND_THEIR_UNILATERAL
		|| peer->state == ONCHAIND_OUR_UNILATERAL;
}

static inline bool peer_on_chain(const struct peer *peer)
{
	return peer->state == ONCHAIND_CHEATED
		|| peer->state == ONCHAIND_THEIR_UNILATERAL
		|| peer->state == ONCHAIND_OUR_UNILATERAL
		|| peer->state == ONCHAIND_MUTUAL;
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

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id);
struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    jsmntok_t *peeridtok);

void peer_fundee_open(struct peer *peer, const u8 *msg,
		      const struct crypto_state *cs,
		      int peer_fd, int gossip_fd);

void add_peer(struct lightningd *ld, u64 unique_id,
	      int fd, const struct pubkey *id,
	      const struct crypto_state *cs);

/* Could be configurable. */
#define OUR_CHANNEL_FLAGS CHANNEL_FLAGS_ANNOUNCE_CHANNEL

/* Peer has failed, but try reconnected. */
PRINTF_FMT(2,3) void peer_fail_transient(struct peer *peer, const char *fmt,...);
/* Peer has failed, give up on it. */
void peer_fail_permanent(struct peer *peer, const u8 *msg TAKES);
/* Permanent error, but due to internal problems, not peer. */
void peer_internal_error(struct peer *peer, const char *fmt, ...);

const char *peer_state_name(enum peer_state state);
void peer_set_condition(struct peer *peer, enum peer_state oldstate,
			enum peer_state state);
void setup_listeners(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
