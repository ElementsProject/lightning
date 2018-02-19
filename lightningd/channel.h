#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_H
#include "config.h"
#include <ccan/list/list.h>
#include <lightningd/peer_state.h>
#include <wallet/wallet.h>

struct uncommitted_channel;

struct channel {
	/* Inside peer->channels. */
	struct list_node list;

	/* Peer context */
	struct peer *peer;

	/* Database ID: 0 == not in db yet */
	u64 dbid;

	/* Error message (iff in error state) */
	u8 *error;

	/* Their shachain. */
	struct wallet_shachain their_shachain;

 	/* What's happening. */
 	enum peer_state state;

	/* Which side offered channel? */
	enum side funder;

	/* Is there a single subdaemon responsible for us? */
	struct subd *owner;

	/* History */
	struct log *log;

	/* Channel flags from opening message. */
	u8 channel_flags;

	/* Our channel config. */
	struct channel_config our_config;

	/* Minimum funding depth (specified by us if they fund). */
	u32 minimum_depth;

	/* Tracking commitment transaction numbers. */
	u64 next_index[NUM_SIDES];
	u64 next_htlc_id;

	/* Funding txid and amounts (once known) */
	struct bitcoin_txid *funding_txid;
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
	struct privkey seed;

	/* Their scriptpubkey if they sent shutdown. */
	u8 *remote_shutdown_scriptpubkey;
	/* Our key for shutdown (-1 if not chosen yet) */
	s64 local_shutdown_idx;

	/* Reestablishment stuff: last sent commit and revocation details. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;

	/* Blockheight at creation, scans for funding confirmations
	 * will start here */
	u64 first_blocknum;
};

struct channel *new_channel(struct peer *peer, u64 dbid, u32 first_blocknum);

/* This lets us give a more detailed error than just a destructor, and
 * deletes from db. */
void delete_channel(struct channel *channel, const char *why);

const char *channel_state_name(const struct channel *channel);

void channel_set_owner(struct channel *channel, struct subd *owner);

/* Channel has failed, but can try again. */
PRINTF_FMT(2,3) void channel_fail_transient(struct channel *channel,
					    const char *fmt,...);
/* Channel has failed, give up on it. */
void channel_fail_permanent(struct channel *channel, const char *fmt, ...);
/* Permanent error, but due to internal problems, not peer. */
void channel_internal_error(struct channel *channel, const char *fmt, ...);

void channel_set_state(struct channel *channel,
		       enum peer_state old_state,
		       enum peer_state state);

/* Find a channel which is not onchain, if any */
struct channel *peer_active_channel(struct peer *peer);

/* Get active channel for peer, optionally any uncommitted_channel. */
struct channel *active_channel_by_id(struct lightningd *ld,
				     const struct pubkey *id,
				     struct uncommitted_channel **uc);

void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const secp256k1_ecdsa_signature *sig);

static inline bool channel_can_add_htlc(const struct channel *channel)
{
	return channel->state == CHANNELD_NORMAL;
}

static inline bool channel_fees_can_change(const struct channel *channel)
{
	return channel->state == CHANNELD_NORMAL
		|| channel->state == CHANNELD_SHUTTING_DOWN;
}

static inline bool channel_can_remove_htlc(const struct channel *channel)
{
	return channel->state == CHANNELD_NORMAL
		|| channel->state == CHANNELD_SHUTTING_DOWN
		|| channel->state == ONCHAIND_THEIR_UNILATERAL
		|| channel->state == ONCHAIND_OUR_UNILATERAL;
}

static inline bool channel_state_on_chain(enum peer_state state)
{
	return state == ONCHAIND_CHEATED
		|| state == ONCHAIND_THEIR_UNILATERAL
		|| state == ONCHAIND_OUR_UNILATERAL
		|| state == ONCHAIND_MUTUAL;
}

static inline bool channel_on_chain(const struct channel *channel)
{
	return channel_state_on_chain(channel->state);
}

static inline bool channel_active(const struct channel *channel)
{
	return channel->state != FUNDING_SPEND_SEEN
		&& channel->state != CLOSINGD_COMPLETE
		&& !channel_on_chain(channel);
}

static inline bool channel_wants_reconnect(const struct channel *channel)
{
	return channel->state >= CHANNELD_AWAITING_LOCKIN
		&& channel->state <= CLOSINGD_COMPLETE;
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
static inline bool channel_persists(const struct channel *channel)
{
	return channel->state >= CHANNELD_AWAITING_LOCKIN;
}

void derive_channel_seed(struct lightningd *ld, struct privkey *seed,
			 const struct pubkey *peer_id,
			 const u64 dbid);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_H */
