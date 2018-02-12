#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_H
#include "config.h"
#include <ccan/list/list.h>
#include <lightningd/peer_state.h>
#include <wallet/wallet.h>

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

	/* Command which ordered us to open channel, if any. */
	struct command *opening_cmd;

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

const char *channel_state_name(const struct channel *channel);

void derive_channel_seed(struct lightningd *ld, struct privkey *seed,
			 const struct pubkey *peer_id,
			 const u64 dbid);

/* FIXME: Temporary mapping from peer to channel, while we only have one. */
struct channel *peer2channel(const struct peer *peer);
struct peer *channel2peer(const struct channel *channel);

/* Find a channel which is not onchain, if any */
struct channel *peer_active_channel(struct peer *peer);

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

/* FIXME: Obsolete */
static inline bool peer_can_add_htlc(const struct peer *peer)
{
	return channel_can_add_htlc(peer2channel(peer));
}

static inline bool peer_fees_can_change(const struct peer *peer)
{
	return channel_fees_can_change(peer2channel(peer));
}

static inline bool peer_can_remove_htlc(const struct peer *peer)
{
	return channel_can_remove_htlc(peer2channel(peer));
}

static inline bool peer_on_chain(const struct peer *peer)
{
	return channel_state_on_chain(peer2channel(peer)->state);
}

static inline bool peer_wants_reconnect(const struct peer *peer)
{
	return channel_wants_reconnect(peer2channel(peer));
}

static inline bool peer_persists(const struct peer *peer)
{
	return channel_persists(peer2channel(peer));
}
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_H */
