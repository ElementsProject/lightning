/* This represents a channel with no HTLCs: all that's required for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_CHANNEL_H
#define LIGHTNING_COMMON_INITIAL_CHANNEL_H
#include "config.h"

#include <bitcoin/tx.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>

struct signature;
struct added_htlc;
struct failed_htlc;
struct fulfilled_htlc;

/* View from each side */
struct channel_view {
	/* How much is owed to each side (includes pending changes).
	 * The index of `owed` array is always relative to the machine
	 * this code is running on, so REMOTE is always the other machine
	 * and LOCAL is always this machine (regardless of view).
	 *
	 * For example:
	 * view[REMOTE].owed[REMOTE] == view[LOCAL].owed[REMOTE]
	 * view[REMOTE].owed[LOCAL] == view[LOCAL].owed[LOCAL]
	 */
	struct amount_msat owed[NUM_SIDES];
	/* Lowest splice relative change amount of all candidate splices.
	 * This will be 0 or negative -- never positive. */
	s64 lowest_splice_amnt[NUM_SIDES];
};

struct channel {

	/* The id for this channel */
	struct channel_id cid;

	/* Funding txid and output. */
	struct bitcoin_outpoint funding;

	/* Keys used to spend funding tx. */
	struct pubkey funding_pubkey[NUM_SIDES];

	/* satoshis in from commitment tx */
	struct amount_sat funding_sats;

	/* confirmations needed for locking funding */
	u32 minimum_depth;

	/* Who is paying fees. */
	enum side opener;

	/* Limits and settings on this channel. */
	struct channel_config config[NUM_SIDES];

	/* Basepoints for deriving keys. */
	struct basepoints basepoints[NUM_SIDES];

	/* Mask for obscuring the encoding of the commitment number. */
	u64 commitment_number_obscurer;

	/* All live HTLCs for this channel */
	struct htlc_map *htlcs;

	/* Fee changes, some which may be in transit */
	struct fee_states *fee_states;

	/* Blockheight changes, some which may be in transit
	 * (option_will_fund)*/
	struct height_states *blockheight_states;

	/* What it looks like to each side. */
	struct channel_view view[NUM_SIDES];

	/* Features which apply to this channel. */
	struct channel_type *type;

	/* Are we using big channels? */
	bool option_wumbo;

	/* When the lease expires for the funds in this channel */
	u32 lease_expiry;
};

/**
 * new_initial_channel: Given initial fees and funding, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @cid: The channel's id.
 * @funding: The commitment transaction id/outnum
 * @minimum_depth: The minimum confirmations needed for funding transaction.
 * @height_states: The blockheight update states.
 * @lease_expiry: Block the lease expires.
 * @funding_sats: The commitment transaction amount.
 * @local_msatoshi: The amount for the local side (remainder goes to remote)
 * @fee_states: The fee update states.
 * @local: local channel configuration
 * @remote: remote channel configuration
 * @local_basepoints: local basepoints.
 * @remote_basepoints: remote basepoints.
 * @local_fundingkey: local funding key
 * @remote_fundingkey: remote funding key
 * @type: type for this channel
 * @option_wumbo: has peer currently negotiated wumbo?
 * @opener: which side initiated it.
 *
 * Returns channel, or NULL if malformed.
 */
struct channel *new_initial_channel(const tal_t *ctx,
				    const struct channel_id *cid,
				    const struct bitcoin_outpoint *funding,
				    u32 minimum_depth,
				    const struct height_states *height_states TAKES,
				    u32 lease_expiry,
				    struct amount_sat funding_sats,
				    struct amount_msat local_msatoshi,
				    const struct fee_states *fee_states TAKES,
				    const struct channel_config *local,
				    const struct channel_config *remote,
				    const struct basepoints *local_basepoints,
				    const struct basepoints *remote_basepoints,
				    const struct pubkey *local_funding_pubkey,
				    const struct pubkey *remote_funding_pubkey,
				    const struct channel_type *type TAKES,
				    bool option_wumbo,
				    enum side opener);

/**
 * initial_channel_tx: Get the current commitment tx for the *empty* channel.
 * @ctx: tal context to allocate return value from.
 * @wscript: wscripts for the commitment tx.
 * @channel: The channel to evaluate
 * @per_commitment_point: Per-commitment point to determine keys
 * @side: which side to get the commitment transaction for
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 * Returns the unsigned initial commitment transaction for @side, or NULL
 * if the channel size was insufficient to cover fees or reserves.
 */
struct bitcoin_tx *initial_channel_tx(const tal_t *ctx,
				      const u8 **wscript,
				      const struct channel *channel,
				      const struct pubkey *per_commitment_point,
				      enum side side,
				      struct wally_tx_output *direct_outputs[NUM_SIDES],
				      char** err_reason);

/* channel_update_funding: Changes the funding for the channel and updates the
 * balance by the difference between `old_local_funding_msatoshi` and
 * `new_local_funding_msatoshi`.
 *
 * Returns NULL on success or an error on failure.
 */
const char *channel_update_funding(struct channel *channel,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   s64 splice_amnt);

/**
 * channel_feerate: Get fee rate for this side of channel.
 * @channel: The channel
 * @side: the side
 */
u32 channel_feerate(const struct channel *channel, enum side side);

/**
 * channel_blockheight: Get blockheight for this side of channel.
 * @channel: The channel
 * @side: the side
 */
u32 channel_blockheight(const struct channel *channel, enum side side);

/* What can we upgrade to?  (Returns NULL if none). */
struct channel_type *channel_upgradable_type(const tal_t *ctx,
					     const struct channel *channel);

/* What channel type do we want? */
struct channel_type *channel_desired_type(const tal_t *ctx,
					  const struct channel *channel);

/* Convenience for querying channel->type */
bool channel_has(const struct channel *channel, int feature);

/* Convenience for querying either anchor_outputs or anchors_zero_fee_htlc_tx */
bool channel_has_anchors(const struct channel *channel);

char *fmt_channel(const tal_t *ctx, const struct channel *channel);
#endif /* LIGHTNING_COMMON_INITIAL_CHANNEL_H */
