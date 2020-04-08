/* This represents a channel with no HTLCs: all that's required for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_CHANNEL_H
#define LIGHTNING_COMMON_INITIAL_CHANNEL_H
#include "config.h"

#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/channel_config.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>
#include <stdbool.h>

struct signature;
struct added_htlc;
struct failed_htlc;
struct fulfilled_htlc;

/* View from each side */
struct channel_view {
	/* How much is owed to each side (includes pending changes) */
	struct amount_msat owed[NUM_SIDES];
};

struct channel {
	/* Funding txid and output. */
	struct bitcoin_txid funding_txid;
	unsigned int funding_txout;

	/* Keys used to spend funding tx. */
	struct pubkey funding_pubkey[NUM_SIDES];

	/* satoshis in from commitment tx */
	struct amount_sat funding;

	/* confirmations needed for locking funding */
	u32 minimum_depth;

	/* Who is paying fees. */
	enum side funder;

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

	/* What it looks like to each side. */
	struct channel_view view[NUM_SIDES];

	/* Is this using option_static_remotekey? */
	bool option_static_remotekey;
};

/**
 * new_initial_channel: Given initial fees and funding, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @funding_txid: The commitment transaction id.
 * @funding_txout: The commitment transaction output number.
 * @minimum_depth: The minimum confirmations needed for funding transaction.
 * @funding_satoshis: The commitment transaction amount.
 * @local_msatoshi: The amount for the local side (remainder goes to remote)
 * @fee_states: The fee update states.
 * @local: local channel configuration
 * @remote: remote channel configuration
 * @local_basepoints: local basepoints.
 * @remote_basepoints: remote basepoints.
 * @local_fundingkey: local funding key
 * @remote_fundingkey: remote funding key
 * @funder: which side initiated it.
 *
 * Returns channel, or NULL if malformed.
 */
struct channel *new_initial_channel(const tal_t *ctx,
				    const struct bitcoin_txid *funding_txid,
				    unsigned int funding_txout,
				    u32 minimum_depth,
				    struct amount_sat funding,
				    struct amount_msat local_msatoshi,
				    const struct fee_states *fee_states TAKES,
				    const struct channel_config *local,
				    const struct channel_config *remote,
				    const struct basepoints *local_basepoints,
				    const struct basepoints *remote_basepoints,
				    const struct pubkey *local_funding_pubkey,
				    const struct pubkey *remote_funding_pubkey,
				    bool option_static_remotekey,
				    enum side funder);


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

/**
 * channel_feerate: Get fee rate for this side of channel.
 * @channel: The channel
 * @side: the side
 */
u32 channel_feerate(const struct channel *channel, enum side side);

#endif /* LIGHTNING_COMMON_INITIAL_CHANNEL_H */
