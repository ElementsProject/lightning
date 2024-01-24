#ifndef LIGHTNING_CHANNELD_SPLICE_H
#define LIGHTNING_CHANNELD_SPLICE_H

#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <channeld/inflight.h>
#include <common/amount.h>
#include <common/htlc.h>

/* The channel's general splice state for tracking splice candidates */
struct splice_state {
	/* The active inflights */
	struct inflight **inflights;
	/* The pending short channel id for a splice. Set when mutual lock. */
	struct short_channel_id short_channel_id;
	/* Set to old short channel id when mutual lock occurs.  */
	struct short_channel_id last_short_channel_id;
	/* Tally of which sides are locked, or not */
	bool locked_ready[NUM_SIDES];
	/* Set to true when commitment cycle completes successfully */
	bool await_commitment_succcess;
	/* The txid of which splice inflight was confirmed */
	struct bitcoin_txid locked_txid;
	/* The number of splices that are active (awaiting confirmation) */
	u32 count;
};

/* Sets `splice_state` items to default values */
struct splice_state *splice_state_new(const tal_t *ctx);

/* An active splice negotiation. Born when splice beings and dies when a splice
 * negotation has finished */
struct splicing {
	/* The opener side's relative balance change */
	s64 opener_relative;
	/* The accepter side's relative balance change */
	s64 accepter_relative;
	/* The feerate for the splice (on set for the initiator) */
	u32 feerate_per_kw;
	/* If the feerate is higher than max, don't abort the splice */
	bool force_feerate;
	/* Make our side sign first */
	bool force_sign_first;
	/* After `splice` and `splice_ack` occur, we are in splice mode */
	bool mode;
	/* Track how many of each tx collab msg we receive */
	u16 tx_add_input_count, tx_add_output_count;
	/* Current negoitated psbt */
	struct wally_psbt *current_psbt;
	/* If, in the last splice_update, was tx_complete was received */
	bool received_tx_complete;
	/* If, in the last splice_update, we sent tx_complete */
	bool sent_tx_complete;
	/* If our peer signs early, we allow that and cache it here */
	const u8 *tx_sig_msg;
};

/* Sets `splice` items to default values */
struct splicing *splicing_new(const tal_t *ctx);

#endif /* LIGHTNING_CHANNELD_SPLICE_H */
