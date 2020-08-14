/* This is the full channel routines, with HTLC support. */
#ifndef LIGHTNING_CHANNELD_FULL_CHANNEL_H
#define LIGHTNING_CHANNELD_FULL_CHANNEL_H
#include "config.h"
#include <channeld/channeld_htlc.h>
#include <channeld/full_channel_error.h>
#include <common/initial_channel.h>
#include <common/sphinx.h>

struct existing_htlc;

/**
 * new_full_channel: Given initial fees and funding, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @funding_txid: The commitment transaction id.
 * @funding_txout: The commitment transaction output number.
 * @minimum_depth: The minimum confirmations needed for funding transaction.
 * @funding: The commitment transaction amount.
 * @local_msat: The amount for the local side (remainder goes to remote)
 * @fee_states: The fee update states.
 * @local: local channel configuration
 * @remote: remote channel configuration
 * @local_basepoints: local basepoints.
 * @remote_basepoints: remote basepoints.
 * @local_fundingkey: local funding key
 * @remote_fundingkey: remote funding key
 * @option_static_remotekey: use `option_static_remotekey`.
 * @option_anchor_outputs: use `option_anchor_outputs`.
 * @opener: which side initiated it.
 *
 * Returns state, or NULL if malformed.
 */
struct channel *new_full_channel(const tal_t *ctx,
				 const struct bitcoin_txid *funding_txid,
				 unsigned int funding_txout,
				 u32 minimum_depth,
				 struct amount_sat funding,
				 struct amount_msat local_msat,
				 const struct fee_states *fee_states,
				 const struct channel_config *local,
				 const struct channel_config *remote,
				 const struct basepoints *local_basepoints,
				 const struct basepoints *remote_basepoints,
				 const struct pubkey *local_funding_pubkey,
				 const struct pubkey *remote_funding_pubkey,
				 bool option_static_remotekey,
				 bool option_anchor_outputs,
				 enum side opener);

/**
 * channel_txs: Get the current commitment and htlc txs for the channel.
 * @ctx: tal context to allocate return value from.
 * @channel: The channel to evaluate
 * @htlc_map: Pointer to htlcs for each tx output (allocated off @ctx).
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @funding_wscript: Pointer to wscript for the funding tx output
 * @per_commitment_point: Per-commitment point to determine keys
 * @commitment_number: The index of this commitment.
 * @side: which side to get the commitment transaction for
 *
 * Returns the unsigned commitment transaction for the committed state
 * for @side, followed by the htlc transactions in output order and
 * fills in @htlc_map, or NULL on key derivation failure.
 */
struct bitcoin_tx **channel_txs(const tal_t *ctx,
				const struct htlc ***htlcmap,
				struct wally_tx_output *direct_outputs[NUM_SIDES],
				const u8 **funding_wscript,
				const struct channel *channel,
				const struct pubkey *per_commitment_point,
				u64 commitment_number,
				enum side side);

/**
 * actual_feerate: what is the actual feerate for the local side.
 * @channel: The channel state
 * @theirsig: The other side's signature
 *
 * The fee calculated on a commitment transaction is a worst-case
 * approximation.  It's also possible that the desired feerate is not
 * met, because the initiator sets it while the other side is adding many
 * htlcs.
 *
 * This is the fee rate we actually care about, if we're going to check
 * whether it's actually too low.
 */
u32 actual_feerate(const struct channel *channel,
		   const struct signature *theirsig);

/**
 * channel_add_htlc: append an HTLC to channel if it can afford it
 * @channel: The channel
 * @offerer: the side offering the HTLC (to the other side).
 * @id: unique HTLC id.
 * @amount: amount in millisatoshi.
 * @cltv_expiry: block number when HTLC can no longer be redeemed.
 * @payment_hash: hash whose preimage can redeem HTLC.
 * @routing: routing information (copied)
 * @blinding: optional blinding information for this HTLC.
 * @htlcp: optional pointer for resulting htlc: filled in if and only if CHANNEL_ERR_NONE.
 *
 * If this returns CHANNEL_ERR_NONE, the fee htlc was added and
 * the output amounts adjusted accordingly.  Otherwise nothing
 * is changed.
 */
enum channel_add_err channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      struct amount_msat msatoshi,
				      u32 cltv_expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[TOTAL_PACKET_SIZE],
				      const struct pubkey *blinding TAKES,
				      struct htlc **htlcp,
				      struct amount_sat *htlc_fee);

/**
 * channel_get_htlc: find an HTLC
 * @channel: The channel
 * @offerer: the side offering the HTLC.
 * @id: unique HTLC id.
 */
struct htlc *channel_get_htlc(struct channel *channel, enum side sender, u64 id);

/**
 * channel_fail_htlc: remove an HTLC, funds to the side which offered it.
 * @channel: The channel state
 * @owner: the side who offered the HTLC (opposite to that failing it)
 * @id: unique HTLC id.
 * @htlcp: optional pointer for failed htlc: filled in if and only if CHANNEL_ERR_REMOVE_OK.
 *
 * This will remove the htlc and credit the value of the HTLC (back)
 * to its offerer.
 */
enum channel_remove_err channel_fail_htlc(struct channel *channel,
					  enum side owner, u64 id,
					  struct htlc **htlcp);

/**
 * channel_fulfill_htlc: remove an HTLC, funds to side which accepted it.
 * @channel: The channel state
 * @owner: the side who offered the HTLC (opposite to that fulfilling it)
 * @id: unique HTLC id.
 * @htlcp: optional pointer for resulting htlc: filled in if and only if CHANNEL_ERR_FULFILL_OK.
 *
 * If the htlc exists, is not already fulfilled, the preimage is correct and
 * HTLC committed at the recipient, this will add a pending change to
 * remove the htlc and give the value of the HTLC to its recipient,
 * and return CHANNEL_ERR_FULFILL_OK.  Otherwise, it will return another error.
 */
enum channel_remove_err channel_fulfill_htlc(struct channel *channel,
					     enum side owner,
					     u64 id,
					     const struct preimage *preimage,
					     struct htlc **htlcp);

/**
 * approx_max_feerate: what's the max opener could raise fee rate to?
 * @channel: The channel state
 *
 * This is not exact!  To check if their offer is valid, try
 * channel_update_feerate.
 */
u32 approx_max_feerate(const struct channel *channel);

/**
 * can_opener_afford_feerate: could the opener pay the fee?
 * @channel: The channel state
 * @feerate: The feerate in satoshi per 1000 bytes.
 */
bool can_opener_afford_feerate(const struct channel *channel, u32 feerate);

/**
 * channel_update_feerate: Change fee rate on non-opener side.
 * @channel: The channel
 * @feerate_per_kw: fee in satoshi per 1000 bytes.
 *
 * Returns true if it's affordable, otherwise does nothing.
 */
bool channel_update_feerate(struct channel *channel, u32 feerate_per_kw);

/**
 * channel_feerate: Get fee rate for this side of channel.
 * @channel: The channel
 * @side: the side
 */
u32 channel_feerate(const struct channel *channel, enum side side);

/**
 * channel_sending_commit: commit all remote outstanding changes.
 * @channel: the channel
 * @htlcs: initially-empty tal_arr() for htlcs which changed state.
 *
 * This is where we commit to pending changes we've added; returns true if
 * anything changed for the remote side (if not, don't send!) */
bool channel_sending_commit(struct channel *channel,
			    const struct htlc ***htlcs);

/**
 * channel_rcvd_revoke_and_ack: accept ack on remote committed changes.
 * @channel: the channel
 * @htlcs: initially-empty tal_arr() for htlcs which changed state.
 *
 * This is where we commit to pending changes we've added; returns true if
 * anything changed for our local commitment (ie. we have pending changes).
 */
bool channel_rcvd_revoke_and_ack(struct channel *channel,
				 const struct htlc ***htlcs);

/**
 * channel_rcvd_commit: commit all local outstanding changes.
 * @channel: the channel
 * @htlcs: initially-empty tal_arr() for htlcs which changed state.
 *
 * This is where we commit to pending changes we've added; returns true if
 * anything changed for our local commitment (ie. we had pending changes).
 */
bool channel_rcvd_commit(struct channel *channel,
			 const struct htlc ***htlcs);

/**
 * channel_sending_revoke_and_ack: sending ack on local committed changes.
 * @channel: the channel
 *
 * This is where we commit to pending changes we've added. Returns true if
 * anything changed for the remote commitment (ie. send a new commit).*/
bool channel_sending_revoke_and_ack(struct channel *channel);

/**
 * num_channel_htlcs: how many (live) HTLCs at all in channel?
 * @channel: the channel
 */
size_t num_channel_htlcs(const struct channel *channel);

/**
 * channel_force_htlcs: force these htlcs into the (new) channel
 * @channel: the channel
 * @htlcs: the htlcs to add (tal_arr) elements stolen.
 *
 * This is used for restoring a channel state.
 */
bool channel_force_htlcs(struct channel *channel,
			 const struct existing_htlc **htlcs);

/**
 * dump_htlcs: debugging dump of all HTLCs
 * @channel: the channel
 * @prefix: the prefix to prepend to each line.
 *
 * Uses status_debug() on every HTLC.
 */
void dump_htlcs(const struct channel *channel, const char *prefix);

const char *channel_add_err_name(enum channel_add_err e);
const char *channel_remove_err_name(enum channel_remove_err e);

#endif /* LIGHTNING_CHANNELD_FULL_CHANNEL_H */
