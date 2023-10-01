#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_H
#include "config.h"
#include <common/channel_id.h>
#include <common/channel_type.h>
#include <common/scb_wiregen.h>
#include <common/tx_roles.h>
#include <common/utils.h>
#include <lightningd/channel_state.h>
#include <wallet/wallet.h>

struct uncommitted_channel;
struct wally_psbt;

struct billboard {
	/* Status information to display on listpeers */
	const char *permanent[CHANNEL_STATE_MAX+1];
	const char *transient;
};

struct funding_info {
	struct bitcoin_outpoint outpoint;
	u32 feerate;
	struct amount_sat total_funds;

	/* Our original funds, in funding amount */
	struct amount_sat our_funds;

	/* Relative splicing balance change */
	s64 splice_amnt;
};

struct channel_inflight {
	/* Inside channel->inflights. */
	struct list_node list;

	/* Channel context */
	struct channel *channel;

	/* Funding info */
	const struct funding_info *funding;
	struct wally_psbt *funding_psbt;
	bool remote_tx_sigs;
	bool tx_broadcast;

	/* Commitment tx and sigs */
	struct bitcoin_tx *last_tx;
	struct bitcoin_signature last_sig;

	/* Channel lease infos */
	u32 lease_expiry;
	secp256k1_ecdsa_signature *lease_commit_sig;
	u32 lease_chan_max_msat;
	u16 lease_chan_max_ppt;
	u32 lease_blockheight_start;

	/* We save this data so we can do nice accounting;
	 * on the channel we slot it into the 'push' field */
	struct amount_msat lease_fee;

	/* Amount requested to lease for this open */
	struct amount_sat lease_amt;

	/* Did I initate this splice attempt? */
	bool i_am_initiator;

	/* Note: This field is not stored in the database.
	 *
	 * After splice_locked, we need a way to stop the chain watchers from
	 * thinking the old channel was spent.
	 *
	 * Leaving the inflight in memory-only with splice_locked true leaves
	 * moves the responsiblity of cleaning up the inflight to the watcher,
	 * avoiding any potential race conditions. */
	bool splice_locked_memonly;
};

struct open_attempt {
	/* on uncommitted_channel struct */
	struct channel *channel;
	struct channel_config our_config;
	enum tx_role role;
	bool aborted;

	/* On funding_channel struct */
	struct command *cmd;
	struct amount_sat funding;
	const u8 *our_upfront_shutdown_script;

	/* First msg to send to dualopend (to make it create channel) */
	const u8 *open_msg;
};

struct channel {
	/* Inside peer->channels. */
	struct list_node list;

	/* Peer context */
	struct peer *peer;

	/* Inflight channel opens */
	struct list_head inflights;

	/* Open attempt */
	struct open_attempt *open_attempt;

	/* Database ID: 0 == not in db yet */
	u64 dbid;

	/* Populated by new_unsaved_channel */
	u64 unsaved_dbid;

	/* Error message (iff in error state) */
	u8 *error;

	/* Their shachain. */
	struct wallet_shachain their_shachain;

 	/* What's happening. */
 	enum channel_state state;

	/* Which side offered channel? */
	enum side opener;

	/* Is there a single subdaemon responsible for us? */
	struct subd *owner;

	/* History */
	struct logger *log;
	struct billboard billboard;

	/* Channel flags from opening message. */
	u8 channel_flags;

	/* Our channel config. */
	struct channel_config our_config;

	/* Require confirmed inputs for interactive tx */
	bool req_confirmed_ins[NUM_SIDES];

	/* Minimum funding depth (specified by us if they fund). */
	u32 minimum_depth;

	/* Depth of the funding TX as reported by the txout
	 * watch. Only used while we're in state
	 * CHANNELD_AWAITING_LOCKING, afterwards the watches do not
	 * trigger anymore. */
	u32 depth;

	/* Tracking commitment transaction numbers. */
	u64 next_index[NUM_SIDES];
	u64 next_htlc_id;

	/* Funding outpoint and amount */
	struct bitcoin_outpoint funding;
	struct amount_sat funding_sats;

	/* Watch we have on funding output. */
	struct txowatch *funding_spend_watch;

	/* Our original funds, in funding amount */
	struct amount_sat our_funds;

	struct amount_msat push;
	bool remote_channel_ready;
	/* Channel if locked locally. */
	struct short_channel_id *scid;

	/* Alias used for option_zeroconf, or option_scid_alias, if
	 * present. LOCAL are all the alias we told the peer about and
	 * REMOTE is one of the aliases we got from the peer and we'll
	 * use in a routehint. */
	struct short_channel_id *alias[NUM_SIDES];

	struct channel_id cid;

	/* Amount going to us, not counting unfinished HTLCs; if we have one. */
	struct amount_msat our_msat;
	/* Statistics for min and max our_msatoshi. */
	struct amount_msat msat_to_us_min;
	struct amount_msat msat_to_us_max;

	/* Last tx they gave us. */
	struct bitcoin_tx *last_tx;
	struct bitcoin_signature last_sig;
	const struct bitcoin_signature *last_htlc_sigs;

	/* Keys for channel */
	struct channel_info channel_info;

	/* Fee status */
	const struct fee_states *fee_states;

	/* Height states (option_will_fund, update_blockheight) */
	const struct height_states *blockheight_states;

	/* Our local basepoints */
	struct basepoints local_basepoints;

	/* Our funding tx pubkey. */
	struct pubkey local_funding_pubkey;

	/* scriptpubkey for shutdown, if applicable. */
	const u8 *shutdown_scriptpubkey[NUM_SIDES];
	/* Address for any final outputs */
	u64 final_key_idx;

	/* Amount to give up on each step of the closing fee negotiation. */
	u64 closing_fee_negotiation_step;

	/* Whether closing_fee_negotiation_step is in satoshi or %. */
	u8 closing_fee_negotiation_step_unit;

	/* optional wrong_funding for mutual close */
	const struct bitcoin_outpoint *shutdown_wrong_funding;

	/* optional feerate min/max for mutual close */
	u32 *closing_feerate_range;

	/* Reestablishment stuff: last sent commit and revocation details. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;

	/* Blockheight at creation, scans for funding confirmations
	 * will start here */
	u32 first_blocknum;

	/* Feerate range */
	u32 min_possible_feerate, max_possible_feerate;

	/* Do we have an "impossible" future per_commitment_point from
	 * peer via option_data_loss_protect? */
	const struct pubkey *future_per_commitment_point;

	/* Min/max htlc amount allowed in channel. */
	struct amount_msat htlc_minimum_msat, htlc_maximum_msat;

	/* Feerate per channel */
	u32 feerate_base, feerate_ppm;

	/* But allow these feerates/htlcs up until this time. */
	struct timeabs old_feerate_timeout;
	u32 old_feerate_base, old_feerate_ppm;
	struct amount_msat old_htlc_minimum_msat, old_htlc_maximum_msat;

	/* If they used option_upfront_shutdown_script. */
	const u8 *remote_upfront_shutdown_script;

	/* At what commit numbers does `option_static_remotekey` apply? */
	u64 static_remotekey_start[NUM_SIDES];

	/* What features apply to this channel? */
	const struct channel_type *type;

	/* Any commands trying to forget us. */
	struct command **forgets;

	/* Our position in the round-robin list.  */
	u64 rr_number;

	/* the one that initiated a bilateral close, NUM_SIDES if unknown. */
	enum side closer;

	/* Block height we saw closing tx at */
	u32 *close_blockheight;

	/* Last known state_change cause */
	enum state_change state_change_cause;

	/* Outstanding command for this channel, v2 only */
	struct command *openchannel_signed_cmd;

	/* Block lease expires at, zero is no lease */
	u32 lease_expiry;

	/* Lease commitment, useful someone breaks their promise
	 * wrt channel fees */
	secp256k1_ecdsa_signature *lease_commit_sig;

	/* Lease commited maximum channel fee base msat */
	u32 lease_chan_max_msat;
	/* Lease commited max part per thousandth channel fee (ppm * 1000) */
	u16 lease_chan_max_ppt;

	/* Latest channel_update, for use in error messages. */
	u8 *channel_update;

	/* `Channel-shell` of this channel
	 * (Minimum information required to backup this channel). */
	struct scb_chan *scb;

	/* Do we allow the peer to set any fee it wants? */
	bool ignore_fee_limits;
};

bool channel_is_connected(const struct channel *channel);

/* For v2 opens, a channel that has not yet been committed/saved to disk */
struct channel *new_unsaved_channel(struct peer *peer,
				    u32 feerate_base,
				    u32 feerate_ppm);

struct open_attempt *new_channel_open_attempt(struct channel *channel);

struct channel *new_channel(struct peer *peer, u64 dbid,
			    /* NULL or stolen */
			    struct wallet_shachain *their_shachain STEALS,
			    enum channel_state state,
			    enum side opener,
			    /* NULL or stolen */
			    struct logger *log STEALS,
			    const char *transient_billboard TAKES,
			    u8 channel_flags,
			    bool req_confirmed_ins_local,
			    bool req_confirmed_ins_remote,
			    const struct channel_config *our_config,
			    u32 minimum_depth,
			    u64 next_index_local,
			    u64 next_index_remote,
			    u64 next_htlc_id,
			    const struct bitcoin_outpoint *funding,
			    struct amount_sat funding_sats,
			    struct amount_msat push,
			    struct amount_sat our_funds,
			    bool remote_channel_ready,
			    /* NULL or stolen */
			    struct short_channel_id *scid STEALS,
			    struct short_channel_id *alias_local STEALS,
			    struct short_channel_id *alias_remote STEALS,
			    struct channel_id *cid,
			    struct amount_msat our_msatoshi,
			    struct amount_msat msatoshi_to_us_min,
			    struct amount_msat msatoshi_to_us_max,
			    struct bitcoin_tx *last_tx STEALS,
			    const struct bitcoin_signature *last_sig,
			    /* NULL or stolen */
			    const struct bitcoin_signature *last_htlc_sigs STEALS,
			    const struct channel_info *channel_info,
			    const struct fee_states *fee_states TAKES,
			    /* NULL or stolen */
			    u8 *remote_shutdown_scriptpubkey STEALS,
			    const u8 *local_shutdown_scriptpubkey,
			    u64 final_key_idx,
			    bool last_was_revoke,
			    /* NULL or stolen */
			    struct changed_htlc *last_sent_commit STEALS,
			    u32 first_blocknum,
			    u32 min_possible_feerate,
			    u32 max_possible_feerate,
			    const struct basepoints *local_basepoints,
			    const struct pubkey *local_funding_pubkey,
			    const struct pubkey *future_per_commitment_point,
			    u32 feerate_base,
			    u32 feerate_ppm,
			    /* NULL or stolen */
			    const u8 *remote_upfront_shutdown_script STEALS,
			    u64 local_static_remotekey_start,
			    u64 remote_static_remotekey_start,
			    const struct channel_type *type STEALS,
			    enum side closer,
			    enum state_change reason,
			    /* NULL or stolen */
			    const struct bitcoin_outpoint *shutdown_wrong_funding STEALS,
			    const struct height_states *height_states TAKES,
			    u32 lease_expiry,
			    secp256k1_ecdsa_signature *lease_commit_sig STEALS,
			    u32 lease_chan_max_msat,
			    u16 lease_chan_max_ppt,
			    struct amount_msat htlc_minimum_msat,
			    struct amount_msat htlc_maximum_msat,
			    bool ignore_fee_limits);

/* new_inflight - Create a new channel_inflight for a channel */
struct channel_inflight *new_inflight(struct channel *channel,
	     const struct bitcoin_outpoint *funding_outpoint,
	     u32 funding_feerate,
	     struct amount_sat funding_sat,
	     struct amount_sat our_funds,
	     struct wally_psbt *funding_psbt STEALS,
	     struct bitcoin_tx *last_tx STEALS,
	     const struct bitcoin_signature last_sig,
	     const u32 lease_expiry,
	     const secp256k1_ecdsa_signature *lease_commit_sig,
	     const u32 lease_chan_max_msat,
	     const u16 lease_chan_max_ppt,
	     const u32 lease_blockheight_start,
	     const struct amount_msat lease_fee,
	     const struct amount_sat lease_amt,
	     s64 splice_amnt,
	     bool i_am_initiator);

/* Given a txid, find an inflight channel stub. Returns NULL if none found */
struct channel_inflight *channel_inflight_find(struct channel *channel,
					       const struct bitcoin_txid *txid);

/* What's the most recent inflight for this channel? */
struct channel_inflight *
channel_current_inflight(const struct channel *channel);

/* What's the last feerate used for a funding tx on this channel? */
u32 channel_last_funding_feerate(const struct channel *channel);

void delete_channel(struct channel *channel STEALS);

const char *channel_state_name(const struct channel *channel);
const char *channel_state_str(enum channel_state state);

/* Can this channel send an HTLC? */
static inline bool channel_state_can_add_htlc(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_SIGEXCHANGE:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
		return false;
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
		return true;
	}
	abort();
}

/* Can this channel remove an HTLC? */
static inline bool channel_state_can_remove_htlc(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case CLOSINGD_SIGEXCHANGE:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
		return false;
	case CHANNELD_SHUTTING_DOWN:
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
		return true;
	}
	abort();
}

static inline bool channel_state_closing(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case CHANNELD_NORMAL:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
	case CHANNELD_AWAITING_SPLICE:
		return false;
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_SIGEXCHANGE:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		return true;
	}
	abort();
}

static inline bool channel_state_fees_can_change(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
		return false;
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CLOSINGD_SIGEXCHANGE:
		return true;
	}
	abort();
}

static inline bool channel_state_failing_onchain(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CLOSINGD_SIGEXCHANGE:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_COMPLETE:
	case CLOSED:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
		return false;
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
		return true;
	}
	abort();
}

static inline bool channel_state_pre_open(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
		return true;
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CLOSINGD_SIGEXCHANGE:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		return false;
	}
	abort();
}

static inline bool channel_state_closed(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CLOSINGD_SIGEXCHANGE:
	case CHANNELD_SHUTTING_DOWN:
		return false;
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		return true;
	}
	abort();
}

/* Not even int the database yet? */
static inline bool channel_state_uncommitted(enum channel_state state)
{
	switch (state) {
 	case DUALOPEND_OPEN_INIT:
		return true;
	case DUALOPEND_OPEN_COMMITTED:
	case CHANNELD_AWAITING_LOCKIN:
 	case DUALOPEND_AWAITING_LOCKIN:
 	case CHANNELD_NORMAL:
 	case CHANNELD_AWAITING_SPLICE:
 	case CLOSINGD_SIGEXCHANGE:
 	case CHANNELD_SHUTTING_DOWN:
 	case CLOSINGD_COMPLETE:
 	case AWAITING_UNILATERAL:
 	case FUNDING_SPEND_SEEN:
 	case ONCHAIN:
 	case CLOSED:
		return false;
	}
	abort();
}

/* Established enough, that we could reach out to peer to discuss */
static inline bool channel_state_wants_peercomms(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case DUALOPEND_AWAITING_LOCKIN:
	case DUALOPEND_OPEN_COMMITTED:
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CLOSINGD_SIGEXCHANGE:
	case CHANNELD_SHUTTING_DOWN:
		return true;
	case DUALOPEND_OPEN_INIT:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		return false;
	}
	abort();
}

/* Established enough, that we have to fail onto chain */
static inline bool channel_state_wants_onchain_fail(enum channel_state state)
{
	switch (state) {
	case CHANNELD_AWAITING_LOCKIN:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CLOSINGD_SIGEXCHANGE:
	case CHANNELD_SHUTTING_DOWN:
		return true;
	case DUALOPEND_OPEN_INIT:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case FUNDING_SPEND_SEEN:
	case ONCHAIN:
	case CLOSED:
		return false;
	}
	abort();
}

void channel_set_owner(struct channel *channel, struct subd *owner);

/* Channel has failed, but can try again.  Usually, set disconnect to true. */
void channel_fail_transient(struct channel *channel,
			    bool disconnect,
			    const char *fmt, ...) PRINTF_FMT(3, 4);

/* Channel has failed, give up on it. */
void channel_fail_permanent(struct channel *channel,
			    enum state_change reason,
			    const char *fmt,
			    ...);
/* Forget the channel. This is only used for the case when we "receive" error
 * during CHANNELD_AWAITING_LOCKIN if we are "fundee". */
void channel_fail_forget(struct channel *channel, const char *fmt, ...);
/* Permanent error, but due to internal problems, not peer. */
void channel_internal_error(struct channel *channel, const char *fmt, ...);

/* Clean up any in-progress commands for a channel */
void channel_cleanup_commands(struct channel *channel, const char *why);

void channel_set_state(struct channel *channel,
		       enum channel_state old_state,
		       enum channel_state state,
		       enum state_change reason,
		       char *why);

const char *channel_change_state_reason_str(enum state_change reason);

/* Find a channel which is passes filter, if any: sets *others if there
 * is more than one. */
struct channel *peer_any_channel(struct peer *peer,
				 bool (*channel_state_filter)(enum channel_state),
				 bool *others);

struct channel *channel_by_dbid(struct lightningd *ld, const u64 dbid);

/* Includes both real scids and aliases.  If !privacy_leak_ok, then private
 * channels' real scids are not included. */
struct channel *any_channel_by_scid(struct lightningd *ld,
				    const struct short_channel_id *scid,
				    bool privacy_leak_ok);

/* Get channel by channel_id */
struct channel *channel_by_cid(struct lightningd *ld,
			       const struct channel_id *cid);

/* Find this channel within peer */
struct channel *find_channel_by_id(const struct peer *peer,
				   const struct channel_id *cid);

/* Find this channel within peer */
struct channel *find_channel_by_scid(const struct peer *peer,
				     const struct short_channel_id *scid);

/* Find a channel by its alias, either local or remote. */
struct channel *find_channel_by_alias(const struct peer *peer,
				      const struct short_channel_id *alias,
				      enum side side);

/* Do we have any channel with option_anchors_zero_fee_htlc_tx?  (i.e. we
 * might need to CPFP the fee if it force closes!) */
bool have_anchor_channel(struct lightningd *ld);

void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const struct bitcoin_signature *sig);

static inline bool channel_has(const struct channel *channel, int f)
{
	return channel_type_has(channel->type, f);
}

/**
 * Either returns the short_channel_id if it is known or the local alias.
 *
 * This is used to refer to a channel by its scid. But sometimes we
 * don't have a scid yet, e.g., for `zeroconf` channels, so we resort
 * to referencing it by the local alias, which we have in that case.
 */
const struct short_channel_id *channel_scid_or_local_alias(const struct channel *chan);

void get_channel_basepoints(struct lightningd *ld,
			    const struct node_id *peer_id,
			    const u64 dbid,
			    struct basepoints *local_basepoints,
			    struct pubkey *local_funding_pubkey);

void channel_set_billboard(struct channel *channel, bool perm,
			   const char *str TAKES);

struct htlc_in *channel_has_htlc_in(struct channel *channel);
struct htlc_out *channel_has_htlc_out(struct channel *channel);

const u8 *get_channel_update(struct channel *channel);

struct amount_msat htlc_max_possible_send(const struct channel *channel);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_H */
