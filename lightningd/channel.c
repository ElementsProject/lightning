#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/blockheight_states.h>
#include <common/closing_fee.h>
#include <common/fee_states.h>
#include <common/json_command.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/channel_state_names_gen.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wallet/txfilter.h>
#include <wire/peer_wire.h>

void channel_set_owner(struct channel *channel, struct subd *owner)
{
	struct subd *old_owner = channel->owner;
	channel->owner = owner;

	if (old_owner)
		subd_release_channel(old_owner, channel);
}

struct htlc_out *channel_has_htlc_out(struct channel *channel)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct lightningd *ld = channel->peer->ld;

	for (hout = htlc_out_map_first(ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(ld->htlcs_out, &outi)) {
		if (hout->key.channel == channel)
			return hout;
	}

	return NULL;
}

struct htlc_in *channel_has_htlc_in(struct channel *channel)
{
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	struct lightningd *ld = channel->peer->ld;

	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
		if (hin->key.channel == channel)
			return hin;
	}

	return NULL;
}

static void destroy_channel(struct channel *channel)
{
	/* Must not have any HTLCs! */
	struct htlc_out *hout = channel_has_htlc_out(channel);
	struct htlc_in *hin = channel_has_htlc_in(channel);

	if (hout)
		fatal("Freeing channel %s has hout %s",
		      channel_state_name(channel),
		      htlc_state_name(hout->hstate));

	if (hin)
		fatal("Freeing channel %s has hin %s",
		      channel_state_name(channel),
		      htlc_state_name(hin->hstate));

	for (size_t i = 0; i < tal_count(channel->forgets); i++)
		was_pending(command_fail(channel->forgets[i], LIGHTNINGD,
			    "Channel structure was freed!"));

	/* Free any old owner still hanging around. */
	channel_set_owner(channel, NULL);

	list_del_from(&channel->peer->channels, &channel->list);
}

void delete_channel(struct channel *channel STEALS)
{
	struct peer *peer = channel->peer;
	if (channel->dbid != 0)
		wallet_channel_close(channel->peer->ld->wallet, channel->dbid);
	tal_free(channel);

	maybe_delete_peer(peer);
}

void get_channel_basepoints(struct lightningd *ld,
			    const struct node_id *peer_id,
			    const u64 dbid,
			    struct basepoints *local_basepoints,
			    struct pubkey *local_funding_pubkey)
{
	const u8 *msg;

	assert(dbid != 0);
	msg = towire_hsmd_get_channel_basepoints(NULL, peer_id, dbid);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_get_channel_basepoints_reply(msg, local_basepoints,
						       local_funding_pubkey))
		fatal("HSM gave bad hsm_get_channel_basepoints_reply %s",
		      tal_hex(msg, msg));
}

static void destroy_inflight(struct channel_inflight *inflight)
{
	list_del_from(&inflight->channel->inflights, &inflight->list);
}

struct channel_inflight *
new_inflight(struct channel *channel,
	     const struct bitcoin_outpoint *funding_outpoint,
	     u32 funding_feerate,
	     struct amount_sat total_funds,
	     struct amount_sat our_funds,
	     struct wally_psbt *psbt STEALS,
	     struct bitcoin_tx *last_tx,
	     const struct bitcoin_signature last_sig,
	     const u32 lease_expiry,
	     const secp256k1_ecdsa_signature *lease_commit_sig,
	     const u32 lease_chan_max_msat, const u16 lease_chan_max_ppt,
	     const u32 lease_blockheight_start,
	     const struct amount_msat lease_fee,
	     const struct amount_sat lease_amt,
	     s64 splice_amnt,
	     bool i_am_initiator)
{
	struct wally_psbt *last_tx_psbt_clone;
	struct channel_inflight *inflight
		= tal(channel, struct channel_inflight);
	struct funding_info *funding
		= tal(inflight, struct funding_info);

	funding->outpoint = *funding_outpoint;
	funding->total_funds = total_funds;
	funding->feerate = funding_feerate;
	funding->our_funds = our_funds;
	funding->splice_amnt = splice_amnt;

	inflight->funding = funding;
	inflight->channel = channel;
	inflight->remote_tx_sigs = false;
	inflight->funding_psbt = tal_steal(inflight, psbt);

	/* Make a 'clone' of this tx */
	inflight->last_tx = NULL;
	if (last_tx) {
		last_tx_psbt_clone = clone_psbt(inflight, last_tx->psbt);
		inflight->last_tx = bitcoin_tx_with_psbt(inflight, last_tx_psbt_clone);
	}
	inflight->last_sig = last_sig;
	inflight->tx_broadcast = false;

	/* Channel lease infos */
	inflight->lease_blockheight_start = lease_blockheight_start;
	inflight->lease_expiry = lease_expiry;
	inflight->lease_commit_sig
		= tal_dup_or_null(inflight, secp256k1_ecdsa_signature,
				  lease_commit_sig);

	inflight->lease_chan_max_msat = lease_chan_max_msat;
	inflight->lease_chan_max_ppt = lease_chan_max_ppt;
	inflight->lease_fee = lease_fee;
	inflight->lease_amt = lease_amt;

	inflight->i_am_initiator = i_am_initiator;
	inflight->splice_locked_memonly = false;

	list_add_tail(&channel->inflights, &inflight->list);
	tal_add_destructor(inflight, destroy_inflight);

	return inflight;
}

struct open_attempt *new_channel_open_attempt(struct channel *channel)
{
	struct open_attempt *oa = tal(channel, struct open_attempt);
	oa->channel = channel;
	/* Copy over the config; we'll clobber the reserve */
	oa->our_config = channel->our_config;
	oa->role = channel->opener == LOCAL ? TX_INITIATOR : TX_ACCEPTER;
	oa->our_upfront_shutdown_script = NULL;
	oa->cmd = NULL;
	oa->aborted = false;
	oa->open_msg = NULL;

	return oa;
}

struct channel *new_unsaved_channel(struct peer *peer,
				    u32 feerate_base,
				    u32 feerate_ppm)
{
	struct lightningd *ld = peer->ld;
	struct channel *channel = tal(ld, struct channel);
	const u8 *msg;

	channel->peer = peer;
	/* Not saved to the database yet! */
	channel->unsaved_dbid = wallet_get_channel_dbid(ld->wallet);
	/* A zero value database id means it's not saved in the database yet */
	channel->dbid = 0;
	channel->error = NULL;
	channel->openchannel_signed_cmd = NULL;
	channel->state = DUALOPEND_OPEN_INIT;
	channel->owner = NULL;
	channel->scb = NULL;
	memset(&channel->billboard, 0, sizeof(channel->billboard));
	channel->billboard.transient = tal_fmt(channel, "%s",
					       "Empty channel init'd");
	channel->log = new_logger(channel, ld->log_book,
				  &peer->id,
				  "chan#%"PRIu64,
				  channel->unsaved_dbid);

	channel->our_config.id = 0;
	channel->open_attempt = NULL;

	channel->last_htlc_sigs = NULL;
	channel->remote_channel_ready = false;
	channel->scid = NULL;
	channel->next_index[LOCAL] = 1;
	channel->next_index[REMOTE] = 1;
	channel->next_htlc_id = 0;
	channel->funding_spend_watch = NULL;
	/* FIXME: remove push when v1 deprecated */
	channel->push = AMOUNT_MSAT(0);
	channel->closing_fee_negotiation_step = 50;
	channel->closing_fee_negotiation_step_unit
		= CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE;
	channel->shutdown_wrong_funding = NULL;
	channel->closing_feerate_range = NULL;
	channel->channel_update = NULL;
	channel->alias[LOCAL] = channel->alias[REMOTE] = NULL;

	channel->shutdown_scriptpubkey[REMOTE] = NULL;
	channel->last_was_revoke = false;
	channel->last_sent_commit = NULL;

	channel->feerate_base = feerate_base;
	channel->feerate_ppm = feerate_ppm;
	channel->old_feerate_timeout.ts.tv_sec = 0;
	channel->old_feerate_timeout.ts.tv_nsec = 0;
	/* closer not yet known */
	channel->closer = NUM_SIDES;
	channel->close_blockheight = NULL;
	/* In case someone looks at channels before open negotiation,
	 * initialize this with default */
	channel->type = default_channel_type(channel,
					     ld->our_features,
					     peer->their_features);

	/* BOLT-7b04b1461739c5036add61782d58ac490842d98b #9
	 * | 222/223 | `option_dual_fund`
	 * | Use v2 of channel open, enables dual funding
	 * | IN9 */
	channel->static_remotekey_start[LOCAL]
		= channel->static_remotekey_start[REMOTE] = 0;

	channel->future_per_commitment_point = NULL;

	channel->lease_commit_sig = NULL;
	channel->ignore_fee_limits = ld->config.ignore_fee_limits;

	/* No shachain yet */
	channel->their_shachain.id = 0;
	shachain_init(&channel->their_shachain.chain);

	msg = towire_hsmd_new_channel(NULL, &peer->id, channel->unsaved_dbid);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_new_channel_reply(msg))
		fatal("HSM gave bad hsm_new_channel_reply %s",
		      tal_hex(msg, msg));

	get_channel_basepoints(ld, &peer->id, channel->unsaved_dbid,
			       &channel->local_basepoints,
			       &channel->local_funding_pubkey);

	channel->forgets = tal_arr(channel, struct command *, 0);
	list_add_tail(&peer->channels, &channel->list);
	channel->rr_number = peer->ld->rr_counter++;
	tal_add_destructor(channel, destroy_channel);

	list_head_init(&channel->inflights);
	return channel;
}

/*
 * The maximum msat that this node could possibly accept for an htlc.
 * It's the default htlc_maximum_msat in channel_updates, if none is
 * explicitly set (and the cap on what can be set!).
 *
 * We advertize the maximum value possible, defined as the smaller
 * of the remote's maximum in-flight HTLC or the total channel
 * capacity the reserve we have to keep.
 * FIXME: does this need fuzz?
 */
struct amount_msat htlc_max_possible_send(const struct channel *channel)
{
	struct amount_sat lower_bound;
	struct amount_msat lower_bound_msat;

	/* These shouldn't fail */
	if (!amount_sat_sub(&lower_bound, channel->funding_sats,
			    channel->channel_info.their_config.channel_reserve)) {
		log_broken(channel->log, "%s: their reserve %s > funding %s!",
			   __func__,
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->funding_sats),
			   type_to_string(tmpctx, struct amount_sat,
					  &channel->channel_info.their_config.channel_reserve));
		return AMOUNT_MSAT(0);
	}

	if (!amount_sat_to_msat(&lower_bound_msat, lower_bound)) {
		log_broken(channel->log, "%s: impossible size channel %s!",
			   __func__,
			   type_to_string(tmpctx, struct amount_sat,
					  &lower_bound));
		return AMOUNT_MSAT(0);
	}

	if (amount_msat_less(channel->channel_info.their_config.max_htlc_value_in_flight,
			     lower_bound_msat))
		lower_bound_msat = channel->channel_info.their_config.max_htlc_value_in_flight;

	return lower_bound_msat;
}

struct channel *new_channel(struct peer *peer, u64 dbid,
			    /* NULL or stolen */
			    struct wallet_shachain *their_shachain,
			    enum channel_state state,
			    enum side opener,
			    /* NULL or stolen */
			    struct logger *log,
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
			    struct short_channel_id *scid,
			    struct short_channel_id *alias_local STEALS,
			    struct short_channel_id *alias_remote STEALS,
			    struct channel_id *cid,
			    struct amount_msat our_msat,
			    struct amount_msat msat_to_us_min,
			    struct amount_msat msat_to_us_max,
			    /* Stolen */
			    struct bitcoin_tx *last_tx,
			    const struct bitcoin_signature *last_sig,
			    /* NULL or stolen */
			    const struct bitcoin_signature *last_htlc_sigs,
			    const struct channel_info *channel_info,
			    const struct fee_states *fee_states TAKES,
			    /* NULL or stolen */
			    u8 *remote_shutdown_scriptpubkey,
			    const u8 *local_shutdown_scriptpubkey,
			    u64 final_key_idx,
			    bool last_was_revoke,
			    /* NULL or stolen */
			    struct changed_htlc *last_sent_commit,
			    u32 first_blocknum,
			    u32 min_possible_feerate,
			    u32 max_possible_feerate,
			    const struct basepoints *local_basepoints,
			    const struct pubkey *local_funding_pubkey,
			    const struct pubkey *future_per_commitment_point,
			    u32 feerate_base,
			    u32 feerate_ppm,
			    const u8 *remote_upfront_shutdown_script,
			    u64 local_static_remotekey_start,
			    u64 remote_static_remotekey_start,
			    const struct channel_type *type STEALS,
			    enum side closer,
			    enum state_change reason,
			    /* NULL or stolen */
			    const struct bitcoin_outpoint *shutdown_wrong_funding,
			    const struct height_states *height_states TAKES,
			    u32 lease_expiry,
			    secp256k1_ecdsa_signature *lease_commit_sig STEALS,
			    u32 lease_chan_max_msat,
			    u16 lease_chan_max_ppt,
			    struct amount_msat htlc_minimum_msat,
			    struct amount_msat htlc_maximum_msat,
			    bool ignore_fee_limits)
{
	struct channel *channel = tal(peer->ld, struct channel);
	struct amount_msat htlc_min, htlc_max;

	bool anysegwit = !chainparams->is_elements && feature_negotiated(peer->ld->our_features,
                        peer->their_features,
                        OPT_SHUTDOWN_ANYSEGWIT);

	assert(dbid != 0);
	channel->peer = peer;
	channel->dbid = dbid;
	channel->unsaved_dbid = 0;
	channel->error = NULL;
	channel->open_attempt = NULL;
	channel->openchannel_signed_cmd = NULL;
	if (their_shachain)
		channel->their_shachain = *their_shachain;
	else {
		channel->their_shachain.id = 0;
		shachain_init(&channel->their_shachain.chain);
	}
	channel->state = state;
	channel->opener = opener;
	channel->owner = NULL;
	memset(&channel->billboard, 0, sizeof(channel->billboard));
	channel->billboard.transient = tal_strdup(channel, transient_billboard);

	/* If it's a unix domain socket connection, we don't save it */
	if (peer->addr.itype == ADDR_INTERNAL_WIREADDR) {
		channel->scb = tal(channel, struct scb_chan);
		channel->scb->id = dbid;
		channel->scb->unused = 0;
		channel->scb->addr = peer->addr.u.wireaddr.wireaddr;
		channel->scb->node_id = peer->id;
		channel->scb->funding = *funding;
		channel->scb->cid = *cid;
		channel->scb->funding_sats = funding_sats;
		channel->scb->type = channel_type_dup(channel->scb, type);
	} else
		channel->scb = NULL;

	if (!log) {
		channel->log = new_logger(channel,
					  peer->ld->log_book,
					  &channel->peer->id,
					  "chan#%"PRIu64,
					  dbid);
	} else
		channel->log = tal_steal(channel, log);
	channel->req_confirmed_ins[LOCAL] = req_confirmed_ins_local;
	channel->req_confirmed_ins[REMOTE] = req_confirmed_ins_remote;
	channel->channel_flags = channel_flags;
	channel->our_config = *our_config;
	channel->minimum_depth = minimum_depth;
	channel->depth = 0;
	channel->next_index[LOCAL] = next_index_local;
	channel->next_index[REMOTE] = next_index_remote;
	channel->next_htlc_id = next_htlc_id;
	channel->funding = *funding;
	channel->funding_sats = funding_sats;
	channel->funding_spend_watch = NULL;
	channel->push = push;
	channel->our_funds = our_funds;
	channel->remote_channel_ready = remote_channel_ready;
	channel->scid = tal_steal(channel, scid);
	channel->alias[LOCAL] = tal_steal(channel, alias_local);
	channel->alias[REMOTE] = tal_steal(channel, alias_remote);  /* Haven't gotten one yet. */
	channel->cid = *cid;
	channel->our_msat = our_msat;
	channel->msat_to_us_min = msat_to_us_min;
	channel->msat_to_us_max = msat_to_us_max;
        channel->last_tx = tal_steal(channel, last_tx);
	if (channel->last_tx) {
		channel->last_tx->chainparams = chainparams;
	}
	channel->last_sig = *last_sig;
	channel->last_htlc_sigs = tal_steal(channel, last_htlc_sigs);
	channel->channel_info = *channel_info;
	channel->fee_states = dup_fee_states(channel, fee_states);
	channel->shutdown_scriptpubkey[REMOTE]
		= tal_steal(channel, remote_shutdown_scriptpubkey);
	channel->final_key_idx = final_key_idx;
	channel->closing_fee_negotiation_step = 50;
	channel->closing_fee_negotiation_step_unit
		= CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE;
	channel->shutdown_wrong_funding
		= tal_steal(channel, shutdown_wrong_funding);
	channel->closing_feerate_range = NULL;
	if (local_shutdown_scriptpubkey) {
		channel->shutdown_scriptpubkey[LOCAL]
			= tal_steal(channel, local_shutdown_scriptpubkey);
	} else if (anysegwit) {
		channel->shutdown_scriptpubkey[LOCAL]
			= p2tr_for_keyidx(channel, channel->peer->ld,
						channel->final_key_idx);
	} else {
		channel->shutdown_scriptpubkey[LOCAL]
			= p2wpkh_for_keyidx(channel, channel->peer->ld,
						channel->final_key_idx);
	}
	channel->last_was_revoke = last_was_revoke;
	channel->last_sent_commit = tal_steal(channel, last_sent_commit);
	channel->first_blocknum = first_blocknum;
	channel->min_possible_feerate = min_possible_feerate;
	channel->max_possible_feerate = max_possible_feerate;
	channel->local_basepoints = *local_basepoints;
	channel->local_funding_pubkey = *local_funding_pubkey;
	channel->future_per_commitment_point
		= tal_steal(channel, future_per_commitment_point);
	channel->feerate_base = feerate_base;
	channel->feerate_ppm = feerate_ppm;
	channel->old_feerate_timeout.ts.tv_sec = 0;
	channel->old_feerate_timeout.ts.tv_nsec = 0;
	channel->remote_upfront_shutdown_script
		= tal_steal(channel, remote_upfront_shutdown_script);
	channel->static_remotekey_start[LOCAL] = local_static_remotekey_start;
	channel->static_remotekey_start[REMOTE] = remote_static_remotekey_start;
	channel->type = tal_steal(channel, type);
	channel->forgets = tal_arr(channel, struct command *, 0);

	channel->lease_expiry = lease_expiry;
	channel->lease_commit_sig = tal_steal(channel, lease_commit_sig);
	channel->lease_chan_max_msat = lease_chan_max_msat;
	channel->lease_chan_max_ppt = lease_chan_max_ppt;
	channel->blockheight_states = dup_height_states(channel, height_states);
	channel->channel_update = NULL;

	/* DB migration, for example, sets min to 0, max to large: fixup */
	htlc_min = channel->channel_info.their_config.htlc_minimum;
	if (amount_msat_greater(htlc_min, htlc_minimum_msat))
		channel->htlc_minimum_msat = htlc_min;
	else
		channel->htlc_minimum_msat = htlc_minimum_msat;
	htlc_max = htlc_max_possible_send(channel);
	if (amount_msat_less(htlc_max, htlc_maximum_msat))
		channel->htlc_maximum_msat = htlc_max;
	else
		channel->htlc_maximum_msat = htlc_maximum_msat;

	list_add_tail(&peer->channels, &channel->list);
	channel->rr_number = peer->ld->rr_counter++;
	tal_add_destructor(channel, destroy_channel);

	list_head_init(&channel->inflights);

	channel->closer = closer;
	channel->close_blockheight = NULL;
	channel->state_change_cause = reason;
	channel->ignore_fee_limits = ignore_fee_limits;

	/* Make sure we see any spends using this key */
	if (!local_shutdown_scriptpubkey) {
		if (anysegwit) {
			txfilter_add_scriptpubkey(peer->ld->owned_txfilter,
						  take(p2tr_for_keyidx(NULL, peer->ld,
									 channel->final_key_idx)));
		} else {
			txfilter_add_scriptpubkey(peer->ld->owned_txfilter,
						  take(p2wpkh_for_keyidx(NULL, peer->ld,
									 channel->final_key_idx)));
		}
	}
	/* scid is NULL when opening a new channel so we don't
	 * need to set error in that case as well */
	if (is_stub_scid(scid))
		channel->error = towire_errorfmt(peer->ld,
						 &channel->cid,
						 "We can't be together anymore.");

	return channel;
}

const char *channel_state_name(const struct channel *channel)
{
	return channel_state_str(channel->state);
}

const char *channel_state_str(enum channel_state state)
{
	for (size_t i = 0; enum_channel_state_names[i].name; i++)
		if (enum_channel_state_names[i].v == state)
			return enum_channel_state_names[i].name;
	return "unknown";
}

struct channel *peer_any_channel(struct peer *peer,
				 bool (*channel_state_filter)(enum channel_state),
				 bool *others)
{
	struct channel *channel, *ret = NULL;

	list_for_each(&peer->channels, channel, list) {
		if (channel_state_filter && !channel_state_filter(channel->state))
			continue;
		/* Already found one? */
		if (ret) {
			if (others)
				*others = true;
		} else {
			if (others)
				*others = false;
			ret = channel;
		}
	}
	return ret;
}

struct channel_inflight *channel_inflight_find(struct channel *channel,
					       const struct bitcoin_txid *txid)
{
	struct channel_inflight *inflight;
	list_for_each(&channel->inflights, inflight, list) {
		if (bitcoin_txid_eq(txid, &inflight->funding->outpoint.txid))
			return inflight;
	}

	return NULL;
}

struct channel *any_channel_by_scid(struct lightningd *ld,
				    const struct short_channel_id *scid,
				    bool privacy_leak_ok)
{
	struct peer *p;
	struct channel *chan;
	struct peer_node_id_map_iter it;

	/* FIXME: Support lookup by scid directly! */
	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&p->channels, chan, list) {
			/* BOLT #2:
			 * - MUST always recognize the `alias` as a
			 *   `short_channel_id` for incoming HTLCs to this
			 *   channel.
			 */
			if (chan->alias[LOCAL] &&
			    short_channel_id_eq(scid, chan->alias[LOCAL]))
				return chan;
			/* BOLT #2:
			 * - if `channel_type` has `option_scid_alias` set:
			 *   - MUST NOT allow incoming HTLCs to this channel
			 *     using the real `short_channel_id`
			 */
			if (!privacy_leak_ok
			    && channel_type_has(chan->type, OPT_SCID_ALIAS))
				continue;
			if (chan->scid
			    && short_channel_id_eq(scid, chan->scid))
				return chan;
		}
	}
	return NULL;
}

struct channel *channel_by_dbid(struct lightningd *ld, const u64 dbid)
{
	struct peer *p;
	struct channel *chan;
	struct peer_node_id_map_iter it;

	/* FIXME: Support lookup by id directly! */
	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&p->channels, chan, list) {
			if (chan->dbid == dbid)
				return chan;
		}
	}
	return NULL;
}

struct channel *channel_by_cid(struct lightningd *ld,
			       const struct channel_id *cid)
{
	struct peer *p;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	/* FIXME: Support lookup by cid directly! */
	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		if (p->uncommitted_channel) {
			/* We can't use this method for old, uncommitted
			 * channels; there's no "channel" struct here! */
			if (channel_id_eq(&p->uncommitted_channel->cid, cid))
				return NULL;
		}
		list_for_each(&p->channels, channel, list) {
			if (channel_id_eq(&channel->cid, cid)) {
				return channel;
			}
		}
	}
	return NULL;
}

struct channel *find_channel_by_id(const struct peer *peer,
				   const struct channel_id *cid)
{
	struct channel *c;

	list_for_each(&peer->channels, c, list) {
		if (channel_id_eq(&c->cid, cid))
			return c;
	}
	return NULL;
}

struct channel *find_channel_by_scid(const struct peer *peer,
				     const struct short_channel_id *scid)
{
	struct channel *c;

	list_for_each(&peer->channels, c, list) {
		if (c->scid && short_channel_id_eq(c->scid, scid))
			return c;
	}
	return NULL;
}

struct channel *find_channel_by_alias(const struct peer *peer,
				      const struct short_channel_id *alias,
				      enum side side)
{
	struct channel *c;
	list_for_each(&peer->channels, c, list) {
		if (c->alias[side] && short_channel_id_eq(c->alias[side], alias))
			return c;
	}
	return NULL;
}

bool have_anchor_channel(struct lightningd *ld)
{
	struct peer *p;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		if (p->uncommitted_channel) {
			/* FIXME: Assume anchors if supported */
			if (feature_negotiated(ld->our_features,
					       p->their_features,
					       OPT_ANCHORS_ZERO_FEE_HTLC_TX))
				return true;
		}
		list_for_each(&p->channels, channel, list) {
			if (channel_type_has(channel->type,
					     OPT_ANCHORS_ZERO_FEE_HTLC_TX))
				return true;
		}
	}
	return false;
}

void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const struct bitcoin_signature *sig)
{
	assert(tx->chainparams);
	channel->last_sig = *sig;
	tal_free(channel->last_tx);
	channel->last_tx = tal_steal(channel, tx);
}

void channel_set_state(struct channel *channel,
		       enum channel_state old_state,
		       enum channel_state state,
		       enum state_change reason,
		       char *why)
{
	struct timeabs timestamp;

	/* set closer, if known */
	if (channel_state_closing(state) && channel->closer == NUM_SIDES) {
		if (reason == REASON_LOCAL)   channel->closer = LOCAL;
		if (reason == REASON_USER)    channel->closer = LOCAL;
		if (reason == REASON_REMOTE)  channel->closer = REMOTE;
		if (reason == REASON_ONCHAIN) channel->closer = REMOTE;
	}

	/* use or update state_change_cause, if known */
	if (reason != REASON_UNKNOWN)
		channel->state_change_cause = reason;
	else
		reason = channel->state_change_cause;

	log_info(channel->log, "State changed from %s to %s",
		 channel_state_name(channel), channel_state_str(state));
	if (channel->state != old_state)
		fatal("channel state %s should be %s",
		      channel_state_name(channel), channel_state_str(old_state));

	channel->state = state;

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(channel->peer->ld->wallet, channel);

	/* plugin notification channel_state_changed and DB entry */
	if (state != old_state) {  /* see issue #4029 */
		timestamp = time_now();
		wallet_state_change_add(channel->peer->ld->wallet,
					channel->dbid,
					timestamp,
					old_state,
					state,
					reason,
					why);
		notify_channel_state_changed(channel->peer->ld,
					     &channel->peer->id,
					     &channel->cid,
					     channel->scid,
					     timestamp,
					     old_state,
					     state,
					     reason,
					     why);
	}
}

const char *channel_change_state_reason_str(enum state_change reason)
{
	switch (reason) {
		case REASON_UNKNOWN:  return "unknown";
		case REASON_LOCAL:    return "local";
		case REASON_USER:     return "user";
		case REASON_REMOTE:   return "remote";
		case REASON_PROTOCOL: return "protocol";
		case REASON_ONCHAIN:  return "onchain";
	}
	abort();
}

void channel_fail_permanent(struct channel *channel,
			    enum state_change reason,
			    const char *fmt,
			    ...)
{
	/* Don't do anything if it's an stub channel because
	 * peer has already closed it unilatelrally. */
	if (is_stub_scid(channel->scid))
		return;

	struct lightningd *ld = channel->peer->ld;
	va_list ap;
	char *why;

	va_start(ap, fmt);
	why = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	log_unusual(channel->log, "Peer permanent failure in %s: %s",
		    channel_state_name(channel), why);

	/* We can have multiple errors, eg. onchaind failures. */
	if (!channel->error)
		channel->error = towire_errorfmt(channel,
						 &channel->cid, "%s", why);

	channel_set_owner(channel, NULL);
	/* Drop non-cooperatively (unilateral) to chain. */
	drop_to_chain(ld, channel, false);

	if (channel_state_wants_onchain_fail(channel->state))
		channel_set_state(channel,
				  channel->state,
				  AWAITING_UNILATERAL,
				  reason,
				  why);

	tal_free(why);
}

void channel_fail_forget(struct channel *channel, const char *fmt, ...)
{
	va_list ap;
	char *why;

	assert(channel->opener == REMOTE &&
	       channel->state == CHANNELD_AWAITING_LOCKIN);
	va_start(ap, fmt);
	why = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	log_unusual(channel->log, "Peer permanent failure in %s: %s, "
		    "forget channel",
		    channel_state_name(channel), why);

	if (!channel->error)
		channel->error = towire_errorfmt(channel,
						 &channel->cid, "%s", why);

	delete_channel(channel);
	tal_free(why);
}

struct channel_inflight *
channel_current_inflight(const struct channel *channel)
{
	/* The last inflight should always be the one in progress */
	return list_tail(&channel->inflights,
			 struct channel_inflight, list);
}

u32 channel_last_funding_feerate(const struct channel *channel)
{
	struct channel_inflight *inflight;
	inflight = channel_current_inflight(channel);
	if (!inflight)
		return 0;
	return inflight->funding->feerate;
}

void channel_cleanup_commands(struct channel *channel, const char *why)
{
	if (channel->open_attempt) {
		struct open_attempt *oa = channel->open_attempt;
		if (oa->cmd) {
			/* If we requested this be aborted, it's a success */
			if (oa->aborted) {
				struct json_stream *response;
				response = json_stream_success(oa->cmd);
				json_add_channel_id(response,
						    "channel_id",
						    &channel->cid);
				json_add_bool(response, "channel_canceled",
					      list_empty(&channel->inflights));
				json_add_string(response, "reason", why);
				was_pending(command_success(oa->cmd, response));
			} else
				was_pending(command_fail(oa->cmd, LIGHTNINGD,
							 "%s", why));
		}
		notify_channel_open_failed(channel->peer->ld, &channel->cid);
		channel->open_attempt = tal_free(channel->open_attempt);
	}

	if (channel->openchannel_signed_cmd) {
		was_pending(command_fail(channel->openchannel_signed_cmd,
					 LIGHTNINGD, "%s", why));
		channel->openchannel_signed_cmd = NULL;
	}
}

void channel_internal_error(struct channel *channel, const char *fmt, ...)
{
	va_list ap;
	char *why;

	va_start(ap, fmt);
	why = tal_vfmt(channel, fmt, ap);
	va_end(ap);

	log_broken(channel->log, "Internal error %s: %s",
		   channel_state_name(channel), why);

	channel_cleanup_commands(channel, why);

	/* Nothing ventured, nothing lost! */
	if (channel_state_uncommitted(channel->state)) {
		channel_set_owner(channel, NULL);
		delete_channel(channel);
		tal_free(why);
		return;
	}

	/* Don't expose internal error causes to remove unless doing dev */
	if (channel->peer->ld->developer)
		channel_fail_permanent(channel,
				       REASON_LOCAL, "Internal error: %s", why);
	else
		channel_fail_permanent(channel, REASON_LOCAL, "Internal error");
	tal_free(why);
}

void channel_set_billboard(struct channel *channel, bool perm, const char *str)
{
	const char **p;

	if (perm)
		p = &channel->billboard.permanent[channel->state];
	else
		p = &channel->billboard.transient;
	*p = tal_free(*p);

	if (str) {
		*p = tal_fmt(channel, "%s:%s", channel_state_name(channel), str);
		if (taken(str))
			tal_free(str);
	}
}

static void channel_err(struct channel *channel, bool disconnect, const char *why)
{
	/* Nothing to do if channel isn't actually owned! */
	if (!channel->owner)
		return;

	log_info(channel->log, "Peer transient failure in %s: %s",
		 channel_state_name(channel), why);

	if (dev_disconnect_permanent(channel->peer->ld)) {
		channel_fail_permanent(channel,
				       REASON_LOCAL,
				       "dev_disconnect permfail");
		return;
	}

	channel_set_owner(channel, NULL);

	/* Force a disconnect in case the issue is with TCP */
	if (disconnect) {
		force_peer_disconnect(channel->peer->ld, channel->peer,
				      "One channel had an error");
	}
}

void channel_fail_transient(struct channel *channel, bool disconnect, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	channel_err(channel, disconnect, tal_vfmt(tmpctx, fmt, ap));
	va_end(ap);
}

bool channel_is_connected(const struct channel *channel)
{
	return channel->owner && channel->owner->talks_to_peer;
}

const struct short_channel_id *
channel_scid_or_local_alias(const struct channel *chan)
{
	assert(chan->scid != NULL || chan->alias[LOCAL] != NULL);
	if (chan->scid != NULL)
		return chan->scid;
	else
		return chan->alias[LOCAL];
}
