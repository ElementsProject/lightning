#include <bitcoin/script.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/tal/str/str.h>
#include <common/closing_fee.h>
#include <common/fee_states.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/utils.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/connect_control.h>
#include <lightningd/gen_channel_state_names.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <lightningd/opening_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wire/wire_sync.h>

static bool connects_to_peer(struct subd *owner)
{
	return owner && owner->talks_to_peer;
}

void channel_set_owner(struct channel *channel, struct subd *owner)
{
	struct subd *old_owner = channel->owner;
	channel->owner = owner;

	if (old_owner) {
		subd_release_channel(old_owner, channel);
		if (channel->connected && !connects_to_peer(owner)) {
			/* If shutting down, connectd no longer exists,
			 * and we should not transfer peer to connectd.
			 * Only transfer to connectd if connectd is
			 * there to be transferred to.
			 */
			if (channel->peer->ld->connectd) {
				u8 *msg;
				msg = towire_connectd_peer_disconnected(
						NULL,
						&channel->peer->id);
				subd_send_msg(channel->peer->ld->connectd,
					      take(msg));
			}
		}
	}
	channel->connected = connects_to_peer(owner);
}

struct htlc_out *channel_has_htlc_out(struct channel *channel)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct lightningd *ld = channel->peer->ld;

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
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

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
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
	u8 *msg;

	assert(dbid != 0);
	msg = towire_hsmd_get_channel_basepoints(NULL, peer_id, dbid);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsmd_get_channel_basepoints_reply(msg, local_basepoints,
						       local_funding_pubkey))
		fatal("HSM gave bad hsm_get_channel_basepoints_reply %s",
		      tal_hex(msg, msg));
}

struct channel *new_channel(struct peer *peer, u64 dbid,
			    /* NULL or stolen */
			    struct wallet_shachain *their_shachain,
			    enum channel_state state,
			    enum side opener,
			    /* NULL or stolen */
			    struct log *log,
			    const char *transient_billboard TAKES,
			    u8 channel_flags,
			    const struct channel_config *our_config,
			    u32 minimum_depth,
			    u64 next_index_local,
			    u64 next_index_remote,
			    u64 next_htlc_id,
			    const struct bitcoin_txid *funding_txid,
			    u16 funding_outnum,
			    struct amount_sat funding,
			    struct amount_msat push,
			    struct amount_sat our_funds,
			    bool remote_funding_locked,
			    /* NULL or stolen */
			    struct short_channel_id *scid,
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
			    bool connected,
			    const struct basepoints *local_basepoints,
			    const struct pubkey *local_funding_pubkey,
			    const struct pubkey *future_per_commitment_point,
			    u32 feerate_base,
			    u32 feerate_ppm,
			    const u8 *remote_upfront_shutdown_script,
			    bool option_static_remotekey,
			    bool option_anchor_outputs)
{
	struct channel *channel = tal(peer->ld, struct channel);

	assert(dbid != 0);
	channel->peer = peer;
	channel->dbid = dbid;
	channel->error = NULL;
	channel->htlc_timeout = NULL;
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

	if (!log) {
		channel->log = new_log(channel,
				       peer->ld->log_book,
				       &channel->peer->id,
				       "chan#%"PRIu64,
				       dbid);
	} else
		channel->log = tal_steal(channel, log);
	channel->channel_flags = channel_flags;
	channel->our_config = *our_config;
	channel->minimum_depth = minimum_depth;
	channel->next_index[LOCAL] = next_index_local;
	channel->next_index[REMOTE] = next_index_remote;
	channel->next_htlc_id = next_htlc_id;
	channel->funding_txid = *funding_txid;
	channel->funding_outnum = funding_outnum;
	channel->funding = funding;
	channel->push = push;
	channel->our_funds = our_funds;
	channel->remote_funding_locked = remote_funding_locked;
	channel->scid = tal_steal(channel, scid);
	channel->cid = *cid;
	channel->our_msat = our_msat;
	channel->msat_to_us_min = msat_to_us_min;
	channel->msat_to_us_max = msat_to_us_max;
	channel->last_tx = tal_steal(channel, last_tx);
	channel->last_tx->chainparams = chainparams;
	channel->last_tx_type = TX_UNKNOWN;
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
	if (local_shutdown_scriptpubkey)
		channel->shutdown_scriptpubkey[LOCAL]
			= tal_steal(channel, local_shutdown_scriptpubkey);
	else
		channel->shutdown_scriptpubkey[LOCAL]
			= p2wpkh_for_keyidx(channel, channel->peer->ld,
					    channel->final_key_idx);
	channel->last_was_revoke = last_was_revoke;
	channel->last_sent_commit = tal_steal(channel, last_sent_commit);
	channel->first_blocknum = first_blocknum;
	channel->min_possible_feerate = min_possible_feerate;
	channel->max_possible_feerate = max_possible_feerate;
	channel->connected = connected;
	channel->local_basepoints = *local_basepoints;
	channel->local_funding_pubkey = *local_funding_pubkey;
	channel->future_per_commitment_point
		= tal_steal(channel, future_per_commitment_point);
	channel->feerate_base = feerate_base;
	channel->feerate_ppm = feerate_ppm;
	channel->remote_upfront_shutdown_script
		= tal_steal(channel, remote_upfront_shutdown_script);
	channel->option_static_remotekey = option_static_remotekey;
	channel->option_anchor_outputs = option_anchor_outputs;
	channel->forgets = tal_arr(channel, struct command *, 0);

	list_add_tail(&peer->channels, &channel->list);
	channel->rr_number = peer->ld->rr_counter++;
	tal_add_destructor(channel, destroy_channel);

	/* Make sure we see any spends using this key */
	txfilter_add_scriptpubkey(peer->ld->owned_txfilter,
				  take(p2wpkh_for_keyidx(NULL, peer->ld,
							 channel->final_key_idx)));

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

struct channel *peer_active_channel(struct peer *peer)
{
	struct channel *channel;

	list_for_each(&peer->channels, channel, list) {
		if (channel_active(channel))
			return channel;
	}
	return NULL;
}

struct channel *peer_normal_channel(struct peer *peer)
{
	struct channel *channel;

	list_for_each(&peer->channels, channel, list) {
		if (channel->state == CHANNELD_NORMAL)
			return channel;
	}
	return NULL;
}

struct channel *active_channel_by_id(struct lightningd *ld,
				     const struct node_id *id,
				     struct uncommitted_channel **uc)
{
	struct peer *peer = peer_by_id(ld, id);
	if (!peer) {
		if (uc)
			*uc = NULL;
		return NULL;
	}

	if (uc)
		*uc = peer->uncommitted_channel;
	return peer_active_channel(peer);
}

struct channel *active_channel_by_scid(struct lightningd *ld,
				       const struct short_channel_id *scid)
{
	struct peer *p;
	struct channel *chan;
	list_for_each(&ld->peers, p, list) {
		list_for_each(&p->channels, chan, list) {
			if (channel_active(chan)
			    && chan->scid
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
	list_for_each(&ld->peers, p, list) {
		list_for_each(&p->channels, chan, list) {
			if (chan->dbid == dbid)
				return chan;
		}
	}
	return NULL;
}

void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const struct bitcoin_signature *sig,
			 enum wallet_tx_type txtypes)
{
	assert(tx->chainparams);
	channel->last_sig = *sig;
	tal_free(channel->last_tx);
	channel->last_tx = tal_steal(channel, tx);
	channel->last_tx_type = txtypes;
}

void channel_set_state(struct channel *channel,
		       enum channel_state old_state,
		       enum channel_state state)
{
	struct channel_id cid;

	log_info(channel->log, "State changed from %s to %s",
		 channel_state_name(channel), channel_state_str(state));
	if (channel->state != old_state)
		fatal("channel state %s should be %s",
		      channel_state_name(channel), channel_state_str(old_state));

	channel->state = state;

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(channel->peer->ld->wallet, channel);

	/* plugin notification channel_state_changed */
	if (state != old_state) {  /* see issue #4029 */
		derive_channel_id(&cid, &channel->funding_txid, channel->funding_outnum);
		notify_channel_state_changed(channel->peer->ld,
					     &channel->peer->id,
					     &cid,
					     channel->scid,
					     old_state,
					     state);
	}
}

void channel_fail_permanent(struct channel *channel, const char *fmt, ...)
{
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

	if (channel_active(channel))
		channel_set_state(channel, channel->state, AWAITING_UNILATERAL);

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

void channel_internal_error(struct channel *channel, const char *fmt, ...)
{
	va_list ap;
	char *why;

	va_start(ap, fmt);
	why = tal_vfmt(channel, fmt, ap);
	va_end(ap);

	log_broken(channel->log, "Peer internal error %s: %s",
		   channel_state_name(channel), why);

	/* Don't expose internal error causes to remove unless doing dev */
#if DEVELOPER
	channel_fail_permanent(channel, "Internal error: %s", why);
#else
	channel_fail_permanent(channel, "Internal error");
#endif
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

static void err_and_reconnect(struct channel *channel,
			      const char *why,
			      u32 seconds_before_reconnect)
{
	log_info(channel->log, "Peer transient failure in %s: %s",
		 channel_state_name(channel), why);

#if DEVELOPER
	if (dev_disconnect_permanent(channel->peer->ld)) {
		channel_fail_permanent(channel, "dev_disconnect permfail");
		return;
	}
#endif

	channel_set_owner(channel, NULL);

	delay_then_reconnect(channel, seconds_before_reconnect,
			     &channel->peer->addr);
}

void channel_fail_reconnect_later(struct channel *channel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_and_reconnect(channel, tal_vfmt(tmpctx, fmt, ap), 60);
	va_end(ap);
}

void channel_fail_reconnect(struct channel *channel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_and_reconnect(channel, tal_vfmt(tmpctx, fmt, ap), 1);
	va_end(ap);
}
