#include <bitcoin/script.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/tal/str/str.h>
#include <common/wire_error.h>
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/gen_channel_state_names.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

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

	/* Free any old owner still hanging around. */
	channel_set_owner(channel, NULL);

	list_del_from(&channel->peer->channels, &channel->list);
}

void delete_channel(struct channel *channel)
{
	struct peer *peer = channel->peer;
	wallet_channel_delete(channel->peer->ld->wallet, channel->dbid);
	tal_free(channel);

	/* Last one out frees the peer */
	if (list_empty(&peer->channels) && !peer->uncommitted_channel)
		delete_peer(peer);
}

/* FIXME: We have no business knowing this! */
/**
 * derive_channel_seed - Generate a unique secret for this peer's channel
 *
 * @ld: the lightning daemon to get global secret from
 * @seed: where to store the generated secret
 * @peer_id: the id node_id of the remote peer
 * @dbid: channel DBID
 *
 * This method generates a unique secret from the given parameters. It
 * is important that this secret be unique for each channel, but it
 * must be reproducible for the same channel in case of
 * reconnection. We use the DB channel ID to guarantee unique secrets
 * per channel.
 */
void derive_channel_seed(struct lightningd *ld, struct privkey *seed,
			 const struct pubkey *peer_id,
			 const u64 dbid)
{
	u8 input[PUBKEY_DER_LEN + sizeof(dbid)];
	char *info = "per-peer seed";
	pubkey_to_der(input, peer_id);
	memcpy(input + PUBKEY_DER_LEN, &dbid, sizeof(dbid));

	assert(dbid != 0);
	hkdf_sha256(seed, sizeof(*seed),
		    input, sizeof(input),
		    &ld->peer_seed, sizeof(ld->peer_seed),
		    info, strlen(info));
}

struct channel *new_channel(struct peer *peer, u64 dbid,
			    /* NULL or stolen */
			    struct wallet_shachain *their_shachain,
			    enum channel_state state,
			    enum side funder,
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
			    u64 funding_satoshi,
			    u64 push_msat,
			    bool remote_funding_locked,
			    /* NULL or stolen */
			    struct short_channel_id *scid,
			    u64 our_msatoshi,
			    u64 msatoshi_to_us_min,
			    u64 msatoshi_to_us_max,
			    /* Stolen */
			    struct bitcoin_tx *last_tx,
			    const secp256k1_ecdsa_signature *last_sig,
			    /* NULL or stolen */
			    secp256k1_ecdsa_signature *last_htlc_sigs,
			    const struct channel_info *channel_info,
			    /* NULL or stolen */
			    u8 *remote_shutdown_scriptpubkey,
			    u64 final_key_idx,
			    bool last_was_revoke,
			    /* NULL or stolen */
			    struct changed_htlc *last_sent_commit,
			    u32 first_blocknum,
			    u32 min_possible_feerate,
			    u32 max_possible_feerate)
{
	struct channel *channel = tal(peer->ld, struct channel);

	assert(dbid != 0);
	channel->peer = peer;
	channel->dbid = dbid;
	channel->error = NULL;
	if (their_shachain)
		channel->their_shachain = *their_shachain;
	else {
		channel->their_shachain.id = 0;
		shachain_init(&channel->their_shachain.chain);
	}
	channel->state = state;
	channel->funder = funder;
	channel->owner = NULL;
	memset(&channel->billboard, 0, sizeof(channel->billboard));
	channel->billboard.transient = tal_strdup(channel, transient_billboard);

	if (!log) {
		/* FIXME: update log prefix when we get scid */
		/* FIXME: Use minimal unique pubkey prefix for logs! */
		char *idname = type_to_string(peer, struct pubkey, &peer->id);
		channel->log = new_log(channel,
				       peer->log_book, "%s chan #%"PRIu64":",
				       idname, dbid);
		tal_free(idname);
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
	channel->funding_satoshi = funding_satoshi;
	channel->push_msat = push_msat;
	channel->remote_funding_locked = remote_funding_locked;
	channel->scid = tal_steal(channel, scid);
	channel->our_msatoshi = our_msatoshi;
	channel->msatoshi_to_us_min = msatoshi_to_us_min;
	channel->msatoshi_to_us_max = msatoshi_to_us_max;
	channel->last_tx = tal_steal(channel, last_tx);
	channel->last_sig = *last_sig;
	channel->last_htlc_sigs = tal_steal(channel, last_htlc_sigs);
	channel->channel_info = *channel_info;
	channel->remote_shutdown_scriptpubkey
		= tal_steal(channel, remote_shutdown_scriptpubkey);
	channel->final_key_idx = final_key_idx;
	channel->last_was_revoke = last_was_revoke;
	channel->last_sent_commit = tal_steal(channel, last_sent_commit);
	channel->first_blocknum = first_blocknum;
	channel->min_possible_feerate = min_possible_feerate;
	channel->max_possible_feerate = max_possible_feerate;
	derive_channel_seed(peer->ld, &channel->seed, &peer->id, channel->dbid);

	list_add_tail(&peer->channels, &channel->list);
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

struct channel *active_channel_by_id(struct lightningd *ld,
				     const struct pubkey *id,
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
			 const secp256k1_ecdsa_signature *sig)
{
	channel->last_sig = *sig;
	tal_free(channel->last_tx);
	channel->last_tx = tal_steal(channel, tx);
}

void channel_set_state(struct channel *channel,
		       enum channel_state old_state,
		       enum channel_state state)
{
	log_info(channel->log, "State changed from %s to %s",
		 channel_state_name(channel), channel_state_str(state));
	if (channel->state != old_state)
		fatal("channel state %s should be %s",
		      channel_state_name(channel), channel_state_str(old_state));

	channel->state = state;

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(channel->peer->ld->wallet, channel);
}

void channel_fail_permanent(struct channel *channel, const char *fmt, ...)
{
	struct lightningd *ld = channel->peer->ld;
	va_list ap;
	char *why;
	struct channel_id cid;

	va_start(ap, fmt);
	why = tal_vfmt(channel, fmt, ap);
	va_end(ap);

	if (channel->scid) {
		u8 *msg = towire_gossip_disable_channel(NULL,
						    channel->scid,
						    channel->peer->direction,
						    false);
		subd_send_msg(ld->gossip, take(msg));
	}

	log_unusual(channel->log, "Peer permanent failure in %s: %s",
		    channel_state_name(channel), why);

	/* We can have multiple errors, eg. onchaind failures. */
	if (!channel->error) {
		derive_channel_id(&cid,
				  &channel->funding_txid,
				  channel->funding_outnum);
		channel->error = towire_errorfmt(channel, &cid, "%s", why);
	}

	channel_set_owner(channel, NULL);
	drop_to_chain(ld, channel);
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

void channel_fail_transient(struct channel *channel, const char *fmt, ...)
{
	va_list ap;
	const char *why;

	va_start(ap, fmt);
	why = tal_vfmt(channel, fmt, ap);
	va_end(ap);
	log_info(channel->log, "Peer transient failure in %s: %s",
		 channel_state_name(channel), why);
	tal_free(why);

#if DEVELOPER
	if (dev_disconnect_permanent(channel->peer->ld)) {
		channel_internal_error(channel, "dev_disconnect permfail");
		return;
	}
#endif

	channel_set_owner(channel, NULL);

	/* Reconnect unless we've dropped/are dropping to chain. */
	if (channel_active(channel)) {
		struct lightningd *ld = channel->peer->ld;

#if DEVELOPER
		/* Don't schedule an attempt if we disabled reconnections with
		 * the `--dev-no-reconnect` flag */
		if (ld->no_reconnect)
			return;
#endif /* DEVELOPER */
		u8 *msg = towire_gossipctl_reach_peer(NULL,
						      &channel->peer->id);
		subd_send_msg(ld->gossip, take(msg));
	}
}
