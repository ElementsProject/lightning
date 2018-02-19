#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/tal/str/str.h>
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <lightningd/channel.h>
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

static void destroy_channel(struct channel *channel)
{
	/* Must not have any HTLCs! */
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	struct lightningd *ld = channel->peer->ld;

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;
		fatal("Freeing channel %s has hout %s",
		      channel_state_name(channel),
		      htlc_state_name(hout->hstate));
	}

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;
		fatal("Freeing channel %s has hin %s",
		      channel_state_name(channel),
		      htlc_state_name(hin->hstate));
	}

	/* Free any old owner still hanging around. */
	channel_set_owner(channel, NULL);

	list_del_from(&channel->peer->channels, &channel->list);
}

/* FIXME: remove why */
void delete_channel(struct channel *channel, const char *why)
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

struct channel *new_channel(struct peer *peer, u64 dbid, u32 first_blocknum)
{
	/* FIXME: We currently rely on it being all zero/NULL */
	struct channel *channel = talz(peer->ld, struct channel);
	char *idname;

	assert(dbid != 0);
	channel->dbid = dbid;
	channel->peer = peer;
	channel->first_blocknum = first_blocknum;
	channel->state = UNINITIALIZED;
	channel->local_shutdown_idx = -1;

	/* FIXME: update log prefix when we get scid */
	/* FIXME: Use minimal unique pubkey prefix for logs! */
	idname = type_to_string(peer, struct pubkey, &peer->id);
	channel->log = new_log(channel, peer->log_book, "%s chan #%"PRIu64":",
			       idname, dbid);
	tal_free(idname);
	list_add_tail(&peer->channels, &channel->list);
	tal_add_destructor(channel, destroy_channel);
	derive_channel_seed(peer->ld, &channel->seed, &peer->id, channel->dbid);

	return channel;
}

const char *channel_state_name(const struct channel *channel)
{
	return peer_state_name(channel->state);
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

void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const secp256k1_ecdsa_signature *sig)
{
	tal_free(channel->last_sig);
	channel->last_sig = tal_dup(channel, secp256k1_ecdsa_signature, sig);
	tal_free(channel->last_tx);
	channel->last_tx = tal_steal(channel, tx);
}

void channel_set_state(struct channel *channel,
		       enum peer_state old_state,
		       enum peer_state state)
{
	log_info(channel->log, "State changed from %s to %s",
		 channel_state_name(channel), peer_state_name(state));
	if (channel->state != old_state)
		fatal("channel state %s should be %s",
		      channel_state_name(channel), peer_state_name(old_state));

	channel->state = state;

	/* We only persist channels/peers that have reached the opening state */
	if (channel_persists(channel)) {
		/* TODO(cdecker) Selectively save updated fields to DB */
		wallet_channel_save(channel->peer->ld->wallet, channel);
	}
}

void channel_fail_permanent(struct channel *channel, const char *fmt, ...)
{
	struct lightningd *ld = channel->peer->ld;
	va_list ap;
	char *why;
	u8 *msg;

	va_start(ap, fmt);
	why = tal_vfmt(channel, fmt, ap);
	va_end(ap);

	if (channel->scid) {
		msg = towire_gossip_disable_channel(channel,
						    channel->scid,
						    channel->peer->direction,
						    false);
		subd_send_msg(ld->gossip, take(msg));
	}

	log_unusual(channel->log, "Peer permanent failure in %s: %s",
		    channel_state_name(channel), why);

	/* We can have multiple errors, eg. onchaind failures. */
	if (!channel->error) {
		/* BOLT #1:
		 *
		 * The channel is referred to by `channel_id` unless `channel_id` is
		 * zero (ie. all bytes zero), in which case it refers to all
		 * channels. */
		static const struct channel_id all_channels;
		u8 *msg = tal_dup_arr(NULL, u8, (const u8 *)why, strlen(why), 0);
		channel->error = towire_error(channel, &all_channels, msg);
		tal_free(msg);
	}

	channel_set_owner(channel, NULL);
	if (channel_persists(channel)) {
		drop_to_chain(ld, channel);
		tal_free(why);
	} else
		delete_channel(channel, why);
}

void channel_internal_error(struct channel *channel, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_broken(channel->log, "Peer internal error %s: ",
		   channel_state_name(channel));
	logv_add(channel->log, fmt, ap);
	va_end(ap);

	channel_fail_permanent(channel, "Internal error");
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

#if DEVELOPER
	if (dev_disconnect_permanent(channel->peer->ld)) {
		tal_free(why);
		channel_internal_error(channel, "dev_disconnect permfail");
		return;
	}
#endif

	channel_set_owner(channel, NULL);

	/* If we haven't reached awaiting locked, we don't need to reconnect */
	if (!channel_persists(channel)) {
		log_info(channel->log, "Only reached state %s: forgetting",
			 channel_state_name(channel));
		delete_channel(channel, why);
		return;
	}
	tal_free(why);

	/* Reconnect unless we've dropped/are dropping to chain. */
	if (channel_active(channel)) {
		struct lightningd *ld = channel->peer->ld;

#if DEVELOPER
		/* Don't schedule an attempt if we disabled reconnections with
		 * the `--dev-no-reconnect` flag */
		if (ld->no_reconnect)
			return;
#endif /* DEVELOPER */
		u8 *msg = towire_gossipctl_reach_peer(channel,
						      &channel->peer->id);
		subd_send_msg(ld->gossip, take(msg));
	}
}
