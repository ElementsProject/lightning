#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <arpa/inet.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <channeld/gen_channel_wire.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/initial_commit_tx.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/key_derive.h>
#include <common/param.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/memdump.h>
#include <lightningd/notification.h>
#include <lightningd/onchain_control.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/peer_htlcs.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/gen_onion_wire.h>
#include <wire/wire_sync.h>

struct close_command {
	/* Inside struct lightningd close_commands. */
	struct list_node list;
	/* Command structure. This is the parent of the close command. */
	struct command *cmd;
	/* Channel being closed. */
	struct channel *channel;
	/* Should we force the close on timeout? */
	bool force;
};

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
}

/* We copy per-peer entries above --log-level into the main log. */
static void copy_to_parent_log(const char *prefix,
			       enum log_level level,
			       bool continued,
			       const struct timeabs *time UNUSED,
			       const char *str,
			       const u8 *io,
			       struct log *parent_log)
{
	if (level == LOG_IO_IN || level == LOG_IO_OUT)
		log_io(parent_log, level, prefix, io, tal_count(io));
	else if (continued)
		log_add(parent_log, "%s ... %s", prefix, str);
	else
		log_(parent_log, level, "%s %s", prefix, str);
}

static void peer_update_features(struct peer *peer,
				 const u8 *globalfeatures TAKES,
				 const u8 *localfeatures TAKES)
{
	tal_free(peer->globalfeatures);
	tal_free(peer->localfeatures);
	peer->globalfeatures = tal_dup_arr(peer, u8,
					   globalfeatures,
					   tal_count(globalfeatures), 0);
	peer->localfeatures = tal_dup_arr(peer, u8,
					  localfeatures,
					  tal_count(localfeatures), 0);
}

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct pubkey *id,
		      const struct wireaddr_internal *addr)
{
	/* We are owned by our channels, and freed manually by destroy_channel */
	struct peer *peer = tal(NULL, struct peer);

	peer->ld = ld;
	peer->dbid = dbid;
	peer->id = *id;
	peer->uncommitted_channel = NULL;
	peer->addr = *addr;
	peer->globalfeatures = peer->localfeatures = NULL;
	list_head_init(&peer->channels);
	peer->direction = get_channel_direction(&peer->ld->id, &peer->id);

#if DEVELOPER
	peer->ignore_htlcs = false;
#endif

	/* Max 128k per peer. */
	peer->log_book = new_log_book(128*1024, get_log_level(ld->log_book));
	set_log_outfn(peer->log_book, copy_to_parent_log, ld->log);
	list_add_tail(&ld->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

static void delete_peer(struct peer *peer)
{
	assert(list_empty(&peer->channels));
	assert(!peer->uncommitted_channel);
	/* If it only ever existed because of uncommitted channel, it won't
	 * be in the database */
	if (peer->dbid != 0)
		wallet_peer_delete(peer->ld->wallet, peer->dbid);
	tal_free(peer);
}

/* Last one out deletes peer. */
void maybe_delete_peer(struct peer *peer)
{
	if (peer->uncommitted_channel)
		return;
	if (!list_empty(&peer->channels))
		return;
	delete_peer(peer);
}

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (p->dbid == dbid)
			return p;
	return NULL;
}

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (pubkey_eq(&p->id, id))
			return p;
	return NULL;
}

struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    const jsmntok_t *peeridtok)
{
	struct pubkey peerid;

	if (!json_to_pubkey(buffer, peeridtok, &peerid))
		return NULL;

	return peer_by_id(ld, &peerid);
}

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx)
{
	struct pubkey shutdownkey;

	if (!bip32_pubkey(ld->wallet->bip32_base, &shutdownkey, keyidx))
		return NULL;

	return scriptpubkey_p2wpkh(ctx, &shutdownkey);
}

static void sign_last_tx(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_signature sig;
	u8 *msg;

	assert(!channel->last_tx->input[0].witness);

	msg = towire_hsm_sign_commitment_tx(tmpctx,
					    &channel->peer->id,
					    channel->dbid,
					    channel->last_tx,
					    &channel->channel_info
					    .remote_fundingkey,
					    channel->funding_satoshi);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsm_sign_commitment_tx_reply(msg, &sig))
		fatal("HSM gave bad sign_commitment_tx_reply %s",
		      tal_hex(tmpctx, msg));

	channel->last_tx->input[0].witness
		= bitcoin_witness_2of2(channel->last_tx->input,
				       &channel->last_sig,
				       &sig,
				       &channel->channel_info.remote_fundingkey,
				       &channel->local_funding_pubkey);
}

static void remove_sig(struct bitcoin_tx *signed_tx)
{
	signed_tx->input[0].witness = tal_free(signed_tx->input[0].witness);
}

/* Resolve a single close command. */
static void
resolve_one_close_command(struct close_command *cc, bool cooperative)
{
	struct json_stream *result = json_stream_success(cc->cmd);
	u8 *tx = linearize_tx(result, cc->channel->last_tx);
	struct bitcoin_txid txid;

	bitcoin_txid(cc->channel->last_tx, &txid);

	json_object_start(result, NULL);
	json_add_hex_talarr(result, "tx", tx);
	json_add_txid(result, "txid", &txid);
	if (cooperative)
		json_add_string(result, "type", "mutual");
	else
		json_add_string(result, "type", "unilateral");
	json_object_end(result);

	was_pending(command_success(cc->cmd, result));
}

/* Resolve a close command for a channel that will be closed soon. */
static void
resolve_close_command(struct lightningd *ld, struct channel *channel,
		      bool cooperative)
{
	struct close_command *cc;
	struct close_command *n;

	list_for_each_safe (&ld->close_commands, cc, n, list) {
		if (cc->channel != channel)
			continue;
		resolve_one_close_command(cc, cooperative);
	}
}

/* Destroy the close command structure in reaction to the
 * channel being destroyed. */
static void
destroy_close_command_on_channel_destroy(struct channel *_ UNUSED,
					 struct close_command *cc)
{
	/* The cc has the command as parent, so resolving the
	 * command destroys the cc and triggers destroy_close_command.
	 * Clear the cc->channel first so that we will not try to
	 * remove a destructor. */
	cc->channel = NULL;
	was_pending(command_fail(cc->cmd, LIGHTNINGD,
				 "Channel forgotten before proper close."));
}

/* Destroy the close command structure. */
static void
destroy_close_command(struct close_command *cc)
{
	list_del(&cc->list);
	/* If destroy_close_command_on_channel_destroy was
	 * triggered beforehand, it will have cleared
	 * the channel field, preventing us from removing it
	 * from an already-destroyed channel. */
	if (!cc->channel)
		return;
	tal_del_destructor2(cc->channel,
			    &destroy_close_command_on_channel_destroy,
			    cc);
}

/* Handle timeout. */
static void
close_command_timeout(struct close_command *cc)
{
	if (cc->force)
		/* This will trigger drop_to_chain, which will trigger
		 * resolution of the command and destruction of the
		 * close_command. */
		channel_fail_permanent(cc->channel,
				       "Forcibly closed by 'close' command timeout");
	else
		/* Fail the command directly, which will resolve the
		 * command and destroy the close_command. */
		was_pending(command_fail(cc->cmd, LIGHTNINGD,
					 "Channel close negotiation not finished "
					 "before timeout"));
}

/* Construct a close command structure and add to ld. */
static void
register_close_command(struct lightningd *ld,
		       struct command *cmd,
		       struct channel *channel,
		       unsigned int timeout,
		       bool force)
{
	struct close_command *cc;
	assert(channel);

	cc = tal(cmd, struct close_command);
	list_add_tail(&ld->close_commands, &cc->list);
	cc->cmd = cmd;
	cc->channel = channel;
	cc->force = force;
	tal_add_destructor(cc, &destroy_close_command);
	tal_add_destructor2(channel,
			    &destroy_close_command_on_channel_destroy,
			    cc);
	new_reltimer(&ld->timers, cc, time_from_sec(timeout),
		     &close_command_timeout, cc);
}

void drop_to_chain(struct lightningd *ld, struct channel *channel,
		   bool cooperative)
{
	/* BOLT #2:
	 *
	 * - if `next_remote_revocation_number` is greater than expected
	 *   above, AND `your_last_per_commitment_secret` is correct for that
	 *   `next_remote_revocation_number` minus 1:
	 *      - MUST NOT broadcast its commitment transaction.
	 */
	if (channel->future_per_commitment_point && !cooperative) {
		log_broken(channel->log,
			   "Cannot broadcast our commitment tx:"
			   " they have a future one");
	} else {
		sign_last_tx(channel);

		/* Keep broadcasting until we say stop (can fail due to dup,
		 * if they beat us to the broadcast). */
		broadcast_tx(ld->topology, channel, channel->last_tx, NULL);

		remove_sig(channel->last_tx);
	}

	resolve_close_command(ld, channel, cooperative);
}

void channel_errmsg(struct channel *channel,
		    int peer_fd, int gossip_fd,
		    const struct crypto_state *cs,
		    const struct channel_id *channel_id UNUSED,
		    const char *desc,
		    const u8 *err_for_them)
{
	/* No peer fd means a subd crash or disconnection. */
	if (peer_fd == -1) {
		channel_fail_transient(channel, "%s: %s",
				       channel->owner->name, desc);
		return;
	}

	/* Do we have an error to send? */
	if (err_for_them && !channel->error)
		channel->error = tal_dup_arr(channel, u8,
					     err_for_them,
					     tal_count(err_for_them), 0);

	/* Make sure channel_fail_permanent doesn't tell connectd we died! */
	channel->connected = false;
	notify_disconnect(channel->peer->ld, &channel->peer->id);

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *   - when `channel_id` is 0:
	 *    - MUST fail all channels with the receiving node.
	 *    - MUST close the connection.
	 */
	/* FIXME: Close if it's an all-channels error sent or rcvd */

	/* BOLT #1:
	 *
	 * A sending node:
	 *  - when sending `error`:
	 *    - MUST fail the channel referred to by the error message.
	 *...
	 * The receiving node:
	 *  - upon receiving `error`:
	 *    - MUST fail the channel referred to by the error message,
	 *      if that channel is with the sending node.
	 */
	channel_fail_permanent(channel, "%s: %s ERROR %s",
			       channel->owner->name,
			       err_for_them ? "sent" : "received", desc);
}

/* Connectd tells us a peer has connected: it never hands us duplicates, since
 * it holds them until we say peer_died. */
void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd)
{
	struct pubkey id;
	struct crypto_state cs;
	u8 *globalfeatures, *localfeatures;
	u8 *error;
	struct channel *channel;
	struct wireaddr_internal addr;
	struct peer *peer;

	if (!fromwire_connect_peer_connected(msg, msg,
					     &id, &addr, &cs,
					     &globalfeatures, &localfeatures))
		fatal("Connectd gave bad CONNECT_PEER_CONNECTED message %s",
		      tal_hex(msg, msg));

	/* Complete any outstanding connect commands. */
	connect_succeeded(ld, &id);

	/* If we're already dealing with this peer, hand off to correct
	 * subdaemon.  Otherwise, we'll hand to openingd to wait there. */
	peer = peer_by_id(ld, &id);
	if (!peer)
		peer = new_peer(ld, 0, &id, &addr);

	peer_update_features(peer, globalfeatures, localfeatures);

	/* Can't be opening, since we wouldn't have sent peer_disconnected. */
	assert(!peer->uncommitted_channel);
	channel = peer_active_channel(peer);

	if (channel) {
		log_debug(channel->log, "Peer has reconnected, state %s",
			  channel_state_name(channel));

		/* If we have a canned error, deliver it now. */
		if (channel->error) {
			error = channel->error;
			goto send_error;
		}

#if DEVELOPER
		if (dev_disconnect_permanent(ld)) {
			channel_internal_error(channel,
					       "dev_disconnect permfail");
			error = channel->error;
			goto send_error;
		}
#endif

		switch (channel->state) {
		case ONCHAIN:
		case FUNDING_SPEND_SEEN:
		case CLOSINGD_COMPLETE:
			/* Channel is supposed to be active! */
			abort();

		/* We consider this "active" but we only send an error */
		case AWAITING_UNILATERAL: {
			struct channel_id cid;
			derive_channel_id(&cid,
					  &channel->funding_txid,
					  channel->funding_outnum);
			/* channel->error is not saved in db, so this can
			 * happen if we restart. */
			error = towire_errorfmt(tmpctx, &cid,
						"Awaiting unilateral close");
			goto send_error;
		}

		case CHANNELD_AWAITING_LOCKIN:
		case CHANNELD_NORMAL:
		case CHANNELD_SHUTTING_DOWN:
			assert(!channel->owner);

			channel->peer->addr = addr;
			peer_start_channeld(channel, &cs,
					    peer_fd, gossip_fd, NULL,
					    true);
			return;

		case CLOSINGD_SIGEXCHANGE:
			assert(!channel->owner);

			channel->peer->addr = addr;
			peer_start_closingd(channel, &cs,
					    peer_fd, gossip_fd,
					    true, NULL);
			return;
		}
		abort();
	}

	notify_connect(ld, &id, &addr);

	/* No err, all good. */
	error = NULL;

send_error:
	peer_start_openingd(peer, &cs, peer_fd, gossip_fd, error);
}

static enum watch_result funding_lockin_cb(struct lightningd *ld,
					   struct channel *channel,
					   const struct bitcoin_txid *txid,
					   unsigned int depth)
{
	const char *txidstr;

	txidstr = type_to_string(channel, struct bitcoin_txid, txid);
	log_debug(channel->log, "Funding tx %s depth %u of %u",
		  txidstr, depth, channel->minimum_depth);
	tal_free(txidstr);

	if (depth < channel->minimum_depth)
		return KEEP_WATCHING;

	/* If we restart, we could already have peer->scid from database */
	if (!channel->scid) {
		struct txlocator *loc;

		loc = wallet_transaction_locate(tmpctx, ld->wallet, txid);
		channel->scid = tal(channel, struct short_channel_id);
		mk_short_channel_id(channel->scid,
				    loc->blkheight, loc->index,
				    channel->funding_outnum);
		/* We've added scid, update */
		wallet_channel_save(ld->wallet, channel);
	}

	/* Try to tell subdaemon */
	if (!channel_tell_funding_locked(ld, channel, txid, depth))
		return KEEP_WATCHING;

	/* BOLT #7:
	 *
	 * A node:
	 *   - if the `open_channel` message has the `announce_channel` bit set
	 *     AND a `shutdown` message has not been sent:
	 *     - MUST send the `announcement_signatures` message.
	 *       - MUST NOT send `announcement_signatures` messages until
	 *         `funding_locked` has been sent AND the funding transaction has
	 *         at least six confirmations.
	 *   - otherwise:
	 *     - MUST NOT send the `announcement_signatures` message.
	 */
	if (!(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
		return DELETE_WATCH;

	/* We keep telling it depth until we get to announce depth. */
	if (depth < ANNOUNCE_MIN_DEPTH)
		return KEEP_WATCHING;

	return DELETE_WATCH;
}

static enum watch_result funding_spent(struct channel *channel,
				       const struct bitcoin_tx *tx,
				       size_t inputnum UNUSED,
				       const struct block *block)
{
	struct bitcoin_txid txid;
	bitcoin_txid(tx, &txid);

	wallet_channeltxs_add(channel->peer->ld->wallet, channel,
			      WIRE_ONCHAIN_INIT, &txid, 0, block->height);

	return onchaind_funding_spent(channel, tx, block->height);
}

void channel_watch_funding(struct lightningd *ld, struct channel *channel)
{
	/* FIXME: Remove arg from cb? */
	watch_txid(channel, ld->topology, channel,
		   &channel->funding_txid, funding_lockin_cb);
	watch_txo(channel, ld->topology, channel,
		  &channel->funding_txid, channel->funding_outnum,
		  funding_spent);
}

static void json_add_htlcs(struct lightningd *ld,
			   struct json_stream *response,
			   const struct channel *channel)
{
	/* FIXME: make per-channel htlc maps! */
	const struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	const struct htlc_out *hout;
	struct htlc_out_map_iter outi;

	/* FIXME: Add more fields. */
	json_array_start(response, "htlcs");
	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "direction", "in");
		json_add_u64(response, "id", hin->key.id);
		json_add_u64(response, "msatoshi", hin->msatoshi);
		json_add_u64(response, "expiry", hin->cltv_expiry);
		json_add_hex(response, "payment_hash",
			     &hin->payment_hash, sizeof(hin->payment_hash));
		json_add_string(response, "state",
				htlc_state_name(hin->hstate));
		json_object_end(response);
	}

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "direction", "out");
		json_add_u64(response, "id", hout->key.id);
		json_add_u64(response, "msatoshi", hout->msatoshi);
		json_add_u64(response, "expiry", hout->cltv_expiry);
		json_add_hex(response, "payment_hash",
			     &hout->payment_hash, sizeof(hout->payment_hash));
		json_add_string(response, "state",
				htlc_state_name(hout->hstate));
		json_object_end(response);
	}
	json_array_end(response);
}

static void json_add_peer(struct lightningd *ld,
			  struct json_stream *response,
			  struct peer *p,
			  const enum log_level *ll)
{
	bool connected;
	struct channel *channel;

	json_object_start(response, NULL);
	json_add_pubkey(response, "id", &p->id);

	/* Channel is also connected if uncommitted channel */
	if (p->uncommitted_channel)
		connected = true;
	else {
		channel = peer_active_channel(p);
		connected = channel && channel->connected;
	}
	json_add_bool(response, "connected", connected);

	/* If it's not connected, features are unreliable: we don't
	 * store them in the database, and they would only reflect
	 * their features *last* time they connected. */
	if (connected) {
		json_array_start(response, "netaddr");
		json_add_string(response, NULL,
				type_to_string(response,
					       struct wireaddr_internal,
					       &p->addr));
		json_array_end(response);
		if (deprecated_apis) {
			json_add_hex_talarr(response, "global_features",
					    p->globalfeatures);
			json_add_hex_talarr(response, "local_features",
					    p->localfeatures);
		}
		json_add_hex_talarr(response, "globalfeatures",
				    p->globalfeatures);
		json_add_hex_talarr(response, "localfeatures",
				    p->localfeatures);
	}

	json_array_start(response, "channels");
	json_add_uncommitted_channel(response, p->uncommitted_channel);

	list_for_each(&p->channels, channel, list) {
		struct channel_id cid;
		struct channel_stats channel_stats;
		u64 our_reserve_msat = channel->channel_info.their_config.channel_reserve_satoshis * 1000;
		json_object_start(response, NULL);
		json_add_string(response, "state",
				channel_state_name(channel));
		if (channel->last_tx) {
			struct bitcoin_txid txid;
			bitcoin_txid(channel->last_tx, &txid);

			json_add_txid(response, "scratch_txid", &txid);
		}
		if (channel->owner)
			json_add_string(response, "owner",
					channel->owner->name);
		if (channel->scid)
			json_add_short_channel_id(response,
						  "short_channel_id",
						  channel->scid);
		derive_channel_id(&cid,
				  &channel->funding_txid,
				  channel->funding_outnum);
		json_add_string(response, "channel_id",
				type_to_string(tmpctx, struct channel_id, &cid));
		json_add_txid(response,
			      "funding_txid",
			      &channel->funding_txid);
		json_add_bool(response, "private",
				!(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL));
		json_add_u64(response, "msatoshi_to_us",
			     channel->our_msatoshi);
		json_add_u64(response, "msatoshi_to_us_min",
			     channel->msatoshi_to_us_min);
		json_add_u64(response, "msatoshi_to_us_max",
			     channel->msatoshi_to_us_max);
		json_add_u64(response, "msatoshi_total",
			     channel->funding_satoshi * 1000);

		/* channel config */
		json_add_u64(response, "dust_limit_satoshis",
			     channel->our_config.dust_limit_satoshis);
		json_add_u64(response, "max_htlc_value_in_flight_msat",
			     channel->our_config.max_htlc_value_in_flight_msat);

		/* The `channel_reserve_satoshis` is imposed on
		 * the *other* side (see `channel_reserve_msat`
		 * function in, it uses `!side` to flip sides).
		 * So our configuration `channel_reserve_satoshis`
		 * is imposed on their side, while their
		 * configuration `channel_reserve_satoshis` is
		 * imposed on ours. */
		json_add_u64(response, "their_channel_reserve_satoshis",
			     channel->our_config.channel_reserve_satoshis);
		json_add_u64(response, "our_channel_reserve_satoshis",
			     channel->channel_info.their_config.channel_reserve_satoshis);
		/* Compute how much we can send via this channel. */
		if (channel->our_msatoshi <= our_reserve_msat)
			json_add_u64(response, "spendable_msatoshi", 0);
		else
			json_add_u64(response, "spendable_msatoshi",
				     channel->our_msatoshi - our_reserve_msat);
		json_add_u64(response, "htlc_minimum_msat",
			     channel->our_config.htlc_minimum_msat);

		/* The `to_self_delay` is imposed on the *other*
		 * side, so our configuration `to_self_delay` is
		 * imposed on their side, while their configuration
		 * `to_self_delay` is imposed on ours. */
		json_add_num(response, "their_to_self_delay",
			     channel->our_config.to_self_delay);
		json_add_num(response, "our_to_self_delay",
			     channel->channel_info.their_config.to_self_delay);
		json_add_num(response, "max_accepted_htlcs",
			     channel->our_config.max_accepted_htlcs);

		json_array_start(response, "status");
		for (size_t i = 0;
		     i < ARRAY_SIZE(channel->billboard.permanent);
		     i++) {
			if (!channel->billboard.permanent[i])
				continue;
			json_add_string(response, NULL,
					channel->billboard.permanent[i]);
		}
		if (channel->billboard.transient)
			json_add_string(response, NULL,
					channel->billboard.transient);
		json_array_end(response);

		/* Provide channel statistics */
		wallet_channel_stats_load(ld->wallet,
					  channel->dbid,
					  &channel_stats);
		json_add_u64(response, "in_payments_offered",
			     channel_stats.in_payments_offered);
		json_add_u64(response, "in_msatoshi_offered",
			     channel_stats.in_msatoshi_offered);
		json_add_u64(response, "in_payments_fulfilled",
			     channel_stats.in_payments_fulfilled);
		json_add_u64(response, "in_msatoshi_fulfilled",
			     channel_stats.in_msatoshi_fulfilled);
		json_add_u64(response, "out_payments_offered",
			     channel_stats.out_payments_offered);
		json_add_u64(response, "out_msatoshi_offered",
			     channel_stats.out_msatoshi_offered);
		json_add_u64(response, "out_payments_fulfilled",
			     channel_stats.out_payments_fulfilled);
		json_add_u64(response, "out_msatoshi_fulfilled",
			     channel_stats.out_msatoshi_fulfilled);

		json_add_htlcs(ld, response, channel);
		json_object_end(response);
	}
	json_array_end(response);

	if (ll)
		json_add_log(response, p->log_book, *ll);
	json_object_end(response);
}

static struct command_result *json_listpeers(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	enum log_level *ll;
	struct pubkey *specific_id;
	struct peer *peer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_pubkey, &specific_id),
		   p_opt("level", param_loglevel, &ll),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "peers");
	if (specific_id) {
		peer = peer_by_id(cmd->ld, specific_id);
		if (peer)
			json_add_peer(cmd->ld, response, peer, ll);
	} else {
		list_for_each(&cmd->ld->peers, peer, list)
			json_add_peer(cmd->ld, response, peer, ll);
	}
	json_array_end(response);
	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command listpeers_command = {
	"listpeers",
	json_listpeers,
	"Show current peers, if {level} is set, include logs for {id}"
};
AUTODATA(json_command, &listpeers_command);

static struct command_result *
command_find_channel(struct command *cmd,
		     const char *buffer, const jsmntok_t *tok,
		     struct channel **channel)
{
	struct lightningd *ld = cmd->ld;
	struct channel_id cid;
	struct channel_id channel_cid;
	struct short_channel_id scid;
	struct peer *peer;

	if (json_tok_channel_id(buffer, tok, &cid)) {
		list_for_each(&ld->peers, peer, list) {
			*channel = peer_active_channel(peer);
			if (!*channel)
				continue;
			derive_channel_id(&channel_cid,
					  &(*channel)->funding_txid,
					  (*channel)->funding_outnum);
			if (channel_id_eq(&channel_cid, &cid))
				return NULL;
		}
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Channel ID not found: '%.*s'",
				    tok->end - tok->start,
				    buffer + tok->start);
	} else if (json_to_short_channel_id(buffer, tok, &scid)) {
		list_for_each(&ld->peers, peer, list) {
			*channel = peer_active_channel(peer);
			if (!*channel)
				continue;
			if ((*channel)->scid
			    && (*channel)->scid->u64 == scid.u64)
				return NULL;
		}
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Short channel ID not found: '%.*s'",
				    tok->end - tok->start,
				    buffer + tok->start);
	} else {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Given id is not a channel ID or "
				    "short channel ID: '%.*s'",
				    json_tok_full_len(tok),
				    json_tok_full(buffer, tok));
	}
}

static struct command_result *json_close(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *obj UNNEEDED,
					 const jsmntok_t *params)
{
	const jsmntok_t *idtok;
	struct peer *peer;
	/* FIXME: gcc 7.3.0 thinks this might not be initialized. */
	struct channel *channel = NULL;
	unsigned int *timeout;
	bool *force;

	if (!param(cmd, buffer, params,
		   p_req("id", param_tok, &idtok),
		   p_opt_def("force", param_bool, &force, false),
		   p_opt_def("timeout", param_number, &timeout, 30),
		   NULL))
		return command_param_failed();

	peer = peer_from_json(cmd->ld, buffer, idtok);
	if (peer)
		channel = peer_active_channel(peer);
	else {
		struct command_result *res;
		res = command_find_channel(cmd, buffer, idtok, &channel);
		if (res)
			return res;
	}

	if (!channel && peer) {
		struct uncommitted_channel *uc = peer->uncommitted_channel;
		if (uc) {
			/* Easy case: peer can simply be forgotten. */
			kill_uncommitted_channel(uc, "close command called");

			return command_success(cmd, null_response(cmd));
		}
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no active channel");
	}

	/* Normal case.
	 * We allow states shutting down and sigexchange; a previous
	 * close command may have timed out, and this current command
	 * will continue waiting for the effects of the previous
	 * close command. */
	if (channel->state != CHANNELD_NORMAL &&
	    channel->state != CHANNELD_AWAITING_LOCKIN &&
	    channel->state != CHANNELD_SHUTTING_DOWN &&
	    channel->state != CLOSINGD_SIGEXCHANGE) {
		return command_fail(cmd, LIGHTNINGD, "Channel is in state %s",
				    channel_state_name(channel));
	}

	/* If normal or locking in, transition to shutting down
	 * state.
	 * (if already shutting down or sigexchange, just keep
	 * waiting) */
	if (channel->state == CHANNELD_NORMAL || channel->state == CHANNELD_AWAITING_LOCKIN) {
		channel_set_state(channel,
				  channel->state, CHANNELD_SHUTTING_DOWN);

		if (channel->owner)
			subd_send_msg(channel->owner,
				      take(towire_channel_send_shutdown(channel)));
	}

	/* Register this command for later handling. */
	register_close_command(cmd->ld, cmd, channel, *timeout, *force);

	/* Wait until close drops down to chain. */
	return command_still_pending(cmd);
}

static const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with {id} "
	"(either peer ID, channel ID, or short channel ID). "
	"If {force} (default false) is true, force a unilateral close "
	"after {timeout} seconds (default 30), "
	"otherwise just schedule a mutual close later and fail after "
	"timing out."
};
AUTODATA(json_command, &close_command);

static void activate_peer(struct peer *peer)
{
	u8 *msg;
	struct channel *channel;
	struct lightningd *ld = peer->ld;

	/* We can only have one active channel: make sure connectd
	 * knows to try reconnecting. */
	channel = peer_active_channel(peer);
	if (channel && ld->reconnect) {
		msg = towire_connectctl_connect_to_peer(NULL, &peer->id, 0,
							&peer->addr);
		subd_send_msg(ld->connectd, take(msg));
		channel_set_billboard(channel, false, "Attempting to reconnect");
	}

	list_for_each(&peer->channels, channel, list) {
		/* Watching lockin may be unnecessary, but it's harmless. */
		channel_watch_funding(ld, channel);
	}
}

void activate_peers(struct lightningd *ld)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		activate_peer(p);
}

/* Pull peers, channels and HTLCs from db, and wire them up. */
void load_channels_from_wallet(struct lightningd *ld)
{
	struct peer *peer;

	/* Load peers from database */
	if (!wallet_channels_load_active(ld, ld->wallet))
		fatal("Could not load channels from the database");

	/* This is a poor-man's db join :( */
	list_for_each(&ld->peers, peer, list) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			if (!wallet_htlcs_load_for_channel(ld->wallet,
							   channel,
							   &ld->htlcs_in,
							   &ld->htlcs_out)) {
				fatal("could not load htlcs for channel");
			}
		}
	}

	/* Now connect HTLC pointers together */
	htlcs_reconnect(ld, &ld->htlcs_in, &ld->htlcs_out);
}

static struct command_result *json_disconnect(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct pubkey *id;
	struct peer *peer;
	struct channel *channel;
	bool *force;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &id),
		   p_opt_def("force", param_bool, &force, false),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");
	}
	channel = peer_active_channel(peer);
	if (channel) {
		if (*force) {
			channel_fail_transient(channel,
					       "disconnect command force=true");
			return command_success(cmd, null_response(cmd));
		}
		return command_fail(cmd, LIGHTNINGD, "Peer is in state %s",
				    channel_state_name(channel));
	}
	if (!peer->uncommitted_channel) {
		return command_fail(cmd, LIGHTNINGD, "Peer not connected");
	}
	kill_uncommitted_channel(peer->uncommitted_channel,
				 "disconnect command");
	return command_success(cmd, null_response(cmd));
}

static const struct json_command disconnect_command = {
	"disconnect",
	json_disconnect,
	"Disconnect from {id} that has previously been connected to using connect; with {force} set, even if it has a current channel"
};
AUTODATA(json_command, &disconnect_command);

static struct command_result *json_getinfo(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
    struct json_stream *response;
    struct peer *peer;
    struct channel *channel;
    unsigned int pending_channels = 0, active_channels = 0,
            inactive_channels = 0, num_peers = 0;

    if (!param(cmd, buffer, params, NULL))
        return command_param_failed();

    response = json_stream_success(cmd);
    json_object_start(response, NULL);
    json_add_pubkey(response, "id", &cmd->ld->id);
    json_add_string(response, "alias", (const char *)cmd->ld->alias);
    json_add_hex_talarr(response, "color", cmd->ld->rgb);

    /* Add some peer and channel stats */
    list_for_each(&cmd->ld->peers, peer, list) {
        num_peers++;
        /* Count towards pending? */
        if (peer->uncommitted_channel) {
            pending_channels++;
        }

        list_for_each(&peer->channels, channel, list) {
            if (channel->state == CHANNELD_AWAITING_LOCKIN) {
                pending_channels++;
            } else if (channel_active(channel)) {
                active_channels++;
            } else {
                inactive_channels++;
            }
        }
    }
    json_add_num(response, "num_peers", num_peers);
    json_add_num(response, "num_pending_channels", pending_channels);
    json_add_num(response, "num_active_channels", active_channels);
    json_add_num(response, "num_inactive_channels", inactive_channels);

    /* Add network info */
    if (cmd->ld->listen) {
        /* These are the addresses we're announcing */
        json_array_start(response, "address");
        for (size_t i = 0; i < tal_count(cmd->ld->announcable); i++)
            json_add_address(response, NULL, cmd->ld->announcable+i);
        json_array_end(response);

        /* This is what we're actually bound to. */
        json_array_start(response, "binding");
        for (size_t i = 0; i < tal_count(cmd->ld->binding); i++)
            json_add_address_internal(response, NULL,
                          cmd->ld->binding+i);
        json_array_end(response);
    }
    json_add_string(response, "version", version());
    json_add_num(response, "blockheight", get_block_height(cmd->ld->topology));
    json_add_string(response, "network", get_chainparams(cmd->ld)->network_name);
    json_add_u64(response, "msatoshi_fees_collected",
             wallet_total_forward_fees(cmd->ld->wallet));
    json_object_end(response);
    return command_success(cmd, response);
}

static const struct json_command getinfo_command = {
    "getinfo",
    json_getinfo,
    "Show information about this node"
};
AUTODATA(json_command, &getinfo_command);

#if DEVELOPER
static struct command_result *json_sign_last_tx(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct pubkey *peerid;
	struct peer *peer;
	struct json_stream *response;
	u8 *linear;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &peerid),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find peer with that id");
	}
	channel = peer_active_channel(peer);
	if (!channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find active channel");
	}

	response = json_stream_success(cmd);
	log_debug(channel->log, "dev-sign-last-tx: signing tx with %zu outputs",
		  tal_count(channel->last_tx->output));
	sign_last_tx(channel);
	linear = linearize_tx(cmd, channel->last_tx);
	remove_sig(channel->last_tx);

	json_object_start(response, NULL);
	json_add_hex_talarr(response, "tx", linear);
	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command dev_sign_last_tx = {
	"dev-sign-last-tx",
	json_sign_last_tx,
	"Sign and show the last commitment transaction with peer {id}"
};
AUTODATA(json_command, &dev_sign_last_tx);

static struct command_result *json_dev_fail(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct pubkey *peerid;
	struct peer *peer;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &peerid),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find peer with that id");
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find active channel with peer");
	}

	channel_internal_error(channel, "Failing due to dev-fail command");
	return command_success(cmd, null_response(cmd));
}

static const struct json_command dev_fail_command = {
	"dev-fail",
	json_dev_fail,
	"Fail with peer {id}"
};
AUTODATA(json_command, &dev_fail_command);

static void dev_reenable_commit_finished(struct subd *channeld UNUSED,
					 const u8 *resp UNUSED,
					 const int *fds UNUSED,
					 struct command *cmd)
{
	was_pending(command_success(cmd, null_response(cmd)));
}

static struct command_result *json_dev_reenable_commit(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	struct pubkey *peerid;
	struct peer *peer;
	u8 *msg;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &peerid),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find peer with that id");
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no active channel");
	}
	if (!channel->owner) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no owner");
	}

	if (!streq(channel->owner->name, "lightning_channeld")) {
		return command_fail(cmd, LIGHTNINGD,
				    "Peer owned by %s", channel->owner->name);
	}

	msg = towire_channel_dev_reenable_commit(channel);
	subd_req(peer, channel->owner, take(msg), -1, 0,
		 dev_reenable_commit_finished, cmd);
	return command_still_pending(cmd);
}

static const struct json_command dev_reenable_commit = {
	"dev-reenable-commit",
	json_dev_reenable_commit,
	"Re-enable the commit timer on peer {id}"
};
AUTODATA(json_command, &dev_reenable_commit);

struct dev_forget_channel_cmd {
	struct short_channel_id scid;
	struct channel *channel;
	bool force;
	struct command *cmd;
};

static void process_dev_forget_channel(struct bitcoind *bitcoind UNUSED,
				       const struct bitcoin_tx_output *txout,
				       void *arg)
{
	struct json_stream *response;
	struct dev_forget_channel_cmd *forget = arg;
	if (txout != NULL && !forget->force) {
		was_pending(command_fail(forget->cmd, LIGHTNINGD,
			     "Cowardly refusing to forget channel with an "
			     "unspent funding output, if you know what "
			     "you're doing you can override with "
			     "`force=true`, otherwise consider `close` or "
			     "`dev-fail`! If you force and the channel "
			     "confirms we will not track the funds in the "
			     "channel"));
		return;
	}
	response = json_stream_success(forget->cmd);
	json_object_start(response, NULL);
	json_add_bool(response, "forced", forget->force);
	json_add_bool(response, "funding_unspent", txout != NULL);
	json_add_txid(response, "funding_txid", &forget->channel->funding_txid);
	json_object_end(response);

	/* Set error so we don't try to reconnect. */
	forget->channel->error = towire_errorfmt(forget->channel, NULL,
						 "dev_forget_channel");
	delete_channel(forget->channel);

	was_pending(command_success(forget->cmd, response));
}

static struct command_result *json_dev_forget_channel(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct pubkey *peerid;
	struct peer *peer;
	struct channel *channel;
	struct short_channel_id *scid;
	struct dev_forget_channel_cmd *forget = tal(cmd, struct dev_forget_channel_cmd);
	forget->cmd = cmd;

	bool *force;
	if (!param(cmd, buffer, params,
		   p_req("id", param_pubkey, &peerid),
		   p_opt("short_channel_id", param_short_channel_id, &scid),
		   p_opt_def("force", param_bool, &force, false),
		   NULL))
		return command_param_failed();

	forget->force = *force;
	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find channel with that peer");
	}

	forget->channel = NULL;
	list_for_each(&peer->channels, channel, list) {
		if (scid) {
			if (!channel->scid)
				continue;
			if (!short_channel_id_eq(channel->scid, scid))
				continue;
		}
		if (forget->channel) {
			return command_fail(cmd, LIGHTNINGD,
					    "Multiple channels:"
					    " please specify short_channel_id");
		}
		forget->channel = channel;
	}
	if (!forget->channel) {
		return command_fail(cmd, LIGHTNINGD,
				    "No channels matching that short_channel_id");
	}

	if (channel_has_htlc_out(forget->channel) ||
	    channel_has_htlc_in(forget->channel)) {
		return command_fail(cmd, LIGHTNINGD,
				    "This channel has HTLCs attached and it is "
				    "not safe to forget it. Please use `close` "
				    "or `dev-fail` instead.");
	}

	bitcoind_gettxout(cmd->ld->topology->bitcoind,
			  &forget->channel->funding_txid,
			  forget->channel->funding_outnum,
			  process_dev_forget_channel, forget);
	return command_still_pending(cmd);
}

static const struct json_command dev_forget_channel_command = {
	"dev-forget-channel", json_dev_forget_channel,
	"Forget the channel with peer {id}, ignore UTXO check with {force}='true'.", false,
	"Forget the channel with peer {id}. Checks if the channel is still active by checking its funding transaction. Check can be ignored by setting {force} to 'true'"
};
AUTODATA(json_command, &dev_forget_channel_command);

static void subd_died_forget_memleak(struct subd *openingd, struct command *cmd)
{
	/* FIXME: We ignore the remaining per-peer daemons in this case. */
	peer_memleak_done(cmd, NULL);
}

/* Mutual recursion */
static void peer_memleak_req_next(struct command *cmd, struct channel *prev);
static void peer_memleak_req_done(struct subd *subd, bool found_leak,
				  struct command *cmd)
{
	struct channel *c = subd->channel;

	if (found_leak)
		peer_memleak_done(cmd, subd);
	else
		peer_memleak_req_next(cmd, c);
}

static void channeld_memleak_req_done(struct subd *channeld,
				      const u8 *msg, const int *fds UNUSED,
				      struct command *cmd)
{
	bool found_leak;

	tal_del_destructor2(channeld, subd_died_forget_memleak, cmd);
	if (!fromwire_channel_dev_memleak_reply(msg, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad channel_dev_memleak"));
		return;
	}
	peer_memleak_req_done(channeld, found_leak, cmd);
}

static void onchaind_memleak_req_done(struct subd *onchaind,
				      const u8 *msg, const int *fds UNUSED,
				      struct command *cmd)
{
	bool found_leak;

	tal_del_destructor2(onchaind, subd_died_forget_memleak, cmd);
	if (!fromwire_onchain_dev_memleak_reply(msg, &found_leak)) {
		was_pending(command_fail(cmd, LIGHTNINGD,
					 "Bad onchain_dev_memleak"));
		return;
	}
	peer_memleak_req_done(onchaind, found_leak, cmd);
}

static void peer_memleak_req_next(struct command *cmd, struct channel *prev)
{
	struct peer *p;

	list_for_each(&cmd->ld->peers, p, list) {
		struct channel *c;

		list_for_each(&p->channels, c, list) {
			if (c == prev) {
				prev = NULL;
				continue;
			}

			if (!c->owner)
				continue;

			if (prev != NULL)
				continue;

			/* Note: closingd does its own checking automatically */
			if (streq(c->owner->name, "lightning_channeld")) {
				subd_req(c, c->owner,
					 take(towire_channel_dev_memleak(NULL)),
					 -1, 0, channeld_memleak_req_done, cmd);
				tal_add_destructor2(c->owner,
						    subd_died_forget_memleak,
						    cmd);
				return;
			}
			if (streq(c->owner->name, "lightning_onchaind")) {
				subd_req(c, c->owner,
					 take(towire_onchain_dev_memleak(NULL)),
					 -1, 0, onchaind_memleak_req_done, cmd);
				tal_add_destructor2(c->owner,
						    subd_died_forget_memleak,
						    cmd);
				return;
			}
		}
	}
	peer_memleak_done(cmd, NULL);
}

void peer_dev_memleak(struct command *cmd)
{
	peer_memleak_req_next(cmd, NULL);
}
#endif /* DEVELOPER */

