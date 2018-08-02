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
#include <common/json_escaped.h>
#include <common/key_derive.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/log.h>
#include <lightningd/onchain_control.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/param.h>
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

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct pubkey *id,
		      const struct wireaddr_internal *addr,
		      const u8 *gfeatures TAKES, const u8 *lfeatures TAKES)
{
	/* We are owned by our channels, and freed manually by destroy_channel */
	struct peer *peer = tal(NULL, struct peer);

	peer->ld = ld;
	peer->dbid = dbid;
	peer->id = *id;
	peer->uncommitted_channel = NULL;
	/* FIXME: This is always set, right? */
	if (addr)
		peer->addr = *addr;
	else {
		peer->addr.itype = ADDR_INTERNAL_WIREADDR;
		peer->addr.u.wireaddr.type = ADDR_TYPE_PADDING;
	}
	peer->global_features = tal_dup_arr(peer, u8,
					    gfeatures, tal_count(gfeatures), 0);
	peer->local_features = tal_dup_arr(peer, u8,
					   lfeatures, tal_count(lfeatures), 0);
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

	if (!json_tok_pubkey(buffer, peeridtok, &peerid))
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

u32 feerate_min(struct lightningd *ld)
{
	u32 min;

	/* We can't allow less than feerate_floor, since that won't relay */
	if (ld->config.ignore_fee_limits)
		min = 1;
	else
		/* Set this to half of slow rate.*/
		min = get_feerate(ld->topology, FEERATE_SLOW) / 2;

	if (min < feerate_floor())
		return feerate_floor();
	return min;
}

/* BOLT #2:
 *
 * Given the variance in fees, and the fact that the transaction may be
 * spent in the future, it's a good idea for the fee payer to keep a good
 * margin (say 5x the expected fee requirement)
 */
u32 feerate_max(struct lightningd *ld)
{
	if (ld->config.ignore_fee_limits)
		return UINT_MAX;

	return get_feerate(ld->topology, FEERATE_IMMEDIATE) *
	       ld->config.max_fee_multiplier;
}

static void sign_last_tx(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	secp256k1_ecdsa_signature sig;
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
	struct json_result *result = new_json_result(cc);
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

	command_success(cc->cmd, result);
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
	command_fail(cc->cmd, LIGHTNINGD,
		     "Channel forgotten before proper close.");
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
		command_fail(cc->cmd, LIGHTNINGD,
			     "Channel close negotiation not finished "
			     "before timeout");
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
	u8 *msg;

	/* Tell connectd we no longer need to keep connection to this peer */
	msg = towire_connectctl_peer_important(NULL, &channel->peer->id, false);
	subd_send_msg(ld->connectd, take(msg));

	sign_last_tx(channel);

	/* Keep broadcasting until we say stop (can fail due to dup,
	 * if they beat us to the broadcast). */
	broadcast_tx(ld->topology, channel, channel->last_tx, NULL);

	resolve_close_command(ld, channel, cooperative);

	remove_sig(channel->last_tx);
}

void channel_errmsg(struct channel *channel,
		    int peer_fd, int gossip_fd,
		    const struct crypto_state *cs,
		    const struct channel_id *channel_id UNUSED,
		    const char *desc,
		    const u8 *err_for_them)
{
	struct lightningd *ld = channel->peer->ld;
	u8 *msg;

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

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *   - when `channel_id` is 0:
	 *    - MUST fail all channels with the receiving node.
	 *    - MUST close the connection.
	 */
	/* FIXME: Connectd closes connection, but doesn't fail channels. */

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

	/* Hand back to connectd, with any error packet. */
	msg = towire_connectctl_hand_back_peer(NULL, &channel->peer->id,
					      cs, err_for_them);
	subd_send_msg(ld->connectd, take(msg));
	subd_send_fd(ld->connectd, peer_fd);
	subd_send_fd(ld->connectd, gossip_fd);
}

/* Connectd tells us a peer has connected: it never hands us duplicates, since
 * it holds them until we say peer_died. */
void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd)
{
	struct pubkey id;
	struct crypto_state cs;
	u8 *gfeatures, *lfeatures;
	u8 *error;
	struct channel *channel;
	struct wireaddr_internal addr;
	struct uncommitted_channel *uc;

	if (!fromwire_connect_peer_connected(msg, msg,
					    &id, &addr, &cs,
					    &gfeatures, &lfeatures))
		fatal("Connectd gave bad CONNECT_PEER_CONNECTED message %s",
		      tal_hex(msg, msg));

	/* Were we trying to open a channel, and we've raced? */
	if (handle_opening_channel(ld, &id, &addr, &cs,
				   gfeatures, lfeatures, peer_fd, gossip_fd))
		return;

	/* If we're already dealing with this peer, hand off to correct
	 * subdaemon.  Otherwise, we'll respond iff they ask about an inactive
	 * channel. */
	channel = active_channel_by_id(ld, &id, &uc);

	/* Can't be opening now, since we wouldn't have sent peer_died. */
	assert(!uc);

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
			channel_internal_error(channel, "dev_disconnect permfail");
			error = channel->error;
			goto send_error;
	}
#endif

		switch (channel->state) {
		case ONCHAIN:
		case FUNDING_SPEND_SEEN:
		case CLOSINGD_COMPLETE:
			/* Channel is active! */
			abort();

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

	/* No err, all good. */
	error = NULL;

send_error:
	/* Hand back to channeld, with an error packet. */
	msg = towire_connectctl_hand_back_peer(msg, &id, &cs, error);
	subd_send_msg(ld->connectd, take(msg));
	subd_send_fd(ld->connectd, peer_fd);
	subd_send_fd(ld->connectd, gossip_fd);
}

static struct channel *channel_by_channel_id(struct peer *peer,
					     const struct channel_id *channel_id)
{
	struct channel *channel;

	list_for_each(&peer->channels, channel, list) {
		struct channel_id cid;

		derive_channel_id(&cid,
				  &channel->funding_txid,
				  channel->funding_outnum);
		if (channel_id_eq(&cid, channel_id))
			return channel;
	}
	return NULL;
}

/* We only get here IF we weren't trying to connect to it. */
void peer_sent_nongossip(struct lightningd *ld,
			 const struct pubkey *id,
			 const struct wireaddr_internal *addr,
			 const struct crypto_state *cs,
			 const u8 *gfeatures,
			 const u8 *lfeatures,
			 int peer_fd, int gossip_fd,
			 const u8 *in_msg)
{
	struct channel_id *channel_id, extracted_channel_id;
	struct peer *peer;
	u8 *error, *msg;

	if (!extract_channel_id(in_msg, &extracted_channel_id))
		channel_id = NULL;
	else
		channel_id = &extracted_channel_id;

	peer = peer_by_id(ld, id);

	/* Open request? */
	if (fromwire_peektype(in_msg) == WIRE_OPEN_CHANNEL) {
		error = peer_accept_channel(tmpctx,
					    ld, id, addr, cs,
					    gfeatures, lfeatures,
					    peer_fd, gossip_fd, channel_id,
					    in_msg);
		if (error)
			goto send_error;
		return;
	}

	/* If they are talking about a specific channel id, we may have an
	 * error for them. */
	if (peer && channel_id) {
		struct channel *channel;
		channel = channel_by_channel_id(peer, channel_id);
		if (channel && channel->error) {
			error = channel->error;
			goto send_error;
		}

		/* Reestablish for a now-closed channel?  They might have
		 * missed final update, so do the closing negotiation dance
		 * again. */
		if (fromwire_peektype(in_msg) == WIRE_CHANNEL_REESTABLISH
		    && channel
		    && channel->state == CLOSINGD_COMPLETE) {
			peer_start_closingd(channel, cs,
					    peer_fd, gossip_fd, true, in_msg);
			return;
		}
	}

	/* Weird request. */
	error = towire_errorfmt(tmpctx, channel_id,
				"Unexpected message %i for peer",
				fromwire_peektype(in_msg));

send_error:
	/* Hand back to channeld, with an error packet. */
	msg = towire_connectctl_hand_back_peer(ld, id, cs, error);
	subd_send_msg(ld->connectd, take(msg));
	subd_send_fd(ld->connectd, peer_fd);
	subd_send_fd(ld->connectd, gossip_fd);
}

static enum watch_result funding_lockin_cb(struct channel *channel,
					   const struct bitcoin_txid *txid,
					   unsigned int depth)
{
	const char *txidstr;
	struct lightningd *ld = channel->peer->ld;

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

struct getpeers_args {
	struct command *cmd;
	/* If non-NULL, they want logs too */
	enum log_level *ll;
	/* If set, only report on a specific id. */
	struct pubkey *specific_id;
};

static void connectd_getpeers_complete(struct subd *connectd, const u8 *msg,
				      const int *fds UNUSED,
				      struct getpeers_args *gpa)
{
	/* This is a little sneaky... */
	struct pubkey *ids;
	struct wireaddr_internal *addrs;
	struct peer_features **pf;
	struct json_result *response = new_json_result(gpa->cmd);
	struct peer *p;

	if (!fromwire_connect_getpeers_reply(msg, msg, &ids, &addrs, &pf)) {
		command_fail(gpa->cmd, LIGHTNINGD,
			     "Bad response from connectd");
		return;
	}

	/* First the peers not just gossiping. */
	json_object_start(response, NULL);
	json_array_start(response, "peers");
	list_for_each(&gpa->cmd->ld->peers, p, list) {
		bool connected;
		struct channel *channel;
		struct channel_stats channel_stats;

		if (gpa->specific_id && !pubkey_eq(gpa->specific_id, &p->id))
			continue;

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
			if (p->addr.itype != ADDR_INTERNAL_WIREADDR
			    || p->addr.u.wireaddr.type != ADDR_TYPE_PADDING)
				json_add_string(response, NULL,
						type_to_string(response,
							       struct wireaddr_internal,
							       &p->addr));
			json_array_end(response);
			json_add_hex_talarr(response, "global_features",
					    p->global_features);

			json_add_hex_talarr(response, "local_features",
					    p->local_features);
		}

		json_array_start(response, "channels");
		json_add_uncommitted_channel(response, p->uncommitted_channel);

		list_for_each(&p->channels, channel, list) {
			struct channel_id cid;
			u64 our_reserve_msat = channel->channel_info.their_config.channel_reserve_satoshis * 1000;
			json_object_start(response, NULL);
			json_add_string(response, "state",
					channel_state_name(channel));
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
					type_to_string(tmpctx,
						       struct channel_id,
						       &cid));
			json_add_txid(response,
				      "funding_txid",
				      &channel->funding_txid);
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
			wallet_channel_stats_load(gpa->cmd->ld->wallet,
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

			json_object_end(response);
		}
		json_array_end(response);

		if (gpa->ll)
			json_add_log(response, p->log_book, *gpa->ll);
		json_object_end(response);
	}

	for (size_t i = 0; i < tal_count(ids); i++) {
		/* Don't report peers in both, which can happen if they're
		 * reconnecting */
		if (peer_by_id(gpa->cmd->ld, ids + i))
			continue;

		json_object_start(response, NULL);
		/* Fake state. */
		json_add_string(response, "state", "GOSSIPING");
		json_add_pubkey(response, "id", ids+i);
		json_add_hex_talarr(response, "global_features",
				    pf[i]->global_features);

		json_add_hex_talarr(response, "local_features",
				    pf[i]->local_features);
		json_array_start(response, "netaddr");
		if (addrs[i].itype != ADDR_INTERNAL_WIREADDR
		    || addrs[i].u.wireaddr.type != ADDR_TYPE_PADDING)
			json_add_string(response, NULL,
					type_to_string(response,
						       struct wireaddr_internal,
						       addrs + i));
		json_array_end(response);
		json_add_bool(response, "connected", true);
		json_add_string(response, "owner", connectd->name);
		json_object_end(response);
	}

	json_array_end(response);
	json_object_end(response);
	command_success(gpa->cmd, response);
}

static void json_listpeers(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct getpeers_args *gpa = tal(cmd, struct getpeers_args);

	gpa->cmd = cmd;
	if (!param(cmd, buffer, params,
		   p_opt("id", json_tok_pubkey, &gpa->specific_id),
		   p_opt("level", json_tok_loglevel, &gpa->ll),
		   NULL))
		return;

	/* Get peers from connectd. */
	subd_req(cmd, cmd->ld->connectd,
		 take(towire_connect_getpeers_request(cmd, gpa->specific_id)),
		 -1, 0, connectd_getpeers_complete, gpa);
	command_still_pending(cmd);
}

static const struct json_command listpeers_command = {
	"listpeers",
	json_listpeers,
	"Show current peers, if {level} is set, include logs for {id}"
};
AUTODATA(json_command, &listpeers_command);

static struct channel *
command_find_channel(struct command *cmd,
		     const char *buffer, const jsmntok_t *tok)
{
	struct lightningd *ld = cmd->ld;
	struct channel_id cid;
	struct channel_id channel_cid;
	struct short_channel_id scid;
	struct peer *peer;
	struct channel *channel;

	if (json_tok_channel_id(buffer, tok, &cid)) {
		list_for_each(&ld->peers, peer, list) {
			channel = peer_active_channel(peer);
			if (!channel)
				continue;
			derive_channel_id(&channel_cid,
					  &channel->funding_txid,
					  channel->funding_outnum);
			if (channel_id_eq(&channel_cid, &cid))
				return channel;
		}
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Channel ID not found: '%.*s'",
			     tok->end - tok->start,
			     buffer + tok->start);
		return NULL;
	} else if (json_tok_short_channel_id(buffer, tok, &scid)) {
		list_for_each(&ld->peers, peer, list) {
			channel = peer_active_channel(peer);
			if (!channel)
				continue;
			if (channel->scid && channel->scid->u64 == scid.u64)
				return channel;
		}
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Short channel ID not found: '%.*s'",
			     tok->end - tok->start,
			     buffer + tok->start);
		return NULL;
	} else {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Given id is not a channel ID or "
			     "short channel ID: '%.*s'",
			     tok->end - tok->start,
			     buffer + tok->start);
		return NULL;
	}
}

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	const jsmntok_t *idtok;
	struct peer *peer;
	struct channel *channel;
	unsigned int timeout;
	bool force;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_tok, &idtok),
		   p_opt_def("force", json_tok_bool, &force, false),
		   p_opt_def("timeout", json_tok_number, &timeout, 30),
		   NULL))
		return;

	peer = peer_from_json(cmd->ld, buffer, idtok);
	if (peer)
		channel = peer_active_channel(peer);
	else {
		channel = command_find_channel(cmd, buffer, idtok);
		if (!channel)
			return;
	}

	if (!channel && peer) {
		struct uncommitted_channel *uc = peer->uncommitted_channel;
		if (uc) {
			/* Easy case: peer can simply be forgotten. */
			kill_uncommitted_channel(uc, "close command called");

			command_success(cmd, null_response(cmd));
			return;
		}
		command_fail(cmd, LIGHTNINGD,
			     "Peer has no active channel");
		return;
	}

	/* Normal case.
	 * We allow states shutting down and sigexchange; a previous
	 * close command may have timed out, and this current command
	 * will continue waiting for the effects of the previous
	 * close command. */
	if (channel->state != CHANNELD_NORMAL &&
	    channel->state != CHANNELD_AWAITING_LOCKIN &&
	    channel->state != CHANNELD_SHUTTING_DOWN &&
	    channel->state != CLOSINGD_SIGEXCHANGE)
		command_fail(cmd, LIGHTNINGD, "Channel is in state %s",
			     channel_state_name(channel));

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
	register_close_command(cmd->ld, cmd, channel, timeout, force);

	/* Wait until close drops down to chain. */
	command_still_pending(cmd);
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

	/* Pass connectd any addrhints we currently have */
	msg = towire_connectctl_peer_addrhint(peer, &peer->id, &peer->addr);
	subd_send_msg(peer->ld->connectd, take(msg));

	/* We can only have one active channel: make sure connectd
	 * knows to reconnect. */
	channel = peer_active_channel(peer);
	if (channel)
		tell_connectd_peer_is_important(ld, channel);

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

/* Peer has been released from connectd. */
static void connectd_peer_disconnected(struct subd *connectd,
				       const u8 *resp,
				       const int *fds,
				       struct command *cmd)
{
	bool isconnected;

	if (!fromwire_connectctl_peer_disconnect_reply(resp)) {
		if (!fromwire_connectctl_peer_disconnect_replyfail(resp, &isconnected))
			fatal("Connect daemon gave invalid reply %s",
			      tal_hex(tmpctx, resp));
		if (isconnected)
			command_fail(cmd, LIGHTNINGD,
				     "Peer is not in gossip mode");
		else
			command_fail(cmd, LIGHTNINGD, "Peer not connected");
	} else {
		/* Successfully disconnected */
		command_success(cmd, null_response(cmd));
	}
	return;
}

static void json_disconnect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct pubkey id;
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &id),
		   NULL))
		return;

	msg = towire_connectctl_peer_disconnect(cmd, &id);
	subd_req(cmd, cmd->ld->connectd, msg, -1, 0, connectd_peer_disconnected, cmd);
	command_still_pending(cmd);
}

static const struct json_command disconnect_command = {
	"disconnect",
	json_disconnect,
	"Disconnect from {id} that has previously been connected to using connect"
};
AUTODATA(json_command, &disconnect_command);

#if DEVELOPER
static void json_sign_last_tx(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	struct pubkey peerid;
	struct peer *peer;
	struct json_result *response = new_json_result(cmd);
	u8 *linear;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &peerid),
		   NULL))
		return;

	peer = peer_by_id(cmd->ld, &peerid);
	if (!peer) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find peer with that id");
		return;
	}
	channel = peer_active_channel(peer);
	if (!channel) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find active channel");
		return;
	}

	log_debug(channel->log, "dev-sign-last-tx: signing tx with %zu outputs",
		  tal_count(channel->last_tx->output));
	sign_last_tx(channel);
	linear = linearize_tx(cmd, channel->last_tx);
	remove_sig(channel->last_tx);

	json_object_start(response, NULL);
	json_add_hex_talarr(response, "tx", linear);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command dev_sign_last_tx = {
	"dev-sign-last-tx",
	json_sign_last_tx,
	"Sign and show the last commitment transaction with peer {id}"
};
AUTODATA(json_command, &dev_sign_last_tx);

static void json_dev_fail(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct pubkey peerid;
	struct peer *peer;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &peerid),
		   NULL))
		return;

	peer = peer_by_id(cmd->ld, &peerid);
	if (!peer) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find peer with that id");
		return;
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find active channel with peer");
		return;
	}

	channel_internal_error(channel, "Failing due to dev-fail command");
	command_success(cmd, null_response(cmd));
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
	command_success(cmd, null_response(cmd));
}

static void json_dev_reenable_commit(struct command *cmd,
				     const char *buffer, const jsmntok_t *params)
{
	struct pubkey peerid;
	struct peer *peer;
	u8 *msg;
	struct channel *channel;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &peerid),
		   NULL))
		return;

	peer = peer_by_id(cmd->ld, &peerid);
	if (!peer) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find peer with that id");
		return;
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		command_fail(cmd, LIGHTNINGD,
			     "Peer has no active channel");
		return;
	}
	if (!channel->owner) {
		command_fail(cmd, LIGHTNINGD,
			     "Peer has no owner");
		return;
	}

	if (!streq(channel->owner->name, "lightning_channeld")) {
		command_fail(cmd, LIGHTNINGD,
			     "Peer owned by %s", channel->owner->name);
		return;
	}

	msg = towire_channel_dev_reenable_commit(channel);
	subd_req(peer, channel->owner, take(msg), -1, 0,
		 dev_reenable_commit_finished, cmd);
	command_still_pending(cmd);
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
	struct json_result *response;
	struct dev_forget_channel_cmd *forget = arg;
	if (txout != NULL && !forget->force) {
		command_fail(forget->cmd, LIGHTNINGD,
			     "Cowardly refusing to forget channel with an "
			     "unspent funding output, if you know what "
			     "you're doing you can override with "
			     "`force=true`, otherwise consider `close` or "
			     "`dev-fail`! If you force and the channel "
			     "confirms we will not track the funds in the "
			     "channel");
		return;
	}
	response = new_json_result(forget->cmd);
	json_object_start(response, NULL);
	json_add_bool(response, "forced", forget->force);
	json_add_bool(response, "funding_unspent", txout != NULL);
	json_add_txid(response, "funding_txid", &forget->channel->funding_txid);
	json_object_end(response);

	delete_channel(forget->channel);

	command_success(forget->cmd, response);
}

static void json_dev_forget_channel(struct command *cmd, const char *buffer,
				    const jsmntok_t *params)
{
	struct pubkey peerid;
	struct peer *peer;
	struct channel *channel;
	struct short_channel_id *scid;
	struct dev_forget_channel_cmd *forget = tal(cmd, struct dev_forget_channel_cmd);
	forget->cmd = cmd;

	/* If &forget->force is used directly in p_opt_def() below then
	 * gcc 7.3.0 fails with:
	 * 'operation on ‘forget->force’ may be undefined [-Werror=sequence-point]'
	 *
	 * See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=86584
	 *
	 * Hence this indirection.
	 */
	bool *force = &forget->force;
	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &peerid),
		   p_opt("short_channel_id", json_tok_short_channel_id, &scid),
		   p_opt_def("force", json_tok_bool, force, false),
		   NULL))
		return;

	peer = peer_by_id(cmd->ld, &peerid);
	if (!peer) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find channel with that peer");
		return;
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
			command_fail(cmd, LIGHTNINGD,
				     "Multiple channels:"
				     " please specify short_channel_id");
			return;
		}
		forget->channel = channel;
	}
	if (!forget->channel) {
		command_fail(cmd, LIGHTNINGD,
			     "No channels matching that short_channel_id");
		return;
	}

	if (channel_has_htlc_out(forget->channel) ||
	    channel_has_htlc_in(forget->channel)) {
		command_fail(cmd, LIGHTNINGD,
			     "This channel has HTLCs attached and it is "
			     "not safe to forget it. Please use `close` "
			     "or `dev-fail` instead.");
		return;

	}

	bitcoind_gettxout(cmd->ld->topology->bitcoind,
			  &forget->channel->funding_txid,
			  forget->channel->funding_outnum,
			  process_dev_forget_channel, forget);
	command_still_pending(cmd);
}

static const struct json_command dev_forget_channel_command = {
	"dev-forget-channel", json_dev_forget_channel,
	"Forget the channel with peer {id}, ignore UTXO check with {force}='true'.", false,
	"Forget the channel with peer {id}. Checks if the channel is still active by checking its funding transaction. Check can be ignored by setting {force} to 'true'"
};
AUTODATA(json_command, &dev_forget_channel_command);
#endif /* DEVELOPER */
