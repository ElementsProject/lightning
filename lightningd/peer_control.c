#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <arpa/inet.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <channeld/gen_channel_wire.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/initial_commit_tx.h>
#include <common/key_derive.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/routing.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/build_utxos.h>
#include <lightningd/chaintopology.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/netaddress.h>
#include <lightningd/onchain_control.h>
#include <lightningd/opening_control.h>
#include <lightningd/options.h>
#include <lightningd/peer_htlcs.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/gen_onion_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* FIXME: Reorder */
static void copy_to_parent_log(const char *prefix,
			       enum log_level level,
			       bool continued,
			       const struct timeabs *time,
			       const char *str,
			       const u8 *io,
			       struct log *parent_log);

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
}

struct peer *new_peer(struct lightningd *ld, u64 dbid,
		      const struct pubkey *id,
		      const struct wireaddr *addr)
{
	/* We are owned by our channels, and freed manually by destroy_channel */
	struct peer *peer = tal(NULL, struct peer);

	peer->ld = ld;
	peer->dbid = dbid;
	peer->id = *id;
	peer->uncommitted_channel = NULL;
	if (addr)
		peer->addr = *addr;
	else
		peer->addr.type = ADDR_TYPE_PADDING;
	list_head_init(&peer->channels);
	peer->direction = get_channel_direction(&peer->ld->id, &peer->id);

	/* Max 128k per peer. */
	peer->log_book = new_log_book(128*1024, get_log_level(ld->log_book));
	set_log_outfn(peer->log_book, copy_to_parent_log, ld->log);
	list_add_tail(&ld->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

void delete_peer(struct peer *peer)
{
	assert(list_empty(&peer->channels));
	assert(!peer->uncommitted_channel);
	/* If it only ever existed because of uncommitted channel, it won't
	 * be in the database */
	if (peer->dbid != 0)
		wallet_peer_delete(peer->ld->wallet, peer->dbid);
	tal_free(peer);
}

struct peer *find_peer_by_dbid(struct lightningd *ld, u64 dbid)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (p->dbid == dbid)
			return p;
	return NULL;
}

static void sign_last_tx(struct channel *channel)
{
	const tal_t *tmpctx = tal_tmpctx(channel);
	u8 *funding_wscript;
	struct pubkey local_funding_pubkey;
	struct secrets secrets;
	secp256k1_ecdsa_signature sig;

	assert(!channel->last_tx->input[0].witness);

	derive_basepoints(&channel->seed, &local_funding_pubkey, NULL, &secrets,
			  NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &channel->channel_info.remote_fundingkey);
	/* Need input amount for signing */
	channel->last_tx->input[0].amount = tal_dup(channel->last_tx->input, u64,
						    &channel->funding_satoshi);
	sign_tx_input(channel->last_tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      &sig);

	channel->last_tx->input[0].witness
		= bitcoin_witness_2of2(channel->last_tx->input,
				       &channel->last_sig,
				       &sig,
				       &channel->channel_info.remote_fundingkey,
				       &local_funding_pubkey);

	tal_free(tmpctx);
}

static void remove_sig(struct bitcoin_tx *signed_tx)
{
	signed_tx->input[0].amount = tal_free(signed_tx->input[0].amount);
	signed_tx->input[0].witness = tal_free(signed_tx->input[0].witness);
}

void drop_to_chain(struct lightningd *ld, struct channel *channel)
{
	sign_last_tx(channel);

	/* Keep broadcasting until we say stop (can fail due to dup,
	 * if they beat us to the broadcast). */
	broadcast_tx(ld->topology, channel, channel->last_tx, NULL);
	remove_sig(channel->last_tx);
}

void channel_errmsg(struct channel *channel,
		    int peer_fd, int gossip_fd,
		    const struct crypto_state *cs,
		    u64 gossip_index,
		    const struct channel_id *channel_id,
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
					     tal_len(err_for_them), 0);

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *   - when `channel_id` is 0:
	 *    - MUST fail all channels.
	 *    - MUST close the connection.
	 */
	/* FIXME: Gossipd closes connection, but doesn't fail channels. */

	/* BOLT #1:
	 *
	 * A sending node:
	 *  - when sending `error`:
	 *    - MUST fail the channel referred to by the error message.
	 *...
	 * The receiving node:
	 *  - upon receiving `error`:
	 *    - MUST fail the channel referred to by the error message.
	 */
	channel_fail_permanent(channel, "%s: %s ERROR %s",
			       channel->owner->name,
			       err_for_them ? "sent" : "received", desc);

	/* Hand back to gossipd, with any error packet. */
	msg = towire_gossipctl_hand_back_peer(NULL, &channel->peer->id,
					      cs, gossip_index,
					      err_for_them);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);
}

/* Gossipd tells us a peer has connected */
void peer_connected(struct lightningd *ld, const u8 *msg,
		    int peer_fd, int gossip_fd)
{
	struct pubkey id;
	struct crypto_state cs;
	u8 *gfeatures, *lfeatures;
	u8 *error;
	u8 *supported_global_features;
	u8 *supported_local_features;
	struct channel *channel;
	struct wireaddr addr;
	u64 gossip_index;
	struct uncommitted_channel *uc;

	if (!fromwire_gossip_peer_connected(msg, msg, NULL,
					    &id, &addr, &cs, &gossip_index,
					    &gfeatures, &lfeatures))
		fatal("Gossip gave bad GOSSIP_PEER_CONNECTED message %s",
		      tal_hex(msg, msg));

	if (unsupported_features(gfeatures, lfeatures)) {
		log_unusual(ld->log, "peer %s offers unsupported features %s/%s",
			    type_to_string(msg, struct pubkey, &id),
			    tal_hex(msg, gfeatures),
			    tal_hex(msg, lfeatures));
		supported_global_features = get_supported_global_features(msg);
		supported_local_features = get_supported_local_features(msg);
		error = towire_errorfmt(msg, NULL,
					"We only support globalfeatures %s"
					" and localfeatures %s",
					tal_hexstr(msg,
						   supported_global_features,
						   tal_len(supported_global_features)),
					tal_hexstr(msg,
						   supported_local_features,
						   tal_len(supported_local_features)));
		goto send_error;
	}

	/* If we're already dealing with this peer, hand off to correct
	 * subdaemon.  Otherwise, we'll respond iff they ask about an inactive
	 * channel. */
	channel = active_channel_by_id(ld, &id, &uc);

	/* Opening now?  Kill it */
	if (uc) {
		kill_uncommitted_channel(uc, "Peer reconnected");
		goto return_to_gossipd;
	}

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
		case ONCHAIND_CHEATED:
		case ONCHAIND_THEIR_UNILATERAL:
		case ONCHAIND_OUR_UNILATERAL:
		case FUNDING_SPEND_SEEN:
		case ONCHAIND_MUTUAL:
		case CLOSINGD_COMPLETE:
			/* Channel is active! */
			abort();

		case CHANNELD_AWAITING_LOCKIN:
		case CHANNELD_NORMAL:
		case CHANNELD_SHUTTING_DOWN:
			/* Stop any existing daemon, without triggering error
			 * on this peer. */
			channel_set_owner(channel, NULL);

			channel->peer->addr = addr;
			peer_start_channeld(channel, &cs, gossip_index,
					    peer_fd, gossip_fd, NULL,
					    true);
			goto connected;

		case CLOSINGD_SIGEXCHANGE:
			/* Stop any existing daemon, without triggering error
			 * on this peer. */
			channel_set_owner(channel, NULL);

			channel->peer->addr = addr;
			peer_start_closingd(channel, &cs, gossip_index,
					    peer_fd, gossip_fd,
					    true);
			goto connected;
		}
		abort();
	}

return_to_gossipd:
	/* Otherwise, we hand back to gossipd, to continue. */
	msg = towire_gossipctl_hand_back_peer(msg, &id, &cs, gossip_index, NULL);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);

connected:
	/* If we were waiting for connection, we succeeded. */
	connect_succeeded(ld, &id);
	return;

send_error:
	/* Hand back to gossipd, with an error packet. */
	connect_failed(ld, &id, sanitize_error(msg, error, NULL));
	msg = towire_gossipctl_hand_back_peer(msg, &id, &cs, gossip_index,
					      error);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);
}

/* Gossipd tells us peer was already connected. */
void peer_already_connected(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;

	if (!fromwire_gossip_peer_already_connected(msg, NULL, &id))
		fatal("Gossip gave bad GOSSIP_PEER_ALREADY_CONNECTED message %s",
		      tal_hex(msg, msg));

	/* If we were waiting for connection, we succeeded. */
	connect_succeeded(ld, &id);
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
		if (structeq(&cid, channel_id))
			return channel;
	}
	return NULL;
}

/* We only get here IF we weren't trying to connect to it. */
void peer_sent_nongossip(struct lightningd *ld,
			 const struct pubkey *id,
			 const struct wireaddr *addr,
			 const struct crypto_state *cs,
			 u64 gossip_index,
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
		error = peer_accept_channel(ld, id, addr, cs, gossip_index,
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
	}

	/* Weird request. */
	error = towire_errorfmt(ld, channel_id,
				"Unexpected message %i for peer",
				fromwire_peektype(in_msg));

send_error:
	/* Hand back to gossipd, with an error packet. */
	connect_failed(ld, id, sanitize_error(error, error, NULL));
	msg = towire_gossipctl_hand_back_peer(ld, id, cs, gossip_index, error);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);
	tal_free(error);
}

/* We copy per-peer entries above --log-level into the main log. */
static void copy_to_parent_log(const char *prefix,
			       enum log_level level,
			       bool continued,
			       const struct timeabs *time,
			       const char *str,
			       const u8 *io,
			       struct log *parent_log)
{
	if (level == LOG_IO_IN || level == LOG_IO_OUT)
		log_io(parent_log, level, prefix, io, tal_len(io));
	else if (continued)
		log_add(parent_log, "%s ... %s", prefix, str);
	else
		log_(parent_log, level, "%s %s", prefix, str);
}

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (pubkey_eq(&p->id, id))
			return p;
	return NULL;
}

struct getpeers_args {
	struct command *cmd;
	/* If non-NULL, they want logs too */
	enum log_level *ll;
	/* If set, only report on a specific id. */
	struct pubkey *specific_id;
};

static void gossipd_getpeers_complete(struct subd *gossip, const u8 *msg,
				      const int *fds,
				      struct getpeers_args *gpa)
{
	/* This is a little sneaky... */
	struct pubkey *ids;
	struct wireaddr *addrs;
	struct json_result *response = new_json_result(gpa->cmd);
	struct peer *p;

	if (!fromwire_gossip_getpeers_reply(msg, msg, NULL, &ids, &addrs)) {
		command_fail(gpa->cmd, "Bad response from gossipd");
		return;
	}

	/* First the peers not just gossiping. */
	json_object_start(response, NULL);
	json_array_start(response, "peers");
	list_for_each(&gpa->cmd->ld->peers, p, list) {
		bool connected;
		struct channel *channel;

		if (gpa->specific_id && !pubkey_eq(gpa->specific_id, &p->id))
			continue;

		json_object_start(response, NULL);
		json_add_pubkey(response, "id", &p->id);
		channel = peer_active_channel(p);
		connected = (channel && channel->owner != NULL);
		json_add_bool(response, "connected", connected);

		if (connected) {
			json_array_start(response, "netaddr");
			if (p->addr.type != ADDR_TYPE_PADDING)
				json_add_string(response, NULL,
						type_to_string(response,
							       struct wireaddr,
							       &p->addr));
			json_array_end(response);
		}

		json_array_start(response, "channels");
		json_add_uncommitted_channel(response, p->uncommitted_channel);

		list_for_each(&p->channels, channel, list) {
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
			json_add_txid(response,
				      "funding_txid",
				      &channel->funding_txid);
			json_add_u64(response, "msatoshi_to_us",
				     channel->our_msatoshi);
			json_add_u64(response, "msatoshi_total",
				     channel->funding_satoshi * 1000);

			/* channel config */
			json_add_u64(response, "dust_limit_satoshis",
				     channel->our_config.dust_limit_satoshis);
			json_add_u64(response, "max_htlc_value_in_flight_msat",
				     channel->our_config.max_htlc_value_in_flight_msat);
			json_add_u64(response, "channel_reserve_satoshis",
				     channel->our_config.channel_reserve_satoshis);
			json_add_u64(response, "htlc_minimum_msat",
				     channel->our_config.htlc_minimum_msat);
			json_add_num(response, "to_self_delay",
				     channel->our_config.to_self_delay);
			json_add_num(response, "max_accepted_htlcs",
				     channel->our_config.max_accepted_htlcs);

			json_object_end(response);
		}
		json_array_end(response);

		if (gpa->ll)
			json_add_log(response, "log", p->log_book, *gpa->ll);
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
		json_array_start(response, "netaddr");
		if (addrs[i].type != ADDR_TYPE_PADDING)
			json_add_string(response, NULL,
					type_to_string(response, struct wireaddr,
						       addrs + i));
		json_array_end(response);
		json_add_bool(response, "connected", true);
		json_add_string(response, "owner", gossip->name);
		json_object_end(response);
	}

	json_array_end(response);
	json_object_end(response);
	command_success(gpa->cmd, response);
}

static void json_listpeers(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *leveltok;
	struct getpeers_args *gpa = tal(cmd, struct getpeers_args);
	jsmntok_t *idtok;

	gpa->cmd = cmd;
	gpa->specific_id = NULL;
	if (!json_get_params(cmd, buffer, params,
			     "?id", &idtok,
			     "?level", &leveltok,
			     NULL)) {
		return;
	}

	if (idtok) {
		gpa->specific_id = tal_arr(cmd, struct pubkey, 1);
		if (!json_tok_pubkey(buffer, idtok, gpa->specific_id)) {
			command_fail(cmd, "id %.*s not valid",
				     idtok->end - idtok->start,
				     buffer + idtok->start);
			return;
		}
	}
	if (leveltok) {
		gpa->ll = tal(gpa, enum log_level);
		if (!json_tok_loglevel(buffer, leveltok, gpa->ll)) {
			command_fail(cmd, "Invalid level param");
			return;
		}
	} else
		gpa->ll = NULL;

	/* Get peers from gossipd. */
	subd_req(cmd, cmd->ld->gossip,
		 take(towire_gossip_getpeers_request(cmd, gpa->specific_id)),
		 -1, 0, gossipd_getpeers_complete, gpa);
	command_still_pending(cmd);
}

static const struct json_command listpeers_command = {
	"listpeers",
	json_listpeers,
	"Show current peers, if {level} is set, include logs for {id}"
};
AUTODATA(json_command, &listpeers_command);

struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    jsmntok_t *peeridtok)
{
	struct pubkey peerid;

	if (!json_tok_pubkey(buffer, peeridtok, &peerid))
		return NULL;

	return peer_by_id(ld, &peerid);
}

static enum watch_result funding_announce_cb(struct channel *channel,
					     const struct bitcoin_tx *tx,
					     unsigned int depth,
					     void *unused)
{
	if (depth < ANNOUNCE_MIN_DEPTH) {
		return KEEP_WATCHING;
	}

	if (!channel->owner || !streq(channel->owner->name, "lightning_channeld")) {
		log_debug(channel->log,
			  "Funding tx announce ready, but channel state %s"
			  " owned by %s",
			  channel_state_name(channel),
			  channel->owner ? channel->owner->name : "none");
		return KEEP_WATCHING;
	}

	subd_send_msg(channel->owner,
		      take(towire_channel_funding_announce_depth(channel)));
	return DELETE_WATCH;
}

/* If channel is NULL, free them all (for shutdown) */
void free_htlcs(struct lightningd *ld, const struct channel *channel)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	bool deleted;

	/* FIXME: Implement check_htlcs to ensure no dangling hout->in ptrs! */

	do {
		deleted = false;
		for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
		     hout;
		     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
			if (channel && hout->key.channel != channel)
				continue;
			tal_free(hout);
			deleted = true;
		}

		for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
		     hin;
		     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
			if (channel && hin->key.channel != channel)
				continue;
			tal_free(hin);
			deleted = true;
		}
		/* Can skip over elements due to iterating while deleting. */
	} while (deleted);
}

u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx)
{
	struct pubkey shutdownkey;

	if (!bip32_pubkey(ld->wallet->bip32_base, &shutdownkey, keyidx))
		return NULL;

	return scriptpubkey_p2wpkh(ctx, &shutdownkey);
}

static enum watch_result funding_lockin_cb(struct channel *channel,
					   const struct bitcoin_tx *tx,
					   unsigned int depth,
					   void *unused)
{
	struct bitcoin_txid txid;
	const char *txidstr;
	struct txlocator *loc;
	bool channel_ready;
	struct lightningd *ld = channel->peer->ld;

	bitcoin_txid(tx, &txid);
	txidstr = type_to_string(channel, struct bitcoin_txid, &txid);
	log_debug(channel->log, "Funding tx %s depth %u of %u",
		  txidstr, depth, channel->minimum_depth);
	tal_free(txidstr);

	if (depth < channel->minimum_depth)
		return KEEP_WATCHING;

	loc = locate_tx(channel, ld->topology, &txid);

	/* If we restart, we could already have peer->scid from database */
	if (!channel->scid) {
		channel->scid = tal(channel, struct short_channel_id);
		channel->scid->blocknum = loc->blkheight;
		channel->scid->txnum = loc->index;
		channel->scid->outnum = channel->funding_outnum;
	}
	tal_free(loc);

	/* In theory, it could have been buried before we got back
	 * from accepting openingd or disconnected: just wait for next one. */
	channel_ready = (channel->owner && channel->state == CHANNELD_AWAITING_LOCKIN);
	if (!channel_ready) {
		log_debug(channel->log,
			  "Funding tx confirmed, but channel state %s %s",
			  channel_state_name(channel),
			  channel->owner ? channel->owner->name : "unowned");
	} else {
		subd_send_msg(channel->owner,
			      take(towire_channel_funding_locked(channel,
								 channel->scid)));
	}

	/* BOLT #7:
	 *
	 * If the `open_channel` message had the `announce_channel` bit set,
	 * then both nodes must send the `announcement_signatures` message,
	 * otherwise they MUST NOT.
	 */
	if (!(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
		return DELETE_WATCH;

	/* Tell channeld that we have reached the announce_depth and
	 * that it may send the announcement_signatures upon receiving
	 * funding_locked, or right now if it already received it
	 * before. If we are at the right depth, call the callback
	 * directly, otherwise schedule a callback */
	if (depth >= ANNOUNCE_MIN_DEPTH)
		funding_announce_cb(channel, tx, depth, NULL);
	else
		watch_txid(channel, ld->topology, channel, &txid,
			   funding_announce_cb, NULL);
	return DELETE_WATCH;
}

void channel_watch_funding(struct lightningd *ld, struct channel *channel)
{
	/* FIXME: Remove arg from cb? */
	watch_txid(channel, ld->topology, channel,
		   &channel->funding_txid, funding_lockin_cb, NULL);
	watch_txo(channel, ld->topology, channel,
		  &channel->funding_txid, channel->funding_outnum,
		  funding_spent, NULL);
}

/* We were informed by channeld that it announced the channel and sent
 * an update, so we can now start sending a node_announcement. The
 * first step is to build the provisional announcement and ask the HSM
 * to sign it. */

static void peer_got_funding_locked(struct channel *channel, const u8 *msg)
{
	struct pubkey next_per_commitment_point;

	if (!fromwire_channel_got_funding_locked(msg, NULL,
						 &next_per_commitment_point)) {
		channel_internal_error(channel,
				       "bad channel_got_funding_locked %s",
				       tal_hex(channel, msg));
		return;
	}

	if (channel->remote_funding_locked) {
		channel_internal_error(channel,
				       "channel_got_funding_locked twice");
		return;
	}
	update_per_commit_point(channel, &next_per_commitment_point);

	log_debug(channel->log, "Got funding_locked");
	channel->remote_funding_locked = true;
}

static void peer_got_shutdown(struct channel *channel, const u8 *msg)
{
	u8 *scriptpubkey;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_channel_got_shutdown(channel, msg, NULL, &scriptpubkey)) {
		channel_internal_error(channel, "bad channel_got_shutdown %s",
				       tal_hex(msg, msg));
		return;
	}

	/* FIXME: Add to spec that we must allow repeated shutdown! */
	tal_free(channel->remote_shutdown_scriptpubkey);
	channel->remote_shutdown_scriptpubkey = scriptpubkey;

	/* BOLT #2:
	 *
	 * A sending node MUST set `scriptpubkey` to one of the following forms:
	 *
	 * 1. `OP_DUP` `OP_HASH160` `20` 20-bytes `OP_EQUALVERIFY` `OP_CHECKSIG`
	 *   (pay to pubkey hash), OR
	 * 2. `OP_HASH160` `20` 20-bytes `OP_EQUAL` (pay to script hash), OR
	 * 3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey), OR
	 * 4. `OP_0` `32` 32-bytes (version 0 pay to witness script hash)
	 *
	 * A receiving node SHOULD fail the connection if the `scriptpubkey`
	 * is not one of those forms. */
	if (!is_p2pkh(scriptpubkey, NULL) && !is_p2sh(scriptpubkey, NULL)
	    && !is_p2wpkh(scriptpubkey, NULL) && !is_p2wsh(scriptpubkey, NULL)) {
		channel_fail_permanent(channel, "Bad shutdown scriptpubkey %s",
				       tal_hex(channel, scriptpubkey));
		return;
	}

	if (channel->local_shutdown_idx == -1) {
		u8 *scriptpubkey;

		channel->local_shutdown_idx = wallet_get_newindex(ld);
		if (channel->local_shutdown_idx == -1) {
			channel_internal_error(channel,
					    "Can't get local shutdown index");
			return;
		}

		channel_set_state(channel,
				  CHANNELD_NORMAL, CHANNELD_SHUTTING_DOWN);

		/* BOLT #2:
		 *
		 * A sending node MUST set `scriptpubkey` to one of the
		 * following forms:
		 *
		 * ...3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey),
		 */
		scriptpubkey = p2wpkh_for_keyidx(msg, ld,
						 channel->local_shutdown_idx);
		if (!scriptpubkey) {
			channel_internal_error(channel,
					    "Can't get shutdown script %"PRIu64,
					    channel->local_shutdown_idx);
			return;
		}

		txfilter_add_scriptpubkey(ld->owned_txfilter, scriptpubkey);

		/* BOLT #2:
		 *
		 * A receiving node MUST reply to a `shutdown` message with a
		 * `shutdown` once there are no outstanding updates on the
		 * peer, unless it has already sent a `shutdown`.
		 */
		subd_send_msg(channel->owner,
			      take(towire_channel_send_shutdown(channel,
								scriptpubkey)));
	}

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(ld->wallet, channel);
}

static void peer_start_closingd_after_shutdown(struct channel *channel,
					       const u8 *msg,
					       const int *fds)
{
	struct crypto_state cs;
	u64 gossip_index;

	/* We expect 2 fds. */
	assert(tal_count(fds) == 2);

	if (!fromwire_channel_shutdown_complete(msg, NULL, &cs, &gossip_index)) {
		channel_internal_error(channel, "bad shutdown_complete: %s",
				       tal_hex(msg, msg));
		return;
	}

	/* This sets channel->owner, closes down channeld. */
	peer_start_closingd(channel, &cs, gossip_index, fds[0], fds[1], false);
	channel_set_state(channel, CHANNELD_SHUTTING_DOWN, CLOSINGD_SIGEXCHANGE);
}

static unsigned channel_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_NORMAL_OPERATION:
		channel_set_state(sd->channel,
				  CHANNELD_AWAITING_LOCKIN, CHANNELD_NORMAL);
		break;
	case WIRE_CHANNEL_SENDING_COMMITSIG:
		peer_sending_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_COMMITSIG:
		peer_got_commitsig(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_REVOKE:
		peer_got_revoke(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_FUNDING_LOCKED:
		peer_got_funding_locked(sd->channel, msg);
		break;
	case WIRE_CHANNEL_GOT_SHUTDOWN:
		peer_got_shutdown(sd->channel, msg);
		break;
	case WIRE_CHANNEL_SHUTDOWN_COMPLETE:
		/* We expect 2 fds. */
		if (!fds)
			return 2;
		peer_start_closingd_after_shutdown(sd->channel, msg, fds);
		break;

	/* And we never get these from channeld. */
	case WIRE_CHANNEL_INIT:
	case WIRE_CHANNEL_FUNDING_LOCKED:
	case WIRE_CHANNEL_FUNDING_ANNOUNCE_DEPTH:
	case WIRE_CHANNEL_OFFER_HTLC:
	case WIRE_CHANNEL_FULFILL_HTLC:
	case WIRE_CHANNEL_FAIL_HTLC:
	case WIRE_CHANNEL_PING:
	case WIRE_CHANNEL_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_REVOKE_REPLY:
	case WIRE_CHANNEL_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNEL_SEND_SHUTDOWN:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT:
	case WIRE_CHANNEL_FEERATES:
	/* Replies go to requests. */
	case WIRE_CHANNEL_OFFER_HTLC_REPLY:
	case WIRE_CHANNEL_PING_REPLY:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT_REPLY:
		break;
	}

	return 0;
}

u32 feerate_min(struct lightningd *ld)
{
	if (ld->config.ignore_fee_limits)
		return 1;

	/* Set this to average of slow and normal.*/
	return (get_feerate(ld->topology, FEERATE_SLOW)
		+ get_feerate(ld->topology, FEERATE_NORMAL)) / 2;
}

/* BOLT #2:
 *
 * Given the variance in fees, and the fact that the transaction may
 * be spent in the future, it's a good idea for the fee payer to keep
 * a good margin, say 5x the expected fee requirement */
u32 feerate_max(struct lightningd *ld)
{
	if (ld->config.ignore_fee_limits)
		return UINT_MAX;

	return get_feerate(ld->topology, FEERATE_IMMEDIATE) * 5;
}

bool peer_start_channeld(struct channel *channel,
			 const struct crypto_state *cs,
			 u64 gossip_index,
			 int peer_fd, int gossip_fd,
			 const u8 *funding_signed,
			 bool reconnected)
{
	const tal_t *tmpctx = tal_tmpctx(channel);
	u8 *msg, *initmsg;
	int hsmfd;
	struct added_htlc *htlcs;
	enum htlc_state *htlc_states;
	struct fulfilled_htlc *fulfilled_htlcs;
	enum side *fulfilled_sides;
	const struct failed_htlc **failed_htlcs;
	enum side *failed_sides;
	struct short_channel_id funding_channel_id;
	const u8 *shutdown_scriptpubkey;
	u64 num_revocations;
	struct lightningd *ld = channel->peer->ld;
	const struct config *cfg = &ld->config;

	msg = towire_hsm_client_hsmfd(tmpctx, &channel->peer->id, HSM_CAP_SIGN_GOSSIP | HSM_CAP_ECDH);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsm_client_hsmfd_reply(msg, NULL))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	channel_set_owner(channel, new_channel_subd(ld,
					   "lightning_channeld", channel,
					   channel->log,
					   channel_wire_type_name,
					   channel_msg,
					   channel_errmsg,
					   take(&peer_fd),
					   take(&gossip_fd),
					   take(&hsmfd), NULL));

	if (!channel->owner) {
		log_unusual(channel->log, "Could not subdaemon channel: %s",
			    strerror(errno));
		channel_fail_transient(channel, "Failed to subdaemon channel");
		tal_free(tmpctx);
		return true;
	}

	peer_htlcs(tmpctx, channel, &htlcs, &htlc_states, &fulfilled_htlcs,
		   &fulfilled_sides, &failed_htlcs, &failed_sides);

	if (channel->scid) {
		funding_channel_id = *channel->scid;
		log_debug(channel->log, "Already have funding locked in");
	} else {
		log_debug(channel->log, "Waiting for funding confirmations");
		memset(&funding_channel_id, 0, sizeof(funding_channel_id));
	}

	if (channel->local_shutdown_idx != -1) {
		shutdown_scriptpubkey
			= p2wpkh_for_keyidx(tmpctx, ld,
					    channel->local_shutdown_idx);
	} else
		shutdown_scriptpubkey = NULL;

	num_revocations = revocations_received(&channel->their_shachain.chain);

	/* Warn once. */
	if (ld->config.ignore_fee_limits)
		log_debug(channel->log, "Ignoring fee limits!");

	initmsg = towire_channel_init(tmpctx,
				      &get_chainparams(ld)->genesis_blockhash,
				      &channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding_satoshi,
				      &channel->our_config,
				      &channel->channel_info.their_config,
				      channel->channel_info.feerate_per_kw,
				      feerate_min(ld),
				      feerate_max(ld),
				      &channel->last_sig,
				      cs, gossip_index,
				      &channel->channel_info.remote_fundingkey,
				      &channel->channel_info.theirbase.revocation,
				      &channel->channel_info.theirbase.payment,
				      &channel->channel_info.theirbase.htlc,
				      &channel->channel_info.theirbase.delayed_payment,
				      &channel->channel_info.remote_per_commit,
				      &channel->channel_info.old_remote_per_commit,
				      channel->funder,
				      cfg->fee_base,
				      cfg->fee_per_satoshi,
				      channel->our_msatoshi,
				      &channel->seed,
				      &ld->id,
				      &channel->peer->id,
				      time_to_msec(cfg->commit_time),
				      cfg->cltv_expiry_delta,
				      channel->last_was_revoke,
				      channel->last_sent_commit,
				      channel->next_index[LOCAL],
				      channel->next_index[REMOTE],
				      num_revocations,
				      channel->next_htlc_id,
				      htlcs, htlc_states,
				      fulfilled_htlcs, fulfilled_sides,
				      failed_htlcs, failed_sides,
				      channel->scid != NULL,
				      channel->remote_funding_locked,
				      &funding_channel_id,
				      reconnected,
				      shutdown_scriptpubkey,
				      channel->remote_shutdown_scriptpubkey != NULL,
				      channel->channel_flags,
				      funding_signed);

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(channel->owner, take(initmsg));

	tal_free(tmpctx);
	return true;
}

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *peertok;
	struct peer *peer;
	struct channel *channel;

	if (!json_get_params(cmd, buffer, params,
			     "id", &peertok,
			     NULL)) {
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		struct uncommitted_channel *uc = peer->uncommitted_channel;
		if (uc) {
			/* Easy case: peer can simply be forgotten. */
			kill_uncommitted_channel(uc, "close command called");

			command_success(cmd, null_response(cmd));
			return;
		}
		command_fail(cmd, "Peer has no active channel");
		return;
	}

	/* Normal case. */
	if (channel->state == CHANNELD_NORMAL) {
		u8 *shutdown_scriptpubkey;

		channel->local_shutdown_idx = wallet_get_newindex(cmd->ld);
		if (channel->local_shutdown_idx == -1) {
			command_fail(cmd, "Failed to get new key for shutdown");
			return;
		}
		shutdown_scriptpubkey = p2wpkh_for_keyidx(cmd, cmd->ld,
							  channel->local_shutdown_idx);
		if (!shutdown_scriptpubkey) {
			command_fail(cmd, "Failed to get script for shutdown");
			return;
		}

		channel_set_state(channel, CHANNELD_NORMAL, CHANNELD_SHUTTING_DOWN);

		txfilter_add_scriptpubkey(cmd->ld->owned_txfilter, shutdown_scriptpubkey);

		if (channel->owner)
			subd_send_msg(channel->owner,
				      take(towire_channel_send_shutdown(channel,
						   shutdown_scriptpubkey)));

		command_success(cmd, null_response(cmd));
	} else
		command_fail(cmd, "Peer is in state %s",
			     channel_state_name(channel));
}

static const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with peer {id}"
};
AUTODATA(json_command, &close_command);

static void activate_peer(struct peer *peer)
{
	u8 *msg;
	struct channel *channel;
	struct lightningd *ld = peer->ld;

	/* Pass gossipd any addrhints we currently have */
	msg = towire_gossipctl_peer_addrhint(peer, &peer->id, &peer->addr);
	subd_send_msg(peer->ld->gossip, take(msg));

	/* We can only have one active channel: reconnect if not already. */
	channel = peer_active_channel(peer);
	if (channel && !channel->owner) {
		msg = towire_gossipctl_reach_peer(peer, &peer->id);
		subd_send_msg(peer->ld->gossip, take(msg));
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

#if DEVELOPER
static void json_sign_last_tx(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *peertok;
	struct peer *peer;
	struct json_result *response = new_json_result(cmd);
	u8 *linear;
	struct channel *channel;

	if (!json_get_params(cmd, buffer, params,
			     "id", &peertok,
			     NULL)) {
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}
	channel = peer_active_channel(peer);
	if (!channel) {
		command_fail(cmd, "Could has not active channel");
		return;
	}

	log_debug(channel->log, "dev-sign-last-tx: signing tx with %zu outputs",
		  tal_count(channel->last_tx->output));
	sign_last_tx(channel);
	linear = linearize_tx(cmd, channel->last_tx);
	remove_sig(channel->last_tx);

	json_object_start(response, NULL);
	json_add_hex(response, "tx", linear, tal_len(linear));
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
	jsmntok_t *peertok;
	struct peer *peer;
	struct channel *channel;

	if (!json_get_params(cmd, buffer, params,
			     "id", &peertok,
			     NULL)) {
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		command_fail(cmd, "Could not find active channel with peer");
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

static void dev_reenable_commit_finished(struct subd *channeld,
					 const u8 *resp,
					 const int *fds,
					 struct command *cmd)
{
	command_success(cmd, null_response(cmd));
}

static void json_dev_reenable_commit(struct command *cmd,
				     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *peertok;
	struct peer *peer;
	u8 *msg;
	struct channel *channel;

	if (!json_get_params(cmd, buffer, params,
			     "id", &peertok,
			     NULL)) {
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	channel = peer_active_channel(peer);
	if (!channel) {
		command_fail(cmd, "Peer has no active channel");
		return;
	}
	if (!channel->owner) {
		command_fail(cmd, "Peer has no owner");
		return;
	}

	if (!streq(channel->owner->name, "lightning_channeld")) {
		command_fail(cmd, "Peer owned by %s", channel->owner->name);
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
		command_fail(forget->cmd,
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

	delete_channel(forget->channel, "dev-forget-channel called");

	command_success(forget->cmd, response);
}

static void json_dev_forget_channel(struct command *cmd, const char *buffer,
				    const jsmntok_t *params)
{
	jsmntok_t *nodeidtok, *forcetok, *scidtok;
	struct peer *peer;
	struct channel *channel;
	struct short_channel_id scid;
	struct dev_forget_channel_cmd *forget = tal(cmd, struct dev_forget_channel_cmd);
	forget->cmd = cmd;
	if (!json_get_params(cmd, buffer, params,
			     "id", &nodeidtok,
			     "?short_channel_id", &scidtok,
			     "?force", &forcetok,
			     NULL)) {
		return;
	}

	if (scidtok && !json_tok_short_channel_id(buffer, scidtok, &scid)) {
		command_fail(cmd, "Invalid short_channel_id '%.*s'",
			     scidtok->end - scidtok->start,
			     buffer + scidtok->start);
		return;
	}

	forget->force = false;
	if (forcetok)
		json_tok_bool(buffer, forcetok, &forget->force);

	peer = peer_from_json(cmd->ld, buffer, nodeidtok);
	if (!peer) {
		command_fail(cmd, "Could not find channel with that peer");
		return;
	}

	forget->channel = NULL;
	list_for_each(&peer->channels, channel, list) {
		if (scidtok) {
			if (!channel->scid)
				continue;
			if (!short_channel_id_eq(channel->scid, &scid))
				continue;
		}
		if (forget->channel) {
			command_fail(cmd,
				     "Multiple channels:"
				     " please specify short_channel_id");
			return;
		}
		forget->channel = channel;
	}
	if (!forget->channel) {
		command_fail(cmd,
			     "No channels matching that short_channel_id");
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
