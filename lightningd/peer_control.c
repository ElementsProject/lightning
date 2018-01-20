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
#include <closingd/gen_closing_wire.h>
#include <common/close_tx.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/funding_tx.h>
#include <common/initial_commit_tx.h>
#include <common/key_derive.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/build_utxos.h>
#include <lightningd/chaintopology.h>
#include <lightningd/gen_peer_state_names.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/netaddress.h>
#include <lightningd/options.h>
#include <lightningd/peer_htlcs.h>
#include <onchaind/gen_onchain_wire.h>
#include <onchaind/onchain_wire.h>
#include <openingd/gen_opening_wire.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/gen_onion_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

struct connect {
	struct list_node list;
	struct pubkey id;
	struct command *cmd;
};

/* FIXME: Reorder */
struct funding_channel;
static void peer_offer_channel(struct lightningd *ld,
			       struct funding_channel *fc,
			       const struct wireaddr *addr,
			       const struct crypto_state *cs,
			       u64 gossip_index,
			       const u8 *gfeatures, const u8 *lfeatures,
			       int peer_fd, int gossip_fd);
static bool peer_start_channeld(struct peer *peer,
				const struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				const u8 *funding_signed,
				bool reconnected);
static void peer_start_closingd(struct peer *peer,
				struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				bool reconnected);
static void peer_accept_channel(struct lightningd *ld,
				const struct pubkey *peer_id,
				const struct wireaddr *addr,
				const struct crypto_state *cs,
				u64 gossip_index,
				const u8 *gfeatures, const u8 *lfeatures,
				int peer_fd, int gossip_fd,
				const u8 *open_msg);

static void peer_set_owner(struct peer *peer, struct subd *owner)
{
	struct subd *old_owner = peer->owner;
	peer->owner = owner;

	if (old_owner)
		subd_release_peer(old_owner, peer);
}

static void destroy_peer(struct peer *peer)
{
	/* Must not have any HTLCs! */
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;

	for (hout = htlc_out_map_first(&peer->ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&peer->ld->htlcs_out, &outi)) {
		if (hout->key.peer != peer)
			continue;
		fatal("Freeing peer %s has hout %s",
		      peer_state_name(peer->state),
		      htlc_state_name(hout->hstate));
	}

	for (hin = htlc_in_map_first(&peer->ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&peer->ld->htlcs_in, &ini)) {
		if (hin->key.peer != peer)
			continue;
		fatal("Freeing peer %s has hin %s",
		      peer_state_name(peer->state),
		      htlc_state_name(hin->hstate));
	}

	/* Free any old owner still hanging around. */
	peer_set_owner(peer, NULL);
	list_del_from(&peer->ld->peers, &peer->list);
}

static void sign_last_tx(struct peer *peer)
{
	const tal_t *tmpctx = tal_tmpctx(peer);
	u8 *funding_wscript;
	struct pubkey local_funding_pubkey;
	struct secrets secrets;
	secp256k1_ecdsa_signature sig;

	assert(!peer->last_tx->input[0].witness);

	derive_basepoints(peer->seed, &local_funding_pubkey, NULL, &secrets,
			  NULL);

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
					      &local_funding_pubkey,
					      &peer->channel_info->remote_fundingkey);
	/* Need input amount for signing */
	peer->last_tx->input[0].amount = tal_dup(peer->last_tx->input, u64,
						 &peer->funding_satoshi);
	sign_tx_input(peer->last_tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      &sig);

	peer->last_tx->input[0].witness
		= bitcoin_witness_2of2(peer->last_tx->input,
				       peer->last_sig,
				       &sig,
				       &peer->channel_info->remote_fundingkey,
				       &local_funding_pubkey);

	tal_free(tmpctx);
}

static void remove_sig(struct bitcoin_tx *signed_tx)
{
	signed_tx->input[0].amount = tal_free(signed_tx->input[0].amount);
	signed_tx->input[0].witness = tal_free(signed_tx->input[0].witness);
}

static void drop_to_chain(struct peer *peer)
{
	sign_last_tx(peer);

	/* Keep broadcasting until we say stop (can fail due to dup,
	 * if they beat us to the broadcast). */
	broadcast_tx(peer->ld->topology, peer, peer->last_tx, NULL);
	remove_sig(peer->last_tx);
}

/* This lets us give a more detailed error than just a destructor. */
static void free_peer(struct peer *peer, const char *why)
{
	if (peer->opening_cmd) {
		command_fail(peer->opening_cmd, "%s", why);
		peer->opening_cmd = NULL;
	}
	tal_free(peer);
}

void peer_fail_permanent(struct peer *peer, const char *fmt, ...)
{
	va_list ap;
	char *why;

	va_start(ap, fmt);
	why = tal_vfmt(peer, fmt, ap);
	va_end(ap);

	log_unusual(peer->log, "Peer permanent failure in %s: %s",
		    peer_state_name(peer->state), why);

	/* We can have multiple errors, eg. onchaind failures. */
	if (!peer->error) {
		/* BOLT #1:
		 *
		 * The channel is referred to by `channel_id` unless `channel_id` is
		 * zero (ie. all bytes zero), in which case it refers to all
		 * channels. */
		static const struct channel_id all_channels;
		u8 *msg = tal_dup_arr(peer, u8, (const u8 *)why, strlen(why), 0);
		peer->error = towire_error(peer, &all_channels, msg);
		tal_free(msg);
	}

	peer_set_owner(peer, NULL);
	if (peer_persists(peer)) {
		drop_to_chain(peer);
		tal_free(why);
	} else
		free_peer(peer, why);
}

void peer_internal_error(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_broken(peer->log, "Peer internal error %s: ",
		   peer_state_name(peer->state));
	logv_add(peer->log, fmt, ap);
	va_end(ap);

	peer_fail_permanent(peer, "Internal error");
}

void peer_fail_transient(struct peer *peer, const char *fmt, ...)
{
	va_list ap;
	const char *why;

	va_start(ap, fmt);
	why = tal_vfmt(peer, fmt, ap);
	va_end(ap);
	log_info(peer->log, "Peer transient failure in %s: %s",
		 peer_state_name(peer->state), why);

#if DEVELOPER
	if (dev_disconnect_permanent(peer->ld)) {
		tal_free(why);
		peer_internal_error(peer, "dev_disconnect permfail");
		return;
	}
#endif

	peer_set_owner(peer, NULL);

	/* If we haven't reached awaiting locked, we don't need to reconnect */
	if (!peer_persists(peer)) {
		log_info(peer->log, "Only reached state %s: forgetting",
			 peer_state_name(peer->state));
		free_peer(peer, why);
		return;
	}
	tal_free(why);

	/* Reconnect unless we've dropped/are dropping to chain. */
	if (!peer_on_chain(peer) && peer->state != CLOSINGD_COMPLETE) {
		/* Don't schedule an attempt if we disabled reconnections with
		 * the `--no-reconnect` flag */
		if (peer->ld->config.no_reconnect)
			return;

		u8 *msg = towire_gossipctl_reach_peer(peer, &peer->id);
		subd_send_msg(peer->ld->gossip, take(msg));
	}
}

void peer_set_condition(struct peer *peer, enum peer_state old_state,
			enum peer_state state)
{
	log_info(peer->log, "state: %s -> %s",
		 peer_state_name(peer->state), peer_state_name(state));
	if (peer->state != old_state)
		fatal("peer state %s should be %s",
		      peer_state_name(peer->state), peer_state_name(old_state));

	peer->state = state;

	/* We only persist channels/peers that have reached the opening state */
	if (peer_persists(peer)) {
		assert(peer->channel != NULL);
		/* TODO(cdecker) Selectively save updated fields to DB */
		wallet_channel_save(peer->ld->wallet, peer->channel, 0);
	}
}

static void destroy_connect(struct connect *c)
{
	list_del(&c->list);
}

static struct connect *new_connect(struct lightningd *ld,
				   const struct pubkey *id,
				   struct command *cmd)
{
	struct connect *c = tal(cmd, struct connect);
	c->id = *id;
	c->cmd = cmd;
	list_add(&ld->connects, &c->list);
	tal_add_destructor(c, destroy_connect);
	return c;
}

static void connect_succeeded(struct lightningd *ld, const struct pubkey *id)
{
	struct connect *i, *next;

	/* Careful!  Completing command frees connect. */
	list_for_each_safe(&ld->connects, i, next, list) {
		struct json_result *response;

		if (!pubkey_eq(&i->id, id))
			continue;

		response = new_json_result(i->cmd);
		json_object_start(response, NULL);
		json_add_pubkey(response, "id", id);
		json_object_end(response);
		command_success(i->cmd, response);
	}
}

static void connect_failed(struct lightningd *ld, const struct pubkey *id,
			   const char *error)
{
	struct connect *i, *next;

	/* Careful!  Completing command frees connect. */
	list_for_each_safe(&ld->connects, i, next, list) {
		if (pubkey_eq(&i->id, id))
			command_fail(i->cmd, "%s", error);
	}
}

static struct peer *new_peer(struct lightningd *ld,
			     const struct pubkey *id,
			     const struct wireaddr *addr,
			     const u8 *gfeatures, const u8 *lfeatures,
			     int peer_fd)
{
	struct peer *peer;

	/* Need to memset since storing will access all fields */
	peer = talz(ld, struct peer);
	peer->error = NULL;
	peer->id = *id;
	peer->addr = *addr;
	peer->funding_txid = NULL;
	peer->remote_funding_locked = false;
	peer->scid = NULL;
	peer->seed = NULL;
	peer->our_msatoshi = NULL;
	peer->state = UNINITIALIZED;
	peer->opening_cmd = NULL;
	peer->channel_info = NULL;
	peer->last_tx = NULL;
	peer->last_sig = NULL;
	peer->last_htlc_sigs = NULL;
	peer->last_was_revoke = false;
	peer->last_sent_commit = NULL;
	peer->remote_shutdown_scriptpubkey = NULL;
	peer->local_shutdown_idx = -1;
	peer->next_index[LOCAL]
		= peer->next_index[REMOTE] = 0;
	peer->next_htlc_id = 0;
	wallet_shachain_init(ld->wallet, &peer->their_shachain);

	/* FIXME: db should be keyed by (peer_id, channel_id) */

	/* If we have the peer in the DB, this'll populate the fields,
	 * failure just indicates that the peer wasn't found in the
	 * DB */
	wallet_peer_by_nodeid(ld->wallet, id, peer);

	/* peer->channel gets populated as soon as we start opening a channel */
	peer->channel = NULL;

	list_add_tail(&ld->peers, &peer->list);
	populate_peer(ld, peer);

	return peer;
}

/**
 * peer_channel_new -- Instantiate a new channel for the given peer and save it
 *
 * We are about to open a channel with the peer, either due to a
 * nongossip message from remote, or because we initiated an
 * open. This creates the `struct wallet_channel` for the peer and
 * stores it in the database.
 *
 * @w: the wallet to store the information in
 * @peer: the peer we are opening a channel to
 *
 * This currently overwrites peer->channel, so can only be used if we
 * allow a single channel per peer.
 */
static struct wallet_channel *peer_channel_new(struct wallet *w,
					       struct peer *peer)
{
	struct wallet_channel *wc = tal(peer, struct wallet_channel);
	wc->peer = peer;

	wallet_peer_by_nodeid(w, &peer->id, peer);
	wc->id = 0;

	wallet_channel_save(w, wc, get_block_height(peer->ld->topology));

	return wc;
}

static void channel_config(struct lightningd *ld,
			   struct channel_config *ours,
			   u32 *max_to_self_delay,
			   u32 *max_minimum_depth,
			   u64 *min_effective_htlc_capacity_msat)
{
	/* FIXME: depend on feerate. */
	*max_to_self_delay = ld->config.locktime_max;
	*max_minimum_depth = ld->config.anchor_confirms_max;
	/* This is 1c at $1000/BTC */
	*min_effective_htlc_capacity_msat = 1000000;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `dust_limit_satoshis` to a sufficient
	 * value to allow commitment transactions to propagate through
	 * the Bitcoin network.
	 */
	ours->dust_limit_satoshis = 546;
	ours->max_htlc_value_in_flight_msat = UINT64_MAX;

	/* Don't care */
	ours->htlc_minimum_msat = 0;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `to_self_delay` sufficient to ensure
	 * the sender can irreversibly spend a commitment transaction
	 * output in case of misbehavior by the receiver.
	 */
	 ours->to_self_delay = ld->config.locktime_blocks;

	 /* BOLT #2:
	  *
	  * It MUST fail the channel if `max_accepted_htlcs` is greater than
	  * 483.
	  */
	 ours->max_accepted_htlcs = 483;

	 /* This is filled in by lightning_openingd, for consistency. */
	 ours->channel_reserve_satoshis = 0;
};

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
	struct peer *peer;
	struct wireaddr addr;
	u64 gossip_index;

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

	/* Now, do we already know this peer? */
	peer = peer_by_id(ld, &id);
	if (peer) {
		log_debug(peer->log, "Peer has reconnected, state %s",
			  peer_state_name(peer->state));

		/* FIXME: We can have errors for multiple channels. */
		if (peer->error) {
			error = peer->error;
			goto send_error;
		}

#if DEVELOPER
		if (dev_disconnect_permanent(ld)) {
			peer_internal_error(peer, "dev_disconnect permfail");
			error = peer->error;
			goto send_error;
	}
#endif

		switch (peer->state) {
			/* This can't happen. */
		case UNINITIALIZED:
			abort();

			/* Reconnect: discard old one. */
		case OPENINGD:
			free_peer(peer, "peer reconnected");
			peer = NULL;
			goto return_to_gossipd;

		case ONCHAIND_CHEATED:
		case ONCHAIND_THEIR_UNILATERAL:
		case ONCHAIND_OUR_UNILATERAL:
		case FUNDING_SPEND_SEEN:
		case ONCHAIND_MUTUAL:
			/* If they try to reestablish channel, we'll send
			 * error then */
			goto return_to_gossipd;

		case CHANNELD_AWAITING_LOCKIN:
		case CHANNELD_NORMAL:
		case CHANNELD_SHUTTING_DOWN:
			/* Stop any existing daemon, without triggering error
			 * on this peer. */
			peer_set_owner(peer, NULL);

			peer->addr = addr;
			peer_start_channeld(peer, &cs, gossip_index,
					    peer_fd, gossip_fd, NULL,
					    true);
			return;

		case CLOSINGD_SIGEXCHANGE:
		case CLOSINGD_COMPLETE:
			/* Stop any existing daemon, without triggering error
			 * on this peer. */
			peer_set_owner(peer, NULL);

			peer->addr = addr;
			peer_start_closingd(peer, &cs, gossip_index,
					    peer_fd, gossip_fd,
					    true);
			return;
		}
		abort();
	}

return_to_gossipd:
	/* Otherwise, we hand back to gossipd, to continue. */
	msg = towire_gossipctl_hand_back_peer(msg, &id, &cs, gossip_index, NULL);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);

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

	/* FIXME: match state too; we can have multiple onchain
	 * (ie. dead) channels for the same peer. */
	peer = peer_by_id(ld, id);
	if (peer) {
		error = towire_errorfmt(ld, channel_id,
					"Unexpected message %i in state %s",
					fromwire_peektype(in_msg),
					peer_state_name(peer->state));
		goto send_error;
	}

	/* Open request? */
	if (fromwire_peektype(in_msg) == WIRE_OPEN_CHANNEL) {
		peer_accept_channel(ld, id, addr, cs, gossip_index,
				    gfeatures, lfeatures,
				    peer_fd, gossip_fd, in_msg);
		return;
	}

	/* Weird request. */
	error = towire_errorfmt(ld, channel_id,
				"Unexpected message %i for unknown peer",
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
			       const char *str,
			       struct peer *peer)
{
	const char *idstr = type_to_string(peer, struct pubkey, &peer->id);
	if (continued)
		log_add(peer->ld->log, "peer %s: ... %s", idstr, str);
	else
		log_(peer->ld->log, level, "peer %s: %s", idstr, str);
	tal_free(idstr);
}

void populate_peer(struct lightningd *ld, struct peer *peer)
{
	const char *idname;
	struct pubkey *id = &peer->id;
	idname = type_to_string(peer, struct pubkey, id);

	peer->ld = ld;

	/* Max 128k per peer. */
	peer->log_book = new_log_book(peer, 128*1024,
				      get_log_level(ld->log_book));
	peer->log = new_log(peer, peer->log_book, "peer %s:", idname);
	set_log_outfn(peer->log_book, copy_to_parent_log, peer);
	tal_free(idname);
	tal_add_destructor(peer, destroy_peer);
}

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (pubkey_eq(&p->id, id))
			return p;
	return NULL;
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *hosttok, *porttok, *idtok;
	struct pubkey id;
	const char *name;
	struct wireaddr addr;
	u8 *msg;

	if (!json_get_params(buffer, params,
			     "id", &idtok,
			     "?host", &hosttok,
			     "?port", &porttok,
			     NULL)) {
		command_fail(cmd, "Need id to connect");
		return;
	}

	if (!json_tok_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	if (porttok && !hosttok) {
		command_fail(cmd, "Can't specify port without host");
		return;
	}

	if (hosttok) {
		name = tal_strndup(cmd, buffer + hosttok->start,
				   hosttok->end - hosttok->start);
		if (porttok) {
			u32 port;
			if (!json_tok_number(buffer, porttok, &port)) {
				command_fail(cmd, "port %.*s not valid",
					     porttok->end - porttok->start,
					     buffer + porttok->start);
				return;
			}
			addr.port = port;
		} else {
			addr.port = DEFAULT_PORT;
		}
		if (!parse_wireaddr(name, &addr, addr.port) || !addr.port) {
			command_fail(cmd, "host %s:%u not valid",
				     name, addr.port);
			return;
		}

		/* Tell it about the address. */
		msg = towire_gossipctl_peer_addrhint(cmd, &id, &addr);
		subd_send_msg(cmd->ld->gossip, take(msg));
	}

	/* Now tell it to try reaching it. */
	msg = towire_gossipctl_reach_peer(cmd, &id);
	subd_send_msg(cmd->ld->gossip, take(msg));

	/* Leave this here for gossip_peer_connected */
	new_connect(cmd->ld, &id, cmd);
	command_still_pending(cmd);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to {id} at {host} (which can end in ':port' if not default)",
	"Returns the {id} on success (once channel established)"
};
AUTODATA(json_command, &connect_command);

struct log_info {
	enum log_level level;
	struct json_result *response;
};

/* FIXME: Share this with jsonrpc.c's code! */
static void log_to_json(unsigned int skipped,
			struct timerel diff,
			enum log_level level,
			const char *prefix,
			const char *log,
			struct log_info *info)
{
	if (level < info->level)
		return;

	if (level != LOG_IO)
		json_add_string(info->response, NULL, log);
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

		if (gpa->specific_id && !pubkey_eq(gpa->specific_id, &p->id))
			continue;

		json_object_start(response, NULL);
		json_add_pubkey(response, "id", &p->id);
		connected = (p->owner != NULL && !peer_state_on_chain(p->state));
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

		/* FIXME: We only support one channel per peer, but API must
		 * support multiple already! */
		json_array_start(response, "channels");
		json_object_start(response, NULL);
		json_add_string(response, "state", peer_state_name(p->state));
		if (p->owner)
			json_add_string(response, "owner", p->owner->name);
		if (p->scid)
			json_add_short_channel_id(response,
						  "short_channel_id", p->scid);
		if (p->funding_txid)
			json_add_txid(response,
				      "funding_txid", p->funding_txid);
		if (p->our_msatoshi) {
			json_add_u64(response, "msatoshi_to_us",
				     *p->our_msatoshi);
			json_add_u64(response, "msatoshi_total",
				     p->funding_satoshi * 1000);
		}
		json_object_end(response);
		json_array_end(response);

		if (gpa->ll) {
			struct log_info info;
			info.level = *gpa->ll;
			info.response = response;
			json_array_start(response, "log");
			log_each_line(p->log_book, log_to_json, &info);
			json_array_end(response);
		}
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
	if (!json_get_params(buffer, params,
			     "?id", &idtok,
			     "?level", &leveltok,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
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
		if (json_tok_streq(buffer, leveltok, "debug"))
			*gpa->ll = LOG_DBG;
		else if (json_tok_streq(buffer, leveltok, "info"))
			*gpa->ll = LOG_INFORM;
		else if (json_tok_streq(buffer, leveltok, "unusual"))
			*gpa->ll = LOG_UNUSUAL;
		else if (json_tok_streq(buffer, leveltok, "broken"))
			*gpa->ll = LOG_BROKEN;
		else {
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
	"List the current peers, if {level} is set, include {log}s",
	"Returns a 'peers' array"
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

struct funding_channel {
	struct command *cmd; /* Which also owns us. */

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Details of how to make funding. */
	const struct utxo **utxomap;
	u64 change;
	u32 change_keyindex;
	u64 funding_satoshi, push_msat;

	/* Peer, once we have one. */
	struct peer *peer;
};

static void funding_broadcast_failed(struct peer *peer,
				     int exitstatus, const char *err)
{
	peer_internal_error(peer, "Funding broadcast exited with %i: %s",
			    exitstatus, err);
}

static enum watch_result funding_announce_cb(struct peer *peer,
					     const struct bitcoin_tx *tx,
					     unsigned int depth,
					     void *unused)
{
	if (depth < ANNOUNCE_MIN_DEPTH) {
		return KEEP_WATCHING;
	}

	if (!peer->owner || !streq(peer->owner->name, "lightning_channeld")) {
		log_debug(peer->ld->log,
			  "Funding tx announce ready, but peer is not owned by channeld");
		return KEEP_WATCHING;
	}

	subd_send_msg(peer->owner,
		      take(towire_channel_funding_announce_depth(peer)));
	return DELETE_WATCH;
}


/* We dump all the known preimages when onchaind starts up. */
static void onchaind_tell_fulfill(struct peer *peer)
{
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	u8 *msg;

	for (hin = htlc_in_map_first(&peer->ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&peer->ld->htlcs_in, &ini)) {
		if (hin->key.peer != peer)
			continue;

		/* BOLT #5:
		 *
		 * If the node receives (or already knows) a payment preimage
		 * for an unresolved HTLC output it was offered for which it
		 * has committed to an outgoing HTLC, it MUST *resolve* the
		 * output by spending it.  Otherwise, if the other node is not
		 * irrevocably committed to the HTLC, it MUST NOT *resolve*
		 * the output by spending it.
		 */

		/* We only set preimage once it's irrevocably committed, and
		 * we spend even if we don't have an outgoing HTLC (eg. local
		 * payment complete) */
		if (!hin->preimage)
			continue;

		msg = towire_onchain_known_preimage(peer, hin->preimage);
		subd_send_msg(peer->owner, take(msg));
	}
}

static void handle_onchain_init_reply(struct peer *peer, const u8 *msg)
{
	u8 state;

	if (!fromwire_onchain_init_reply(msg, NULL, &state)) {
		peer_internal_error(peer, "Invalid onchain_init_reply");
		return;
	}

	if (!peer_state_on_chain(state)) {
		peer_internal_error(peer,
				    "Invalid onchain_init_reply state %u (%s)",
				    state, peer_state_name(state));
		return;
	}

	peer_set_condition(peer, FUNDING_SPEND_SEEN, state);

	/* Tell it about any preimages we know. */
	onchaind_tell_fulfill(peer);
}

static enum watch_result onchain_tx_watched(struct peer *peer,
					    const struct bitcoin_tx *tx,
					    unsigned int depth,
					    void *unused)
{
	u8 *msg;
	struct bitcoin_txid txid;

	if (depth == 0) {
		log_unusual(peer->log, "Chain reorganization!");
		peer_set_owner(peer, NULL);

		/* FIXME!
		topology_rescan(peer->ld->topology, peer->funding_txid);
		*/

		/* We will most likely be freed, so this is a noop */
		return KEEP_WATCHING;
	}

	bitcoin_txid(tx, &txid);
	msg = towire_onchain_depth(peer, &txid, depth);
	subd_send_msg(peer->owner, take(msg));
	return KEEP_WATCHING;
}

static void watch_tx_and_outputs(struct peer *peer,
				 const struct bitcoin_tx *tx);

static enum watch_result onchain_txo_watched(struct peer *peer,
					     const struct bitcoin_tx *tx,
					     size_t input_num,
					     const struct block *block,
					     void *unused)
{
	u8 *msg;

	watch_tx_and_outputs(peer, tx);

	msg = towire_onchain_spent(peer, tx, input_num, block->height);
	subd_send_msg(peer->owner, take(msg));

	/* We don't need to keep watching: If this output is double-spent
	 * (reorg), we'll get a zero depth cb to onchain_tx_watched, and
	 * restart onchaind. */
	return DELETE_WATCH;
}

/* To avoid races, we watch the tx and all outputs. */
static void watch_tx_and_outputs(struct peer *peer,
				 const struct bitcoin_tx *tx)
{
	struct bitcoin_txid txid;
	struct txwatch *txw;

	bitcoin_txid(tx, &txid);

	/* Make txwatch a parent of txo watches, so we can unwatch together. */
	txw = watch_tx(peer->owner, peer->ld->topology, peer, tx,
		       onchain_tx_watched, NULL);

	for (size_t i = 0; i < tal_count(tx->output); i++)
		watch_txo(txw, peer->ld->topology, peer, &txid, i,
			  onchain_txo_watched, NULL);
}

static void handle_onchain_broadcast_tx(struct peer *peer, const u8 *msg)
{
	struct bitcoin_tx *tx;

	tx = tal(msg, struct bitcoin_tx);
	if (!fromwire_onchain_broadcast_tx(msg, NULL, tx)) {
		peer_internal_error(peer, "Invalid onchain_broadcast_tx");
		return;
	}

	/* We don't really care if it fails, we'll respond via watch. */
	broadcast_tx(peer->ld->topology, peer, tx, NULL);
}

static void handle_onchain_unwatch_tx(struct peer *peer, const u8 *msg)
{
	/* FIXME: unwatch tx and children here. */
}

static void handle_extracted_preimage(struct peer *peer, const u8 *msg)
{
	struct preimage preimage;

	if (!fromwire_onchain_extracted_preimage(msg, NULL, &preimage)) {
		peer_internal_error(peer, "Invalid extracted_preimage");
		return;
	}

	onchain_fulfilled_htlc(peer, &preimage);
}

static void handle_missing_htlc_output(struct peer *peer, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchain_missing_htlc_output(msg, NULL, &htlc)) {
		peer_internal_error(peer, "Invalid missing_htlc_output");
		return;
	}

	/* BOLT #5:
	 *
	 * For any committed HTLC which does not have an output in this
	 * commitment transaction, the node MUST fail the corresponding
	 * incoming HTLC (if any) once the commitment transaction has reached
	 * reasonable depth, and MAY fail it sooner if no valid commitment
	 * transaction contains an output corresponding to the HTLC.
	 */
	onchain_failed_our_htlc(peer, &htlc, "missing in commitment tx");
}

static void handle_onchain_htlc_timeout(struct peer *peer, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchain_htlc_timeout(msg, NULL, &htlc)) {
		peer_internal_error(peer, "Invalid onchain_htlc_timeout");
		return;
	}

	/* BOLT #5:
	 *
	 * If the HTLC output has *timed out* and not been *resolved*, the node
	 * MUST *resolve* the output and MUST fail the corresponding incoming
	 * HTLC (if any) once the resolving transaction has reached reasonable
	 * depth.
	 */
	onchain_failed_our_htlc(peer, &htlc, "timed out");
}

/* If peer is NULL, free them all (for shutdown) */
void free_htlcs(struct lightningd *ld, const struct peer *peer)
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
			if (peer && hout->key.peer != peer)
				continue;
			tal_free(hout);
			deleted = true;
		}

		for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
		     hin;
		     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
			if (peer && hin->key.peer != peer)
				continue;
			tal_free(hin);
			deleted = true;
		}
		/* Can skip over elements due to iterating while deleting. */
	} while (deleted);
}

static void handle_irrevocably_resolved(struct peer *peer, const u8 *msg)
{
	/* FIXME: Implement check_htlcs to ensure no dangling hout->in ptrs! */
	free_htlcs(peer->ld, peer);

	/* FIXME: Remove peer from db. */
	log_info(peer->log, "onchaind complete, forgetting peer");

	/* This will also free onchaind. */
	free_peer(peer, "onchaind complete, forgetting peer");
}

/**
 * onchain_add_utxo -- onchaind is telling us about a UTXO we own
 */
static void onchain_add_utxo(struct peer *peer, const u8 *msg)
{
	struct utxo *u = tal(msg, struct utxo);
	u->close_info = tal(u, struct unilateral_close_info);

	u->is_p2sh = true;
	u->keyindex = 0;
	u->status = output_state_available;
	u->close_info->channel_id = peer->channel->id;
	u->close_info->peer_id = peer->id;

	if (!fromwire_onchain_add_utxo(msg, NULL, &u->txid, &u->outnum,
				       &u->close_info->commitment_point,
				       &u->amount)) {
		fatal("onchaind gave invalid add_utxo message: %s", tal_hex(msg, msg));
	}


	wallet_add_utxo(peer->ld->wallet, u, p2wpkh);
}

static unsigned int onchain_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum onchain_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ONCHAIN_INIT_REPLY:
		handle_onchain_init_reply(sd->peer, msg);
		break;

	case WIRE_ONCHAIN_BROADCAST_TX:
		handle_onchain_broadcast_tx(sd->peer, msg);
		break;

	case WIRE_ONCHAIN_UNWATCH_TX:
		handle_onchain_unwatch_tx(sd->peer, msg);
		break;

 	case WIRE_ONCHAIN_EXTRACTED_PREIMAGE:
		handle_extracted_preimage(sd->peer, msg);
		break;

	case WIRE_ONCHAIN_MISSING_HTLC_OUTPUT:
		handle_missing_htlc_output(sd->peer, msg);
		break;

	case WIRE_ONCHAIN_HTLC_TIMEOUT:
		handle_onchain_htlc_timeout(sd->peer, msg);
		break;

	case WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED:
		handle_irrevocably_resolved(sd->peer, msg);
		break;

	case WIRE_ONCHAIN_ADD_UTXO:
		onchain_add_utxo(sd->peer, msg);
		break;

	/* We send these, not receive them */
	case WIRE_ONCHAIN_INIT:
	case WIRE_ONCHAIN_SPENT:
	case WIRE_ONCHAIN_DEPTH:
	case WIRE_ONCHAIN_HTLC:
	case WIRE_ONCHAIN_KNOWN_PREIMAGE:
		break;
	}

	return 0;
}

static u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx)
{
	struct pubkey shutdownkey;

	if (!bip32_pubkey(ld->wallet->bip32_base, &shutdownkey, keyidx))
		return NULL;

	return scriptpubkey_p2wpkh(ctx, &shutdownkey);
}

/* If we want to know if this HTLC is missing, return depth. */
static bool tell_if_missing(const struct peer *peer, struct htlc_stub *stub,
			    bool *tell_immediate)
{
	struct htlc_out *hout;

	/* Keep valgrind happy. */
	*tell_immediate = false;

	/* Is it a current HTLC? */
	hout = find_htlc_out_by_ripemd(peer, &stub->ripemd);
	if (!hout)
		return false;

	/* BOLT #5:
	 *
	 * For any committed HTLC which does not have an output in this
	 * commitment transaction, the node MUST fail the corresponding
	 * incoming HTLC (if any) once the commitment transaction has reached
	 * reasonable depth, and MAY fail it sooner if no valid commitment
	 * transaction contains an output corresponding to the HTLC.
	 */
	if (hout->hstate >= RCVD_ADD_REVOCATION
	    && hout->hstate < SENT_REMOVE_REVOCATION)
		*tell_immediate = true;

	log_debug(peer->log, "We want to know if htlc %"PRIu64" is missing (%s)",
		  hout->key.id, *tell_immediate ? "immediate" : "later");
	return true;
}

/* With a reorg, this can get called multiple times; each time we'll kill
 * onchaind (like any other owner), and restart */
static enum watch_result funding_spent(struct peer *peer,
				       const struct bitcoin_tx *tx,
				       size_t input_num,
				       const struct block *block,
				       void *unused)
{
	u8 *msg, *scriptpubkey;
	struct bitcoin_txid our_last_txid;
	s64 keyindex;
	struct pubkey ourkey;
	struct htlc_stub *stubs;
	const tal_t *tmpctx = tal_tmpctx(peer);

	peer_fail_permanent(peer, "Funding transaction spent");

	/* We could come from almost any state. */
	peer_set_condition(peer, peer->state, FUNDING_SPEND_SEEN);

	peer_set_owner(peer, new_peer_subd(peer->ld,
					   "lightning_onchaind", peer,
					   onchain_wire_type_name,
					   onchain_msg,
					   NULL));

	if (!peer->owner) {
		log_broken(peer->log, "Could not subdaemon onchain: %s",
			   strerror(errno));
		tal_free(tmpctx);
		return KEEP_WATCHING;
	}

	stubs = wallet_htlc_stubs(tmpctx, peer->ld->wallet, peer->channel);
	if (!stubs) {
		log_broken(peer->log, "Could not load htlc_stubs");
		tal_free(tmpctx);
		return KEEP_WATCHING;
	}

	/* We re-use this key to send other outputs to. */
	if (peer->local_shutdown_idx >= 0)
		keyindex = peer->local_shutdown_idx;
	else {
		keyindex = wallet_get_newindex(peer->ld);
		if (keyindex < 0) {
			log_broken(peer->log, "Could not get keyindex");
			tal_free(tmpctx);
			return KEEP_WATCHING;
		}
	}
	scriptpubkey = p2wpkh_for_keyidx(tmpctx, peer->ld, keyindex);
	if (!scriptpubkey) {
		peer_internal_error(peer,
				    "Can't get shutdown script %"PRIu64,
				    keyindex);
		tal_free(tmpctx);
		return DELETE_WATCH;
	}
	txfilter_add_scriptpubkey(peer->ld->owned_txfilter, scriptpubkey);

	if (!bip32_pubkey(peer->ld->wallet->bip32_base, &ourkey, keyindex)) {
		peer_internal_error(peer,
				    "Can't get shutdown key %"PRIu64,
				    keyindex);
		tal_free(tmpctx);
		return DELETE_WATCH;
	}

	/* This could be a mutual close, but it doesn't matter. */
	bitcoin_txid(peer->last_tx, &our_last_txid);

	msg = towire_onchain_init(peer, peer->seed, &peer->their_shachain.chain,
				  peer->funding_satoshi,
				  &peer->channel_info->old_remote_per_commit,
				  &peer->channel_info->remote_per_commit,
				   /* BOLT #2:
				    * `to_self_delay` is the number of blocks
				    * that the other nodes to-self outputs
				    * must be delayed */
				   /* So, these are reversed: they specify ours,
				    * we specify theirs. */
				  peer->channel_info->their_config.to_self_delay,
				  peer->our_config.to_self_delay,
				  get_feerate(peer->ld->topology,
					      FEERATE_NORMAL),
				  peer->our_config.dust_limit_satoshis,
				  &peer->channel_info->theirbase.revocation,
				  &our_last_txid,
				  scriptpubkey,
				  peer->remote_shutdown_scriptpubkey,
				  &ourkey,
				  peer->funder,
				  &peer->channel_info->theirbase.payment,
				  &peer->channel_info->theirbase.htlc,
				  &peer->channel_info->theirbase.delayed_payment,
				  tx,
				  block->height,
				  /* FIXME: config for 'reasonable depth' */
				  3,
				  peer->last_htlc_sigs,
				  tal_count(stubs));
	subd_send_msg(peer->owner, take(msg));

	/* FIXME: Don't queue all at once, use an empty cb... */
	for (size_t i = 0; i < tal_count(stubs); i++) {
		bool tell_immediate;
		bool tell = tell_if_missing(peer, &stubs[i], &tell_immediate);
		msg = towire_onchain_htlc(peer, &stubs[i],
					  tell, tell_immediate);
		subd_send_msg(peer->owner, take(msg));
	}

	watch_tx_and_outputs(peer, tx);

	tal_free(tmpctx);
	/* We keep watching until peer finally deleted, for reorgs. */
	return KEEP_WATCHING;
}

static enum watch_result funding_lockin_cb(struct peer *peer,
					   const struct bitcoin_tx *tx,
					   unsigned int depth,
					   void *unused)
{
	struct bitcoin_txid txid;
	const char *txidstr;
	struct txlocator *loc;
	bool peer_ready;

	bitcoin_txid(tx, &txid);
	txidstr = type_to_string(peer, struct bitcoin_txid, &txid);
	log_debug(peer->log, "Funding tx %s depth %u of %u",
		  txidstr, depth, peer->minimum_depth);
	tal_free(txidstr);

	if (depth < peer->minimum_depth)
		return KEEP_WATCHING;

	loc = locate_tx(peer, peer->ld->topology, &txid);

	/* If we restart, we could already have peer->scid from database */
	if (!peer->scid) {
		peer->scid = tal(peer, struct short_channel_id);
		peer->scid->blocknum = loc->blkheight;
		peer->scid->txnum = loc->index;
		peer->scid->outnum = peer->funding_outnum;
	}
	tal_free(loc);

	/* In theory, it could have been buried before we got back
	 * from accepting openingd or disconnected: just wait for next one. */
	peer_ready = (peer->owner && peer->state == CHANNELD_AWAITING_LOCKIN);
	if (!peer_ready) {
		log_unusual(peer->log,
			    "Funding tx confirmed, but peer state %s %s",
			    peer_state_name(peer->state),
			    peer->owner ? peer->owner->name : "unowned");
	} else {
		subd_send_msg(peer->owner,
			      take(towire_channel_funding_locked(peer,
								 peer->scid)));
	}

	/* BOLT #7:
	 *
	 * If the `open_channel` message had the `announce_channel` bit set,
	 * then both nodes must send the `announcement_signatures` message,
	 * otherwise they MUST NOT.
	 */
	if (!(peer->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
		return DELETE_WATCH;

	/* Tell channeld that we have reached the announce_depth and
	 * that it may send the announcement_signatures upon receiving
	 * funding_locked, or right now if it already received it
	 * before. If we are at the right depth, call the callback
	 * directly, otherwise schedule a callback */
	if (depth >= ANNOUNCE_MIN_DEPTH)
		funding_announce_cb(peer, tx, depth, NULL);
	else
		watch_txid(peer, peer->ld->topology, peer, &txid,
			   funding_announce_cb, NULL);
	return DELETE_WATCH;
}

static void opening_got_hsm_funding_sig(struct funding_channel *fc,
					int peer_fd, int gossip_fd,
					const u8 *resp,
					const struct crypto_state *cs,
					u64 gossip_index)
{
	struct bitcoin_tx *tx = tal(fc, struct bitcoin_tx);
	u8 *linear;
	u64 change_satoshi;
	struct json_result *response = new_json_result(fc->cmd);

	if (!fromwire_hsm_sign_funding_reply(resp, NULL, tx))
		fatal("HSM gave bad sign_funding_reply %s",
		      tal_hex(fc, resp));

	/* Send it out and watch for confirms. */
	broadcast_tx(fc->peer->ld->topology, fc->peer, tx, funding_broadcast_failed);
	watch_tx(fc->peer, fc->peer->ld->topology, fc->peer, tx,
		 funding_lockin_cb, NULL);

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(fc->peer->ld->wallet, tx, &change_satoshi);

	/* FIXME: Remove arg from cb? */
	watch_txo(fc->peer, fc->peer->ld->topology, fc->peer,
		  fc->peer->funding_txid, fc->peer->funding_outnum,
		  funding_spent, NULL);

	json_object_start(response, NULL);
	linear = linearize_tx(response, tx);
	json_add_hex(response, "tx", linear, tal_len(linear));
	json_add_txid(response, "txid", fc->peer->funding_txid);
	json_object_end(response);
	command_success(fc->peer->opening_cmd, response);
	fc->peer->opening_cmd = NULL;

	/* Start normal channel daemon. */
	peer_start_channeld(fc->peer, cs, gossip_index,
			    peer_fd, gossip_fd, NULL, false);
	peer_set_condition(fc->peer, OPENINGD, CHANNELD_AWAITING_LOCKIN);

	wallet_confirm_utxos(fc->peer->ld->wallet, fc->utxomap);
	tal_free(fc);
}

/* We were informed by channeld that it announced the channel and sent
 * an update, so we can now start sending a node_announcement. The
 * first step is to build the provisional announcement and ask the HSM
 * to sign it. */

static void peer_got_funding_locked(struct peer *peer, const u8 *msg)
{
	struct pubkey next_per_commitment_point;

	if (!fromwire_channel_got_funding_locked(msg, NULL,
						 &next_per_commitment_point)) {
		peer_internal_error(peer, "bad channel_got_funding_locked %s",
				    tal_hex(peer, msg));
		return;
	}

	if (peer->remote_funding_locked) {
		peer_internal_error(peer, "channel_got_funding_locked twice");
		return;
	}
	update_per_commit_point(peer, &next_per_commitment_point);

	log_debug(peer->log, "Got funding_locked");
	peer->remote_funding_locked = true;
}

static void peer_got_shutdown(struct peer *peer, const u8 *msg)
{
	u8 *scriptpubkey;

	if (!fromwire_channel_got_shutdown(peer, msg, NULL, &scriptpubkey)) {
		peer_internal_error(peer, "bad channel_got_shutdown %s",
				    tal_hex(peer, msg));
		return;
	}

	/* FIXME: Add to spec that we must allow repeated shutdown! */
	tal_free(peer->remote_shutdown_scriptpubkey);
	peer->remote_shutdown_scriptpubkey = scriptpubkey;

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
		peer_fail_permanent(peer, "Bad shutdown scriptpubkey %s",
				    tal_hex(peer, scriptpubkey));
		return;
	}

	if (peer->local_shutdown_idx == -1) {
		u8 *scriptpubkey;

		peer->local_shutdown_idx = wallet_get_newindex(peer->ld);
		if (peer->local_shutdown_idx == -1) {
			peer_internal_error(peer,
					    "Can't get local shutdown index");
			return;
		}

		peer_set_condition(peer, CHANNELD_NORMAL, CHANNELD_SHUTTING_DOWN);

		/* BOLT #2:
		 *
		 * A sending node MUST set `scriptpubkey` to one of the
		 * following forms:
		 *
		 * ...3. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey),
		 */
		scriptpubkey = p2wpkh_for_keyidx(msg, peer->ld,
						 peer->local_shutdown_idx);
		if (!scriptpubkey) {
			peer_internal_error(peer,
					    "Can't get shutdown script %"PRIu64,
					    peer->local_shutdown_idx);
			return;
		}

		txfilter_add_scriptpubkey(peer->ld->owned_txfilter, scriptpubkey);

		/* BOLT #2:
		 *
		 * A receiving node MUST reply to a `shutdown` message with a
		 * `shutdown` once there are no outstanding updates on the
		 * peer, unless it has already sent a `shutdown`.
		 */
		subd_send_msg(peer->owner,
			      take(towire_channel_send_shutdown(peer,
								scriptpubkey)));
	}

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(peer->ld->wallet, peer->channel, 0);
}

void peer_last_tx(struct peer *peer, struct bitcoin_tx *tx,
		  const secp256k1_ecdsa_signature *sig)
{
	tal_free(peer->last_sig);
	peer->last_sig = tal_dup(peer, secp256k1_ecdsa_signature, sig);
	tal_free(peer->last_tx);
	peer->last_tx = tal_steal(peer, tx);
}

/* Is this better than the last tx we were holding? */
static bool better_closing_fee(struct peer *peer, const struct bitcoin_tx *tx)
{
	u64 weight, fee, last_fee, ideal_fee, min_fee;
	s64 old_diff, new_diff;
	size_t i;

	/* Calculate actual fee. */
	fee = peer->funding_satoshi;
	for (i = 0; i < tal_count(tx->output); i++)
		fee -= tx->output[i].amount;

	last_fee = peer->funding_satoshi;
	for (i = 0; i < tal_count(peer->last_tx); i++)
		last_fee -= peer->last_tx->output[i].amount;

	/* Weight once we add in sigs. */
	weight = measure_tx_cost(tx) + 74 * 2;

	min_fee = get_feerate(peer->ld->topology, FEERATE_SLOW) * weight / 1000;
	if (fee < min_fee)
		return false;

	ideal_fee = get_feerate(peer->ld->topology, FEERATE_NORMAL) * weight / 1000;

	/* We prefer fee which is closest to our ideal. */
	old_diff = imaxabs((s64)ideal_fee - (s64)last_fee);
	new_diff = imaxabs((s64)ideal_fee - (s64)fee);

	return (new_diff < old_diff);
}

static void peer_received_closing_signature(struct peer *peer, const u8 *msg)
{
	secp256k1_ecdsa_signature sig;
	struct bitcoin_tx *tx = tal(msg, struct bitcoin_tx);

	if (!fromwire_closing_received_signature(msg, NULL, &sig, tx)) {
		peer_internal_error(peer, "Bad closing_received_signature %s",
				    tal_hex(peer, msg));
		return;
	}

	/* FIXME: Make sure signature is correct! */
	if (better_closing_fee(peer, tx)) {
		peer_last_tx(peer, tx, &sig);
		/* TODO(cdecker) Selectively save updated fields to DB */
		wallet_channel_save(peer->ld->wallet, peer->channel, 0);
	}

	/* OK, you can continue now. */
	subd_send_msg(peer->owner,
		      take(towire_closing_received_signature_reply(peer)));
}

static void peer_closing_complete(struct peer *peer, const u8 *msg)
{
	/* FIXME: We should save this, to return to gossipd */
	u64 gossip_index;

	if (!fromwire_closing_complete(msg, NULL, &gossip_index)) {
		peer_internal_error(peer, "Bad closing_complete %s",
				    tal_hex(peer, msg));
		return;
	}

	/* Retransmission only, ignore closing. */
	if (peer->state == CLOSINGD_COMPLETE)
		return;

	drop_to_chain(peer);
	peer_set_condition(peer, CLOSINGD_SIGEXCHANGE, CLOSINGD_COMPLETE);
}

static unsigned closing_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum closing_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CLOSING_RECEIVED_SIGNATURE:
		peer_received_closing_signature(sd->peer, msg);
		break;

	case WIRE_CLOSING_COMPLETE:
		peer_closing_complete(sd->peer, msg);
		break;

	/* We send these, not receive them */
	case WIRE_CLOSING_INIT:
	case WIRE_CLOSING_RECEIVED_SIGNATURE_REPLY:
		break;
	}

	return 0;
}

static void peer_start_closingd(struct peer *peer,
				struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				bool reconnected)
{
	const tal_t *tmpctx = tal_tmpctx(peer);
	u8 *initmsg, *local_scriptpubkey;
	u64 minfee, maxfee, startfee, feelimit;
	u64 num_revocations;

	if (peer->local_shutdown_idx == -1
	    || !peer->remote_shutdown_scriptpubkey) {
		peer_internal_error(peer,
				    "Can't start closing: local %s remote %s",
				    peer->local_shutdown_idx == -1
				    ? "not shutdown" : "shutdown",
				    peer->remote_shutdown_scriptpubkey
				    ? "shutdown" : "not shutdown");
		tal_free(tmpctx);
		return;
	}

	peer_set_owner(peer, new_peer_subd(peer->ld,
					   "lightning_closingd", peer,
					   closing_wire_type_name, closing_msg,
					   take(&peer_fd), take(&gossip_fd),
					   NULL));
	if (!peer->owner) {
		log_unusual(peer->log, "Could not subdaemon closing: %s",
			    strerror(errno));
		peer_fail_transient(peer, "Failed to subdaemon closing");
		tal_free(tmpctx);
		return;
	}

	local_scriptpubkey = p2wpkh_for_keyidx(tmpctx, peer->ld,
					       peer->local_shutdown_idx);
	if (!local_scriptpubkey) {
		peer_internal_error(peer,
				    "Can't generate local shutdown scriptpubkey");
		tal_free(tmpctx);
		return;
	}

	/* BOLT #2:
	 *
	 * A sending node MUST set `fee_satoshis` lower than or equal
	 * to the base fee of the final commitment transaction as
	 * calculated in [BOLT
	 * #3](03-transactions.md#fee-calculation).
	 */
	feelimit = commit_tx_base_fee(peer->channel_info->feerate_per_kw[LOCAL],
				      0);

	maxfee = commit_tx_base_fee(get_feerate(peer->ld->topology,
						FEERATE_IMMEDIATE), 0);
	minfee = commit_tx_base_fee(get_feerate(peer->ld->topology,
						FEERATE_SLOW), 0);
	startfee = commit_tx_base_fee(get_feerate(peer->ld->topology,
						  FEERATE_NORMAL), 0);

	if (maxfee > feelimit)
		maxfee = feelimit;
	if (startfee > feelimit)
		startfee = feelimit;
	if (minfee > feelimit)
		minfee = feelimit;

	num_revocations
		= revocations_received(&peer->their_shachain.chain);

	/* BOLT #3:
	 *
	 * The amounts for each output MUST BE rounded down to whole satoshis.
	 */
	initmsg = towire_closing_init(tmpctx,
				      cs,
				      gossip_index,
				      peer->seed,
				      peer->funding_txid,
				      peer->funding_outnum,
				      peer->funding_satoshi,
				      &peer->channel_info->remote_fundingkey,
				      peer->funder,
				      *peer->our_msatoshi / 1000,
				      peer->funding_satoshi
				      - *peer->our_msatoshi / 1000,
				      peer->our_config.dust_limit_satoshis,
				      minfee, maxfee, startfee,
				      local_scriptpubkey,
				      peer->remote_shutdown_scriptpubkey,
				      reconnected,
				      peer->next_index[LOCAL],
				      peer->next_index[REMOTE],
				      num_revocations);

	/* We don't expect a response: it will give us feedback on
	 * signatures sent and received, then closing_complete. */
	subd_send_msg(peer->owner, take(initmsg));
	tal_free(tmpctx);
}

static void peer_start_closingd_after_shutdown(struct peer *peer, const u8 *msg,
					       const int *fds)
{
	struct crypto_state cs;
	u64 gossip_index;

	/* We expect 2 fds. */
	assert(tal_count(fds) == 2);

	if (!fromwire_channel_shutdown_complete(msg, NULL, &cs, &gossip_index)) {
		peer_internal_error(peer, "bad shutdown_complete: %s",
				    tal_hex(peer, msg));
		return;
	}

	/* This sets peer->owner, closes down channeld. */
	peer_start_closingd(peer, &cs, gossip_index, fds[0], fds[1], false);
	peer_set_condition(peer, CHANNELD_SHUTTING_DOWN, CLOSINGD_SIGEXCHANGE);
}

static unsigned channel_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_NORMAL_OPERATION:
		peer_set_condition(sd->peer,
				   CHANNELD_AWAITING_LOCKIN, CHANNELD_NORMAL);
		break;
	case WIRE_CHANNEL_SENDING_COMMITSIG:
		peer_sending_commitsig(sd->peer, msg);
		break;
	case WIRE_CHANNEL_GOT_COMMITSIG:
		peer_got_commitsig(sd->peer, msg);
		break;
	case WIRE_CHANNEL_GOT_REVOKE:
		peer_got_revoke(sd->peer, msg);
		break;
	case WIRE_CHANNEL_GOT_FUNDING_LOCKED:
		peer_got_funding_locked(sd->peer, msg);
		break;
	case WIRE_CHANNEL_GOT_SHUTDOWN:
		peer_got_shutdown(sd->peer, msg);
		break;
	case WIRE_CHANNEL_SHUTDOWN_COMPLETE:
		/* We expect 2 fds. */
		if (!fds)
			return 2;
		peer_start_closingd_after_shutdown(sd->peer, msg, fds);
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

static bool peer_start_channeld(struct peer *peer,
				const struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				const u8 *funding_signed,
				bool reconnected)
{
	const tal_t *tmpctx = tal_tmpctx(peer);
	u8 *msg, *initmsg;
	int hsmfd;
	const struct config *cfg = &peer->ld->config;
	struct added_htlc *htlcs;
	enum htlc_state *htlc_states;
	struct fulfilled_htlc *fulfilled_htlcs;
	enum side *fulfilled_sides;
	struct failed_htlc *failed_htlcs;
	enum side *failed_sides;
	struct short_channel_id funding_channel_id;
	const u8 *shutdown_scriptpubkey;
	u64 num_revocations;

	/* Now we can consider balance set. */
	if (!reconnected) {
		assert(!peer->our_msatoshi);
		peer->our_msatoshi = tal(peer, u64);
		if (peer->funder == LOCAL)
			*peer->our_msatoshi
				= peer->funding_satoshi * 1000 - peer->push_msat;
		else
			*peer->our_msatoshi = peer->push_msat;
	} else
		assert(peer->our_msatoshi);

	msg = towire_hsm_client_hsmfd(tmpctx, &peer->id, HSM_CAP_SIGN_GOSSIP | HSM_CAP_ECDH);
	if (!wire_sync_write(peer->ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, peer->ld);
	if (!fromwire_hsm_client_hsmfd_reply(msg, NULL))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	hsmfd = fdpass_recv(peer->ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	peer_set_owner(peer, new_peer_subd(peer->ld,
					   "lightning_channeld", peer,
					   channel_wire_type_name,
					   channel_msg,
					   take(&peer_fd),
					   take(&gossip_fd),
					   take(&hsmfd), NULL));

	if (!peer->owner) {
		log_unusual(peer->log, "Could not subdaemon channel: %s",
			    strerror(errno));
		peer_fail_transient(peer, "Failed to subdaemon channel");
		tal_free(tmpctx);
		return true;
	}

	peer_htlcs(tmpctx, peer, &htlcs, &htlc_states, &fulfilled_htlcs,
		   &fulfilled_sides, &failed_htlcs, &failed_sides);

	if (peer->scid) {
		funding_channel_id = *peer->scid;
		log_debug(peer->log, "Already have funding locked in");
	} else {
		log_debug(peer->log, "Waiting for funding confirmations");
		memset(&funding_channel_id, 0, sizeof(funding_channel_id));
	}

	if (peer->local_shutdown_idx != -1) {
		shutdown_scriptpubkey
			= p2wpkh_for_keyidx(tmpctx, peer->ld,
					    peer->local_shutdown_idx);
	} else
		shutdown_scriptpubkey = NULL;

	num_revocations = revocations_received(&peer->their_shachain.chain);

	/* Warn once. */
	if (peer->ld->config.ignore_fee_limits)
		log_unusual(peer->log, "Ignoring fee limits!");

	initmsg = towire_channel_init(tmpctx,
				      &get_chainparams(peer->ld)
				      ->genesis_blockhash,
				      peer->funding_txid,
				      peer->funding_outnum,
				      peer->funding_satoshi,
				      &peer->our_config,
				      &peer->channel_info->their_config,
				      peer->channel_info->feerate_per_kw,
				      feerate_min(peer->ld),
				      feerate_max(peer->ld),
				      peer->last_sig,
				      cs, gossip_index,
				      &peer->channel_info->remote_fundingkey,
				      &peer->channel_info->theirbase.revocation,
				      &peer->channel_info->theirbase.payment,
				      &peer->channel_info->theirbase.htlc,
				      &peer->channel_info->theirbase.delayed_payment,
				      &peer->channel_info->remote_per_commit,
				      &peer->channel_info->old_remote_per_commit,
				      peer->funder,
				      cfg->fee_base,
				      cfg->fee_per_satoshi,
				      *peer->our_msatoshi,
				      peer->seed,
				      &peer->ld->id,
				      &peer->id,
				      time_to_msec(cfg->commit_time),
				      cfg->cltv_expiry_delta,
				      peer->last_was_revoke,
				      peer->last_sent_commit,
				      peer->next_index[LOCAL],
				      peer->next_index[REMOTE],
				      num_revocations,
				      peer->next_htlc_id,
				      htlcs, htlc_states,
				      fulfilled_htlcs, fulfilled_sides,
				      failed_htlcs, failed_sides,
				      peer->scid != NULL,
				      peer->remote_funding_locked,
				      &funding_channel_id,
				      reconnected,
				      shutdown_scriptpubkey,
				      peer->remote_shutdown_scriptpubkey != NULL,
				      peer->channel_flags,
				      funding_signed);

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(peer->owner, take(initmsg));

	tal_free(tmpctx);
	return true;
}

static bool peer_commit_initial(struct peer *peer)
{
	peer->next_index[LOCAL] = peer->next_index[REMOTE] = 1;
	return true;
}

static void opening_funder_finished(struct subd *opening, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	tal_t *tmpctx = tal_tmpctx(fc);
	u8 *msg;
	struct channel_info *channel_info;
	struct utxo *utxos;
	struct bitcoin_tx *fundingtx;
	struct bitcoin_txid funding_txid;
	struct pubkey changekey;
	struct pubkey local_fundingkey;
	struct crypto_state cs;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u64 gossip_index;

	assert(tal_count(fds) == 2);

	/* At this point, we care about peer */
	fc->peer->channel_info = channel_info
		= tal(fc->peer, struct channel_info);
	remote_commit = tal(resp, struct bitcoin_tx);

	/* This is a new channel_info->their_config so set its ID to 0 */
	fc->peer->channel_info->their_config.id = 0;

	if (!fromwire_opening_funder_reply(resp, NULL,
					   &channel_info->their_config,
					   remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &gossip_index,
					   &channel_info->theirbase.revocation,
					   &channel_info->theirbase.payment,
					   &channel_info->theirbase.htlc,
					   &channel_info->theirbase.delayed_payment,
					   &channel_info->remote_per_commit,
					   &fc->peer->minimum_depth,
					   &channel_info->remote_fundingkey,
					   &funding_txid,
					   &channel_info->feerate_per_kw[REMOTE])) {
		peer_internal_error(fc->peer, "bad funder_reply: %s",
				    tal_hex(resp, resp));
		return;
	}
	/* Feerates begin identical. */
	channel_info->feerate_per_kw[LOCAL]
		= channel_info->feerate_per_kw[REMOTE];

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* Now, keep the initial commit as our last-tx-to-broadcast. */
	peer_last_tx(fc->peer, remote_commit, &remote_commit_sig);

	/* Generate the funding tx. */
	if (fc->change
	    && !bip32_pubkey(fc->peer->ld->wallet->bip32_base,
			     &changekey, fc->change_keyindex))
		fatal("Error deriving change key %u", fc->change_keyindex);

	derive_basepoints(fc->peer->seed, &local_fundingkey, NULL, NULL, NULL);

	fundingtx = funding_tx(tmpctx, &fc->peer->funding_outnum,
			       fc->utxomap, fc->peer->funding_satoshi,
			       &local_fundingkey,
			       &channel_info->remote_fundingkey,
			       fc->change, &changekey,
			       fc->peer->ld->wallet->bip32_base);

	log_debug(fc->peer->log, "Funding tx has %zi inputs, %zu outputs:",
		  tal_count(fundingtx->input),
		  tal_count(fundingtx->output));

	for (size_t i = 0; i < tal_count(fundingtx->input); i++) {
		log_debug(fc->peer->log, "%zi: %"PRIu64" satoshi (%s) %s\n",
			  i, fc->utxomap[i]->amount,
			  fc->utxomap[i]->is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(ltmp, struct bitcoin_txid,
					 &fundingtx->input[i].txid));
	}

	fc->peer->funding_txid = tal(fc->peer, struct bitcoin_txid);
	bitcoin_txid(fundingtx, fc->peer->funding_txid);

	if (!structeq(fc->peer->funding_txid, &funding_txid)) {
		peer_internal_error(fc->peer,
				    "Funding txid mismatch:"
				    " satoshi %"PRIu64" change %"PRIu64
				    " changeidx %u"
				    " localkey %s remotekey %s",
				    fc->peer->funding_satoshi,
				    fc->change, fc->change_keyindex,
				    type_to_string(fc, struct pubkey,
						   &local_fundingkey),
				    type_to_string(fc, struct pubkey,
						   &channel_info->remote_fundingkey));
		return;
	}

	if (!peer_commit_initial(fc->peer)) {
		peer_internal_error(fc->peer, "Initial peer to db failed");
		return;
	}

	/* Get HSM to sign the funding tx. */
	log_debug(fc->peer->log, "Getting HSM to sign funding tx");

	utxos = from_utxoptr_arr(tmpctx, fc->utxomap);
	msg = towire_hsm_sign_funding(tmpctx, fc->peer->funding_satoshi,
				      fc->change, fc->change_keyindex,
				      &local_fundingkey,
				      &channel_info->remote_fundingkey,
				      utxos);
	/* Unowned (will free openingd). */
	peer_set_owner(fc->peer, NULL);

	if (!wire_sync_write(fc->peer->ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	tal_free(tmpctx);

	msg = hsm_sync_read(fc, fc->peer->ld);
	opening_got_hsm_funding_sig(fc, fds[0], fds[1], msg, &cs, gossip_index);
}

static void opening_fundee_finished(struct subd *opening,
				    const u8 *reply,
				    const int *fds,
				    struct peer *peer)
{
	u8 *funding_signed;
	struct channel_info *channel_info;
	struct crypto_state cs;
	u64 gossip_index;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	const tal_t *tmpctx = tal_tmpctx(peer);

	log_debug(peer->log, "Got opening_fundee_finish_response");
	assert(tal_count(fds) == 2);

	remote_commit = tal(reply, struct bitcoin_tx);

	/* At this point, we care about peer */
	peer->channel_info = channel_info = tal(peer, struct channel_info);
	/* This is a new channel_info->their_config, set its ID to 0 */
	peer->channel_info->their_config.id = 0;

	peer->funding_txid = tal(peer, struct bitcoin_txid);
	if (!fromwire_opening_fundee_reply(tmpctx, reply, NULL,
					   &channel_info->their_config,
					   remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &gossip_index,
					   &channel_info->theirbase.revocation,
					   &channel_info->theirbase.payment,
					   &channel_info->theirbase.htlc,
					   &channel_info->theirbase.delayed_payment,
					   &channel_info->remote_per_commit,
					   &channel_info->remote_fundingkey,
					   peer->funding_txid,
					   &peer->funding_outnum,
					   &peer->funding_satoshi,
					   &peer->push_msat,
					   &peer->channel_flags,
					   &channel_info->feerate_per_kw[REMOTE],
					   &funding_signed)) {
		peer_internal_error(peer, "bad OPENING_FUNDEE_REPLY %s",
				    tal_hex(reply, reply));
		tal_free(tmpctx);
		return;
	}

	/* Feerates begin identical. */
	channel_info->feerate_per_kw[LOCAL]
		= channel_info->feerate_per_kw[REMOTE];

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* Now, keep the initial commit as our last-tx-to-broadcast. */
	peer_last_tx(peer, remote_commit, &remote_commit_sig);

	if (!peer_commit_initial(peer)) {
		tal_free(tmpctx);
		return;
	}

	log_debug(peer->log, "Watching funding tx %s",
		     type_to_string(reply, struct bitcoin_txid,
				    peer->funding_txid));
	watch_txid(peer, peer->ld->topology, peer, peer->funding_txid,
		   funding_lockin_cb, NULL);

	/* FIXME: Remove arg from cb? */
	watch_txo(peer, peer->ld->topology, peer, peer->funding_txid,
		  peer->funding_outnum, funding_spent, NULL);

	/* Unowned (will free openingd). */
	peer_set_owner(peer, NULL);

	/* On to normal operation! */
	peer_start_channeld(peer, &cs, gossip_index,
			    fds[0], fds[1], funding_signed, false);
	peer_set_condition(peer, OPENINGD, CHANNELD_AWAITING_LOCKIN);
	tal_free(tmpctx);
}

/* Negotiation failed, but we can keep gossipping */
static unsigned int opening_negotiation_failed(struct subd *openingd,
					       const u8 *msg,
					       const int *fds)
{
	struct crypto_state cs;
	u64 gossip_index;
	struct peer *peer = openingd->peer;
	u8 *err;
	const char *why;

	/* We need the peer fd and gossip fd. */
	if (tal_count(fds) == 0)
		return 2;

	if (!fromwire_opening_negotiation_failed(msg, msg, NULL,
						 &cs, &gossip_index, &err)) {
		peer_internal_error(peer,
				    "bad OPENING_NEGOTIATION_FAILED %s",
				    tal_hex(msg, msg));
		return 0;
	}

	msg = towire_gossipctl_hand_back_peer(msg, &peer->id, &cs, gossip_index,
					      NULL);
	subd_send_msg(openingd->ld->gossip, take(msg));
	subd_send_fd(openingd->ld->gossip, fds[0]);
	subd_send_fd(openingd->ld->gossip, fds[1]);

	why = tal_strndup(peer, (const char *)err, tal_len(err));
	log_unusual(peer->log, "Opening negotiation failed: %s", why);

	/* This will free openingd, since that's peer->owner */
	free_peer(peer, why);
	return 0;
}

/* Peer has spontaneously exited from gossip due to open msg */
static void peer_accept_channel(struct lightningd *ld,
				const struct pubkey *peer_id,
				const struct wireaddr *addr,
				const struct crypto_state *cs,
				u64 gossip_index,
				const u8 *gfeatures, const u8 *lfeatures,
				int peer_fd, int gossip_fd,
				const u8 *open_msg)
{
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;
	struct peer *peer;

	assert(fromwire_peektype(open_msg) == WIRE_OPEN_CHANNEL);

	/* We make a new peer. */
	peer = new_peer(ld, peer_id, addr, gfeatures, lfeatures, peer_fd);
	peer_set_condition(peer, UNINITIALIZED, OPENINGD);
	peer_set_owner(peer,
		       new_peer_subd(ld, "lightning_openingd", peer,
				     opening_wire_type_name,
				     opening_negotiation_failed,
				     take(&peer_fd), take(&gossip_fd), NULL));
	if (!peer->owner) {
		peer_fail_transient(peer, "Failed to subdaemon opening: %s",
				    strerror(errno));
		return;
	}

	/* They will open channel. */
	peer->funder = REMOTE;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `minimum_depth` to a number of blocks it
	 * considers reasonable to avoid double-spending of the funding
	 * transaction.
	 */
	peer->minimum_depth = ld->config.anchor_confirms;

	channel_config(ld, &peer->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	/* Store the channel in the database in order to get a channel
	 * ID that is unique and which we can base the peer_seed on */
	peer->channel = peer_channel_new(ld->wallet, peer);
	peer->seed = tal(peer, struct privkey);
	derive_peer_seed(ld, peer->seed, &peer->id, peer->channel->id);

	msg = towire_opening_init(peer, get_chainparams(ld)->index,
				  &peer->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, gossip_index, peer->seed);

	subd_send_msg(peer->owner, take(msg));

	/* BOLT #2:
	 *
	 * Given the variance in fees, and the fact that the transaction may
	 * be spent in the future, it's a good idea for the fee payer to keep
	 * a good margin, say 5x the expected fee requirement */
	msg = towire_opening_fundee(peer, peer->minimum_depth,
				    get_feerate(ld->topology, FEERATE_SLOW),
				    get_feerate(ld->topology, FEERATE_IMMEDIATE)
				    * 5,
				    open_msg);

	subd_req(peer, peer->owner, take(msg), -1, 2,
		 opening_fundee_finished, peer);
}

static void peer_offer_channel(struct lightningd *ld,
			       struct funding_channel *fc,
			       const struct wireaddr *addr,
			       const struct crypto_state *cs,
			       u64 gossip_index,
			       const u8 *gfeatures, const u8 *lfeatures,
			       int peer_fd, int gossip_fd)
{
	u8 *msg;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	struct utxo *utxos;

	/* We make a new peer. */
	fc->peer = new_peer(ld, &fc->peerid, addr,
			    gfeatures, lfeatures, peer_fd);
	fc->peer->funding_satoshi = fc->funding_satoshi;
	fc->peer->push_msat = fc->push_msat;

	peer_set_condition(fc->peer, UNINITIALIZED, OPENINGD);
	peer_set_owner(fc->peer,
		       new_peer_subd(ld,
				     "lightning_openingd", fc->peer,
				     opening_wire_type_name,
				     opening_negotiation_failed,
				     take(&peer_fd), take(&gossip_fd), NULL));
	if (!fc->peer->owner) {
		fc->peer = tal_free(fc->peer);
		command_fail(fc->cmd,
			     "Failed to launch openingd: %s",
			     strerror(errno));
		return;
	}

	/* FIXME: This is wrong in several ways.
	 *
	 * 1. We should set the temporary channel id *now*, so that's the
	 *    key.
	 * 2. We don't need the peer or channel in db until peer_persists().
	 */

	/* Store the channel in the database in order to get a channel
	 * ID that is unique and which we can base the peer_seed on */
	fc->peer->channel = peer_channel_new(ld->wallet, fc->peer);
	fc->peer->seed = tal(fc->peer, struct privkey);
	derive_peer_seed(ld, fc->peer->seed, &fc->peer->id,
			 fc->peer->channel->id);

	/* We will fund channel */
	fc->peer->funder = LOCAL;
	channel_config(ld, &fc->peer->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	fc->peer->channel_flags = OUR_CHANNEL_FLAGS;

	msg = towire_opening_init(fc,
				  get_chainparams(ld)->index,
				  &fc->peer->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, gossip_index, fc->peer->seed);
	subd_send_msg(fc->peer->owner, take(msg));

	utxos = from_utxoptr_arr(fc, fc->utxomap);

	msg = towire_opening_funder(fc, fc->peer->funding_satoshi,
				    fc->peer->push_msat,
				    get_feerate(ld->topology, FEERATE_NORMAL),
				    max_minimum_depth,
				    fc->change, fc->change_keyindex,
				    fc->peer->channel_flags,
				    utxos, fc->peer->ld->wallet->bip32_base);

	/* Peer now owns fc; if it dies, we fail fc. */
	tal_steal(fc->peer, fc);
	fc->peer->opening_cmd = fc->cmd;

	subd_req(fc, fc->peer->owner,
		 take(msg), -1, 2, opening_funder_finished, fc);
}

/* Peer has been released from gossip.  Start opening. */
static void gossip_peer_released(struct subd *gossip,
				 const u8 *resp,
				 const int *fds,
				 struct funding_channel *fc)
{
	struct lightningd *ld = gossip->ld;
	struct crypto_state cs;
	u64 gossip_index;
	u8 *gfeatures, *lfeatures;
	struct wireaddr addr;

	/* We could have raced with peer doing something else. */
	fc->peer = peer_by_id(ld, &fc->peerid);

	if (!fromwire_gossipctl_release_peer_reply(fc, resp, NULL, &addr, &cs,
						   &gossip_index,
						   &gfeatures, &lfeatures)) {
		if (!fromwire_gossipctl_release_peer_replyfail(resp, NULL)) {
			fatal("Gossip daemon gave invalid reply %s",
			      tal_hex(gossip, resp));
		}
		if (fc->peer)
			command_fail(fc->cmd, "Peer already %s",
				     peer_state_name(fc->peer->state));
		else
			command_fail(fc->cmd, "Peer not connected");
		return;
	}
	assert(tal_count(fds) == 2);

	/* We asked to release this peer, but another raced in?  Corner case,
	 * close this is easiest. */
	if (fc->peer) {
		command_fail(fc->cmd, "Peer already %s",
			     peer_state_name(fc->peer->state));
		close(fds[0]);
		close(fds[1]);
		return;
	}

	/* OK, offer peer a channel. */
	peer_offer_channel(ld, fc, &addr, &cs, gossip_index,
			   gfeatures, lfeatures,
			   fds[0], fds[1]);
}

static void json_fund_channel(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *peertok, *satoshitok;
	struct funding_channel *fc = tal(cmd, struct funding_channel);
	u8 *msg;

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     "satoshi", &satoshitok,
			     NULL)) {
		command_fail(cmd, "Need id and satoshi");
		return;
	}

	fc->cmd = cmd;

	if (!pubkey_from_hexstr(buffer + peertok->start,
				peertok->end - peertok->start, &fc->peerid)) {
		command_fail(cmd, "Could not parse id");
		return;
	}

	if (!json_tok_u64(buffer, satoshitok, &fc->funding_satoshi)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}

	if (fc->funding_satoshi > MAX_FUNDING_SATOSHI) {
		command_fail(cmd, "Funding satoshi must be <= %d",
			     MAX_FUNDING_SATOSHI);
		return;
	}

	/* FIXME: Support push_msat? */
	fc->push_msat = 0;

	/* Try to do this now, so we know if insufficient funds. */
	/* FIXME: dustlimit */
	fc->utxomap = build_utxos(fc, cmd->ld, fc->funding_satoshi,
				  get_feerate(cmd->ld->topology, FEERATE_NORMAL),
				  600, BITCOIN_SCRIPTPUBKEY_P2WSH_LEN,
				  &fc->change, &fc->change_keyindex);
	if (!fc->utxomap) {
		command_fail(cmd, "Cannot afford funding transaction");
		return;
	}

	msg = towire_gossipctl_release_peer(cmd, &fc->peerid);
	subd_req(fc, cmd->ld->gossip, msg, -1, 2, gossip_peer_released, fc);
	command_still_pending(cmd);
}

static const struct json_command fund_channel_command = {
	"fundchannel",
	json_fund_channel,
	"Fund channel with {id} using {satoshi} satoshis",
	"Returns {tx} once channel established"
};
AUTODATA(json_command, &fund_channel_command);

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *peertok;
	struct peer *peer;

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     NULL)) {
		command_fail(cmd, "Need id");
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	/* Easy case: peer can simply be forgotten. */
	if (!peer_persists(peer)) {
		peer_fail_permanent(peer, "Peer closed in state %s",
				    peer_state_name(peer->state));
		command_success(cmd, null_response(cmd));
		return;
	}

	/* Normal case. */
	if (peer->state == CHANNELD_NORMAL) {
		u8 *shutdown_scriptpubkey;

		peer->local_shutdown_idx = wallet_get_newindex(peer->ld);
		if (peer->local_shutdown_idx == -1) {
			command_fail(cmd, "Failed to get new key for shutdown");
			return;
		}
		shutdown_scriptpubkey = p2wpkh_for_keyidx(cmd, peer->ld,
							  peer->local_shutdown_idx);
		if (!shutdown_scriptpubkey) {
			command_fail(cmd, "Failed to get script for shutdown");
			return;
		}

		peer_set_condition(peer, CHANNELD_NORMAL, CHANNELD_SHUTTING_DOWN);

		txfilter_add_scriptpubkey(peer->ld->owned_txfilter, shutdown_scriptpubkey);

		if (peer->owner)
			subd_send_msg(peer->owner,
				      take(towire_channel_send_shutdown(peer,
						   shutdown_scriptpubkey)));

		command_success(cmd, null_response(cmd));
	} else
		command_fail(cmd, "Peer is in state %s",
			     peer_state_name(peer->state));
}

static const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with peer {id}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &close_command);


const char *peer_state_name(enum peer_state state)
{
	size_t i;

	for (i = 0; enum_peer_state_names[i].name; i++)
		if (enum_peer_state_names[i].v == state)
			return enum_peer_state_names[i].name;
	return "unknown";
}

static void activate_peer(struct peer *peer)
{
	u8 *msg;

	assert(!peer->owner);

	/* Pass gossipd any addrhints we currently have */
	msg = towire_gossipctl_peer_addrhint(peer, &peer->id, &peer->addr);
	subd_send_msg(peer->ld->gossip, take(msg));

	/* FIXME: We should never have these in the database! */
	if (!peer->funding_txid) {
		log_broken(peer->log, "activate_peer(%s) with no funding txid?",
			   peer_state_name(peer->state));
		return;
	}

	/* This may be unnecessary, but it's harmless. */
	watch_txid(peer, peer->ld->topology, peer, peer->funding_txid,
		   funding_lockin_cb, NULL);

	watch_txo(peer, peer->ld->topology, peer, peer->funding_txid, peer->funding_outnum,
		  funding_spent, NULL);

	if (peer_wants_reconnect(peer)) {
		msg = towire_gossipctl_reach_peer(peer, &peer->id);
		subd_send_msg(peer->ld->gossip, take(msg));
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

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     NULL)) {
		command_fail(cmd, "Need id");
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}
	if (!peer->last_tx) {
		command_fail(cmd, "Peer has no final transaction");
		return;
	}

	log_debug(peer->log, "dev-sign-last-tx: signing tx with %zu outputs",
		  tal_count(peer->last_tx->output));
	sign_last_tx(peer);
	linear = linearize_tx(cmd, peer->last_tx);
	remove_sig(peer->last_tx);

	json_object_start(response, NULL);
	json_add_hex(response, "tx", linear, tal_len(linear));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command dev_sign_last_tx = {
	"dev-sign-last-tx",
	json_sign_last_tx,
	"Sign and return the last commitment transaction with peer {id}",
	"Sign last transaction with peer @id, return as @tx."
	"  This should never be called outside testing!"
};
AUTODATA(json_command, &dev_sign_last_tx);

static void json_dev_fail(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *peertok;
	struct peer *peer;

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     NULL)) {
		command_fail(cmd, "Need id");
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	peer_internal_error(peer, "Failing due to dev-fail command");
	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_fail_command = {
	"dev-fail",
	json_dev_fail,
	"Fail with peer {id}",
	"Returns {} on success"
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

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     NULL)) {
		command_fail(cmd, "Need id");
		return;
	}

	peer = peer_from_json(cmd->ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	if (!peer->owner) {
		command_fail(cmd, "Peer has no owner");
		return;
	}

	if (!streq(peer->owner->name, "lightning_channeld")) {
		command_fail(cmd, "Peer owned by %s", peer->owner->name);
		return;
	}

	msg = towire_channel_dev_reenable_commit(peer);
	subd_req(peer, peer->owner, take(msg), -1, 0,
		 dev_reenable_commit_finished, cmd);
	command_still_pending(cmd);
}

static const struct json_command dev_reenable_commit = {
	"dev-reenable-commit",
	json_dev_reenable_commit,
	"Reenable the commit timer on peer {id}",
	"Returns {} on success"
};
AUTODATA(json_command, &dev_reenable_commit);
#endif /* DEVELOPER */
