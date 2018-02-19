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
#include <gossipd/routing.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
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

/* Channel we're still opening. */
struct uncommitted_channel {
	/* peer->uncommitted_channel == this */
	struct peer *peer;

	/* openingd which is running now */
	struct subd *openingd;

	/* Reserved dbid for if we become a real struct channel */
	u64 dbid;

	/* For logging */
	struct log *log;

	/* If we offered channel, this contains information, otherwise NULL */
	struct funding_channel *fc;

	/* Secret seed (FIXME: Move to hsm!) */
	struct privkey seed;

	/* Blockheight at creation, scans for funding confirmations
	 * will start here */
	u64 first_blocknum;

	/* These are *not* filled in by new_uncommitted_channel: */

	/* Minimum funding depth (if funder == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};

struct funding_channel {
	struct command *cmd; /* Which also owns us. */

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Details of how to make funding. */
	const struct utxo **utxomap;
	u64 change;
	u32 change_keyindex;
	u64 funding_satoshi, push_msat;
	u8 channel_flags;

	/* Channel. */
	struct uncommitted_channel *uc;
};

/* FIXME: Reorder */
static void copy_to_parent_log(const char *prefix,
			       enum log_level level,
			       bool continued,
			       const struct timeabs *time,
			       const char *str,
			       const u8 *io,
			       struct log *parent_log);
static void peer_offer_channel(struct lightningd *ld,
			       struct funding_channel *fc,
			       const struct wireaddr *addr,
			       const struct crypto_state *cs,
			       u64 gossip_index,
			       const u8 *gfeatures, const u8 *lfeatures,
			       int peer_fd, int gossip_fd);
static bool peer_start_channeld(struct channel *channel,
				const struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				const u8 *funding_signed,
				bool reconnected);
static void peer_start_closingd(struct channel *channel,
				struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				bool reconnected);
static u8 *peer_accept_channel(struct lightningd *ld,
			       const struct pubkey *peer_id,
			       const struct wireaddr *addr,
			       const struct crypto_state *cs,
			       u64 gossip_index,
			       const u8 *gfeatures, const u8 *lfeatures,
			       int peer_fd, int gossip_fd,
			       const struct channel_id *channel_id,
			       const u8 *open_msg);

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
					      &channel->channel_info->remote_fundingkey);
	/* Need input amount for signing */
	channel->last_tx->input[0].amount = tal_dup(channel->last_tx->input, u64,
						    &channel->funding_satoshi);
	sign_tx_input(channel->last_tx, 0, NULL, funding_wscript,
		      &secrets.funding_privkey,
		      &local_funding_pubkey,
		      &sig);

	channel->last_tx->input[0].witness
		= bitcoin_witness_2of2(channel->last_tx->input,
				       channel->last_sig,
				       &sig,
				       &channel->channel_info->remote_fundingkey,
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

/* Opening failed: hand back to gossipd (with error if we have channel_id) */
static void uncommitted_channel_to_gossipd(struct lightningd *ld,
					   struct uncommitted_channel *uc,
					   const struct channel_id *channel_id,
					   const struct crypto_state *cs,
					   u64 gossip_index,
					   int peer_fd, int gossip_fd,
					   const char *fmt,
					   ...)
{
	va_list ap;
	char *errstr;
	u8 *error = NULL, *msg;

	va_start(ap, fmt);
	errstr = tal_vfmt(uc, fmt, ap);
	va_end(ap);

	log_unusual(uc->log, "Opening channel: %s", errstr);
	if (uc->fc)
		command_fail(uc->fc->cmd, "%s", errstr);
	if (channel_id)
		error = towire_errorfmt(uc, channel_id, "%s", errstr);
	/* Hand back to gossipd, with an error packet. */
	msg = towire_gossipctl_hand_back_peer(error, &uc->peer->id, cs,
					      gossip_index,
					      error);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);
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

static void channel_errmsg(struct channel *channel,
			   enum side sender,
			   const struct channel_id *channel_id,
			   const char *desc,
			   const u8 *errmsg)
{
	if (sender == LOCAL) {
		/* If this is NULL, it means subd died. */
		if (!errmsg) {
			channel_fail_transient(channel, "%s: %s",
					       channel->owner->name, desc);
			return;
		}

		/* Otherwise overwrite any error we have */
		if (!channel->error)
			channel->error = tal_dup_arr(channel, u8,
						     errmsg, tal_len(errmsg), 0);
	}

	channel_fail_permanent(channel, "%s: %s ERROR %s",
			       channel->owner->name,
			       sender == LOCAL ? "sent" : "received", desc);
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
		log_info(uc->log, "Peer reconnected, killing openingd");

		/* Close openingd. */
		subd_release_channel(uc->openingd, uc);
		tal_free(uc);
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
			/* This can't happen. */
		case UNINITIALIZED:
			abort();

			/* Reconnect: discard old one. */
		case OPENINGD:
			delete_channel(channel, "peer reconnected");
			channel = NULL;
			goto return_to_gossipd;

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

void peer_connection_failed(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;
	u32 attempts, timediff;
	struct connect *i, *next;
	bool addr_unknown;
	char *error;

	if (!fromwire_gossip_peer_connection_failed(msg, NULL, &id, &timediff,
						    &attempts, &addr_unknown))
		fatal(
		    "Gossip gave bad GOSSIP_PEER_CONNECTION_FAILED message %s",
		    tal_hex(msg, msg));

	if (addr_unknown) {
		error = tal_fmt(
		    msg, "No address known for node %s, please provide one",
		    type_to_string(msg, struct pubkey, &id));
	} else {
		error = tal_fmt(msg, "Could not connect to %s after %d seconds and %d attempts",
				type_to_string(msg, struct pubkey, &id), timediff,
				attempts);
	}

	/* Careful!  Completing command frees connect. */
	list_for_each_safe(&ld->connects, i, next, list) {
		if (!pubkey_eq(&i->id, &id))
			continue;

		command_fail(i->cmd, "%s", error);
	}
}

static struct channel *channel_by_channel_id(struct peer *peer,
					     const struct channel_id *channel_id)
{
	struct channel *channel;

	list_for_each(&peer->channels, channel, list) {
		struct channel_id cid;

		if (!channel->funding_txid)
			continue;

		derive_channel_id(&cid,
				  channel->funding_txid,
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

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *hosttok, *porttok, *idtok;
	struct pubkey id;
	const char *name;
	struct wireaddr addr;
	u8 *msg;

	if (!json_get_params(cmd, buffer, params,
			     "id", &idtok,
			     "?host", &hosttok,
			     "?port", &porttok,
			     NULL)) {
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
				command_fail(cmd, "Port %.*s not valid",
					     porttok->end - porttok->start,
					     buffer + porttok->start);
				return;
			}
			addr.port = port;
		} else {
			addr.port = DEFAULT_PORT;
		}
		if (!parse_wireaddr(name, &addr, addr.port) || !addr.port) {
			command_fail(cmd, "Host %s:%u not valid",
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
	"Connect to {id} at {host} (which can end in ':port' if not default)"
};
AUTODATA(json_command, &connect_command);

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
		if (p->uncommitted_channel) {
			const struct uncommitted_channel *uc
				= p->uncommitted_channel;
			json_object_start(response, NULL);
			json_add_string(response, "state", "OPENINGD");
			json_add_string(response, "owner", "lightning_openingd");
			json_add_string(response, "funder",
					uc->fc ? "LOCAL" : "REMOTE");
			if (uc->fc) {
				u64 msatoshi_total, our_msatoshi;

				msatoshi_total = uc->fc->funding_satoshi * 1000;
				our_msatoshi = msatoshi_total - uc->fc->push_msat;
				json_add_u64(response, "msatoshi_to_us",
					     our_msatoshi);
				json_add_u64(response, "msatoshi_total",
					     msatoshi_total);
			}
			json_object_end(response);
		}

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
			if (channel->funding_txid)
				json_add_txid(response,
					      "funding_txid",
					      channel->funding_txid);
			if (channel->our_msatoshi) {
				json_add_u64(response, "msatoshi_to_us",
					     *channel->our_msatoshi);
				json_add_u64(response, "msatoshi_total",
					     channel->funding_satoshi * 1000);
			}

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

static void funding_broadcast_failed(struct channel *channel,
				     int exitstatus, const char *err)
{
	channel_internal_error(channel,
			       "Funding broadcast exited with %i: %s",
			       exitstatus, err);
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


/* We dump all the known preimages when onchaind starts up. */
static void onchaind_tell_fulfill(struct channel *channel)
{
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	u8 *msg;
	struct lightningd *ld = channel->peer->ld;

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
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

		msg = towire_onchain_known_preimage(channel, hin->preimage);
		subd_send_msg(channel->owner, take(msg));
	}
}

static void handle_onchain_init_reply(struct channel *channel, const u8 *msg)
{
	u8 state;

	if (!fromwire_onchain_init_reply(msg, NULL, &state)) {
		channel_internal_error(channel, "Invalid onchain_init_reply");
		return;
	}

	if (!channel_state_on_chain(state)) {
		channel_internal_error(channel,
				    "Invalid onchain_init_reply state %u (%s)",
				    state, peer_state_name(state));
		return;
	}

	channel_set_state(channel, FUNDING_SPEND_SEEN, state);

	/* Tell it about any preimages we know. */
	onchaind_tell_fulfill(channel);
}

static enum watch_result onchain_tx_watched(struct channel *channel,
					    const struct bitcoin_tx *tx,
					    unsigned int depth,
					    void *unused)
{
	u8 *msg;
	struct bitcoin_txid txid;

	if (depth == 0) {
		log_unusual(channel->log, "Chain reorganization!");
		channel_set_owner(channel, NULL);

		/* FIXME!
		topology_rescan(peer->ld->topology, peer->funding_txid);
		*/

		/* We will most likely be freed, so this is a noop */
		return KEEP_WATCHING;
	}

	bitcoin_txid(tx, &txid);
	msg = towire_onchain_depth(channel, &txid, depth);
	subd_send_msg(channel->owner, take(msg));
	return KEEP_WATCHING;
}

static void watch_tx_and_outputs(struct channel *channel,
				 const struct bitcoin_tx *tx);

static enum watch_result onchain_txo_watched(struct channel *channel,
					     const struct bitcoin_tx *tx,
					     size_t input_num,
					     const struct block *block,
					     void *unused)
{
	u8 *msg;

	watch_tx_and_outputs(channel, tx);

	msg = towire_onchain_spent(channel, tx, input_num, block->height);
	subd_send_msg(channel->owner, take(msg));

	/* We don't need to keep watching: If this output is double-spent
	 * (reorg), we'll get a zero depth cb to onchain_tx_watched, and
	 * restart onchaind. */
	return DELETE_WATCH;
}

/* To avoid races, we watch the tx and all outputs. */
static void watch_tx_and_outputs(struct channel *channel,
				 const struct bitcoin_tx *tx)
{
	struct bitcoin_txid txid;
	struct txwatch *txw;
	struct lightningd *ld = channel->peer->ld;

	bitcoin_txid(tx, &txid);

	/* Make txwatch a parent of txo watches, so we can unwatch together. */
	txw = watch_tx(channel->owner, ld->topology, channel, tx,
		       onchain_tx_watched, NULL);

	for (size_t i = 0; i < tal_count(tx->output); i++)
		watch_txo(txw, ld->topology, channel, &txid, i,
			  onchain_txo_watched, NULL);
}

static void handle_onchain_broadcast_tx(struct channel *channel, const u8 *msg)
{
	struct bitcoin_tx *tx;

	if (!fromwire_onchain_broadcast_tx(msg, msg, NULL, &tx)) {
		channel_internal_error(channel, "Invalid onchain_broadcast_tx");
		return;
	}

	/* We don't really care if it fails, we'll respond via watch. */
	broadcast_tx(channel->peer->ld->topology, channel, tx, NULL);
}

static void handle_onchain_unwatch_tx(struct channel *channel, const u8 *msg)
{
	struct bitcoin_txid txid;
	struct txwatch *txw;

	if (!fromwire_onchain_unwatch_tx(msg, NULL, &txid)) {
		channel_internal_error(channel, "Invalid onchain_unwatch_tx");
		return;
	}

	/* Frees the txo watches, too: see watch_tx_and_outputs() */
	txw = find_txwatch(channel->peer->ld->topology, &txid, channel);
	if (!txw)
		log_unusual(channel->log, "Can't unwatch txid %s",
			    type_to_string(ltmp, struct bitcoin_txid, &txid));
	tal_free(txw);
}

static void handle_extracted_preimage(struct channel *channel, const u8 *msg)
{
	struct preimage preimage;

	if (!fromwire_onchain_extracted_preimage(msg, NULL, &preimage)) {
		channel_internal_error(channel, "Invalid extracted_preimage");
		return;
	}

	onchain_fulfilled_htlc(channel, &preimage);
}

static void handle_missing_htlc_output(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchain_missing_htlc_output(msg, NULL, &htlc)) {
		channel_internal_error(channel, "Invalid missing_htlc_output");
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
	onchain_failed_our_htlc(channel, &htlc, "missing in commitment tx");
}

static void handle_onchain_htlc_timeout(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchain_htlc_timeout(msg, NULL, &htlc)) {
		channel_internal_error(channel, "Invalid onchain_htlc_timeout");
		return;
	}

	/* BOLT #5:
	 *
	 * If the HTLC output has *timed out* and not been *resolved*, the node
	 * MUST *resolve* the output and MUST fail the corresponding incoming
	 * HTLC (if any) once the resolving transaction has reached reasonable
	 * depth.
	 */
	onchain_failed_our_htlc(channel, &htlc, "timed out");
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

static void handle_irrevocably_resolved(struct channel *channel, const u8 *msg)
{
	/* FIXME: Implement check_htlcs to ensure no dangling hout->in ptrs! */
	free_htlcs(channel->peer->ld, channel);

	log_info(channel->log, "onchaind complete, forgetting peer");

	/* This will also free onchaind. */
	delete_channel(channel, "onchaind complete, forgetting peer");
}

/**
 * onchain_add_utxo -- onchaind is telling us about an UTXO we own
 */
static void onchain_add_utxo(struct channel *channel, const u8 *msg)
{
	struct utxo *u = tal(msg, struct utxo);
	u->close_info = tal(u, struct unilateral_close_info);

	u->is_p2sh = true;
	u->keyindex = 0;
	u->status = output_state_available;
	u->close_info->channel_id = channel->dbid;
	u->close_info->peer_id = channel->peer->id;

	if (!fromwire_onchain_add_utxo(msg, NULL, &u->txid, &u->outnum,
				       &u->close_info->commitment_point,
				       &u->amount)) {
		fatal("onchaind gave invalid add_utxo message: %s", tal_hex(msg, msg));
	}


	wallet_add_utxo(channel->peer->ld->wallet, u, p2wpkh);
}

static unsigned int onchain_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum onchain_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ONCHAIN_INIT_REPLY:
		handle_onchain_init_reply(sd->channel, msg);
		break;

	case WIRE_ONCHAIN_BROADCAST_TX:
		handle_onchain_broadcast_tx(sd->channel, msg);
		break;

	case WIRE_ONCHAIN_UNWATCH_TX:
		handle_onchain_unwatch_tx(sd->channel, msg);
		break;

 	case WIRE_ONCHAIN_EXTRACTED_PREIMAGE:
		handle_extracted_preimage(sd->channel, msg);
		break;

	case WIRE_ONCHAIN_MISSING_HTLC_OUTPUT:
		handle_missing_htlc_output(sd->channel, msg);
		break;

	case WIRE_ONCHAIN_HTLC_TIMEOUT:
		handle_onchain_htlc_timeout(sd->channel, msg);
		break;

	case WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED:
		handle_irrevocably_resolved(sd->channel, msg);
		break;

	case WIRE_ONCHAIN_ADD_UTXO:
		onchain_add_utxo(sd->channel, msg);
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
static bool tell_if_missing(const struct channel *channel,
			    struct htlc_stub *stub,
			    bool *tell_immediate)
{
	struct htlc_out *hout;

	/* Keep valgrind happy. */
	*tell_immediate = false;

	/* Is it a current HTLC? */
	hout = find_htlc_out_by_ripemd(channel, &stub->ripemd);
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

	log_debug(channel->log,
		  "We want to know if htlc %"PRIu64" is missing (%s)",
		  hout->key.id, *tell_immediate ? "immediate" : "later");
	return true;
}

/* Only error onchaind can get is if it dies. */
static void onchain_error(struct channel *channel,
			  enum side sender,
			  const struct channel_id *channel_id,
			  const char *desc,
			  const u8 *errmsg)
{
	/* FIXME: re-launch? */
	log_broken(channel->log, "%s", desc);
}

/* With a reorg, this can get called multiple times; each time we'll kill
 * onchaind (like any other owner), and restart */
static enum watch_result funding_spent(struct channel *channel,
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
	const tal_t *tmpctx = tal_tmpctx(channel);
	struct lightningd *ld = channel->peer->ld;

	channel_fail_permanent(channel, "Funding transaction spent");

	/* We could come from almost any state. */
	channel_set_state(channel, channel->state, FUNDING_SPEND_SEEN);

	channel_set_owner(channel, new_channel_subd(ld,
						    "lightning_onchaind",
						    channel,
						    channel->log,
						    onchain_wire_type_name,
						    onchain_msg,
						    onchain_error,
						    NULL));

	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon onchain: %s",
			   strerror(errno));
		tal_free(tmpctx);
		return KEEP_WATCHING;
	}

	stubs = wallet_htlc_stubs(tmpctx, ld->wallet, channel);
	if (!stubs) {
		log_broken(channel->log, "Could not load htlc_stubs");
		tal_free(tmpctx);
		return KEEP_WATCHING;
	}

	/* We re-use this key to send other outputs to. */
	if (channel->local_shutdown_idx >= 0)
		keyindex = channel->local_shutdown_idx;
	else {
		keyindex = wallet_get_newindex(ld);
		if (keyindex < 0) {
			log_broken(channel->log, "Could not get keyindex");
			tal_free(tmpctx);
			return KEEP_WATCHING;
		}
	}
	scriptpubkey = p2wpkh_for_keyidx(tmpctx, ld, keyindex);
	if (!scriptpubkey) {
		channel_internal_error(channel,
				    "Can't get shutdown script %"PRIu64,
				    keyindex);
		tal_free(tmpctx);
		return DELETE_WATCH;
	}
	txfilter_add_scriptpubkey(ld->owned_txfilter, scriptpubkey);

	if (!bip32_pubkey(ld->wallet->bip32_base, &ourkey, keyindex)) {
		channel_internal_error(channel,
				    "Can't get shutdown key %"PRIu64,
				    keyindex);
		tal_free(tmpctx);
		return DELETE_WATCH;
	}

	/* This could be a mutual close, but it doesn't matter. */
	bitcoin_txid(channel->last_tx, &our_last_txid);

	msg = towire_onchain_init(channel,
				  &channel->seed, &channel->their_shachain.chain,
				  channel->funding_satoshi,
				  &channel->channel_info->old_remote_per_commit,
				  &channel->channel_info->remote_per_commit,
				   /* BOLT #2:
				    * `to_self_delay` is the number of blocks
				    * that the other nodes to-self outputs
				    * must be delayed */
				   /* So, these are reversed: they specify ours,
				    * we specify theirs. */
				  channel->channel_info->their_config.to_self_delay,
				  channel->our_config.to_self_delay,
				  get_feerate(ld->topology, FEERATE_NORMAL),
				  channel->our_config.dust_limit_satoshis,
				  &channel->channel_info->theirbase.revocation,
				  &our_last_txid,
				  scriptpubkey,
				  channel->remote_shutdown_scriptpubkey,
				  &ourkey,
				  channel->funder,
				  &channel->channel_info->theirbase.payment,
				  &channel->channel_info->theirbase.htlc,
				  &channel->channel_info->theirbase.delayed_payment,
				  tx,
				  block->height,
				  /* FIXME: config for 'reasonable depth' */
				  3,
				  channel->last_htlc_sigs,
				  tal_count(stubs));
	subd_send_msg(channel->owner, take(msg));

	/* FIXME: Don't queue all at once, use an empty cb... */
	for (size_t i = 0; i < tal_count(stubs); i++) {
		bool tell_immediate;
		bool tell = tell_if_missing(channel, &stubs[i], &tell_immediate);
		msg = towire_onchain_htlc(channel, &stubs[i],
					  tell, tell_immediate);
		subd_send_msg(channel->owner, take(msg));
	}

	watch_tx_and_outputs(channel, tx);

	tal_free(tmpctx);
	/* We keep watching until peer finally deleted, for reorgs. */
	return KEEP_WATCHING;
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

static void opening_got_hsm_funding_sig(struct channel *channel,
					struct command *cmd,
					const struct utxo **utxomap,
					int peer_fd, int gossip_fd,
					const u8 *resp,
					const struct crypto_state *cs,
					u64 gossip_index)
{
	struct bitcoin_tx *tx;
	u8 *linear;
	u64 change_satoshi;
	struct json_result *response = new_json_result(cmd);
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_hsm_sign_funding_reply(cmd, resp, NULL, &tx))
		fatal("HSM gave bad sign_funding_reply %s",
		      tal_hex(cmd, resp));

	/* Send it out and watch for confirms. */
	broadcast_tx(ld->topology, channel, tx, funding_broadcast_failed);
	watch_tx(channel, ld->topology, channel, tx, funding_lockin_cb, NULL);

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(ld->wallet, tx, &change_satoshi);

	/* FIXME: Remove arg from cb? */
	watch_txo(channel, ld->topology, channel,
		  channel->funding_txid, channel->funding_outnum,
		  funding_spent, NULL);

	json_object_start(response, NULL);
	linear = linearize_tx(response, tx);
	json_add_hex(response, "tx", linear, tal_len(linear));
	json_add_txid(response, "txid", channel->funding_txid);
	json_object_end(response);
	command_success(cmd, response);

	/* Start normal channel daemon. */
	peer_start_channeld(channel, cs, gossip_index,
			    peer_fd, gossip_fd, NULL, false);

	wallet_confirm_utxos(ld->wallet, utxomap);
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

/* Is this better than the last tx we were holding?  This can happen
 * even without closingd misbehaving, if we have multiple,
 * interrupted, rounds of negotiation. */
static bool better_closing_fee(struct lightningd *ld,
			       struct channel *channel,
			       const struct bitcoin_tx *tx)
{
	u64 weight, fee, last_fee, ideal_fee, min_fee;
	s64 old_diff, new_diff;
	size_t i;

	/* Calculate actual fee (adds in eliminated outputs) */
	fee = channel->funding_satoshi;
	for (i = 0; i < tal_count(tx->output); i++)
		fee -= tx->output[i].amount;

	last_fee = channel->funding_satoshi;
	for (i = 0; i < tal_count(channel->last_tx); i++)
		last_fee -= channel->last_tx->output[i].amount;

	log_debug(channel->log, "Their actual closing tx fee is %"PRIu64
		 " vs previous %"PRIu64, fee, last_fee);

	/* Weight once we add in sigs. */
	weight = measure_tx_weight(tx) + 74 * 2;

	min_fee = get_feerate(ld->topology, FEERATE_SLOW) * weight / 1000;
	if (fee < min_fee) {
		log_debug(channel->log, "... That's below our min %"PRIu64
			 " for weight %"PRIu64" at feerate %u",
			 min_fee, weight,
			 get_feerate(ld->topology, FEERATE_SLOW));
		return false;
	}

	ideal_fee = get_feerate(ld->topology, FEERATE_NORMAL) * weight / 1000;

	/* We prefer fee which is closest to our ideal. */
	old_diff = imaxabs((s64)ideal_fee - (s64)last_fee);
	new_diff = imaxabs((s64)ideal_fee - (s64)fee);

	/* In case of a tie, prefer new over old: this covers the preference
	 * for a mutual close over a unilateral one. */
	log_debug(channel->log, "... That's %s our ideal %"PRIu64,
		 new_diff < old_diff
		 ? "closer to"
		 : new_diff > old_diff
		 ? "further from"
		 : "same distance to",
		 ideal_fee);

	return new_diff <= old_diff;
}

static void peer_received_closing_signature(struct channel *channel,
					    const u8 *msg)
{
	secp256k1_ecdsa_signature sig;
	struct bitcoin_tx *tx;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_closing_received_signature(msg, msg, NULL, &sig, &tx)) {
		channel_internal_error(channel, "Bad closing_received_signature %s",
				       tal_hex(msg, msg));
		return;
	}

	/* FIXME: Make sure signature is correct! */
	if (better_closing_fee(ld, channel, tx)) {
		channel_set_last_tx(channel, tx, &sig);
		/* TODO(cdecker) Selectively save updated fields to DB */
		wallet_channel_save(ld->wallet, channel);
	}

	/* OK, you can continue now. */
	subd_send_msg(channel->owner,
		      take(towire_closing_received_signature_reply(channel)));
}

static void peer_closing_complete(struct channel *channel, const u8 *msg)
{
	/* FIXME: We should save this, to return to gossipd */
	u64 gossip_index;

	if (!fromwire_closing_complete(msg, NULL, &gossip_index)) {
		channel_internal_error(channel, "Bad closing_complete %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Retransmission only, ignore closing. */
	if (channel->state == CLOSINGD_COMPLETE)
		return;

	drop_to_chain(channel->peer->ld, channel);
	channel_set_state(channel, CLOSINGD_SIGEXCHANGE, CLOSINGD_COMPLETE);
}

static unsigned closing_msg(struct subd *sd, const u8 *msg, const int *fds)
{
	enum closing_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CLOSING_RECEIVED_SIGNATURE:
		peer_received_closing_signature(sd->channel, msg);
		break;

	case WIRE_CLOSING_COMPLETE:
		peer_closing_complete(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_CLOSING_INIT:
	case WIRE_CLOSING_RECEIVED_SIGNATURE_REPLY:
		break;
	}

	return 0;
}

static void peer_start_closingd(struct channel *channel,
				struct crypto_state *cs,
				u64 gossip_index,
				int peer_fd, int gossip_fd,
				bool reconnected)
{
	const tal_t *tmpctx = tal_tmpctx(channel);
	u8 *initmsg, *local_scriptpubkey;
	u64 minfee, startfee, feelimit;
	u64 num_revocations;
	u64 funding_msatoshi, our_msatoshi, their_msatoshi;
	struct lightningd *ld = channel->peer->ld;

	if (channel->local_shutdown_idx == -1
	    || !channel->remote_shutdown_scriptpubkey) {
		channel_internal_error(channel,
				    "Can't start closing: local %s remote %s",
				    channel->local_shutdown_idx == -1
				    ? "not shutdown" : "shutdown",
				    channel->remote_shutdown_scriptpubkey
				    ? "shutdown" : "not shutdown");
		tal_free(tmpctx);
		return;
	}

	channel_set_owner(channel, new_channel_subd(ld,
					   "lightning_closingd",
					   channel, channel->log,
					   closing_wire_type_name, closing_msg,
					   channel_errmsg,
					   take(&peer_fd), take(&gossip_fd),
					   NULL));
	if (!channel->owner) {
		log_unusual(channel->log, "Could not subdaemon closing: %s",
			    strerror(errno));
		channel_fail_transient(channel, "Failed to subdaemon closing");
		tal_free(tmpctx);
		return;
	}

	local_scriptpubkey = p2wpkh_for_keyidx(tmpctx, ld,
					       channel->local_shutdown_idx);
	if (!local_scriptpubkey) {
		channel_internal_error(channel,
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
	feelimit = commit_tx_base_fee(channel->channel_info->feerate_per_kw[LOCAL],
				      0);

	minfee = commit_tx_base_fee(get_feerate(ld->topology, FEERATE_SLOW), 0);
	startfee = commit_tx_base_fee(get_feerate(ld->topology, FEERATE_NORMAL),
				      0);

	if (startfee > feelimit)
		startfee = feelimit;
	if (minfee > feelimit)
		minfee = feelimit;

	num_revocations
		= revocations_received(&channel->their_shachain.chain);

	/* BOLT #3:
	 *
	 * The amounts for each output MUST BE rounded down to whole satoshis.
	 */
	/* Convert unit */
	funding_msatoshi = channel->funding_satoshi * 1000;
	/* What is not ours is theirs */
	our_msatoshi = *channel->our_msatoshi;
	their_msatoshi = funding_msatoshi - our_msatoshi;
	initmsg = towire_closing_init(tmpctx,
				      cs,
				      gossip_index,
				      &channel->seed,
				      channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding_satoshi,
				      &channel->channel_info->remote_fundingkey,
				      channel->funder,
				      our_msatoshi / 1000, /* Rounds down */
				      their_msatoshi / 1000, /* Rounds down */
				      channel->our_config.dust_limit_satoshis,
				      minfee, feelimit, startfee,
				      local_scriptpubkey,
				      channel->remote_shutdown_scriptpubkey,
				      reconnected,
				      channel->next_index[LOCAL],
				      channel->next_index[REMOTE],
				      num_revocations,
				      deprecated_apis);

	/* We don't expect a response: it will give us feedback on
	 * signatures sent and received, then closing_complete. */
	subd_send_msg(channel->owner, take(initmsg));
	tal_free(tmpctx);
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

static bool peer_start_channeld(struct channel *channel,
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

	assert(channel->our_msatoshi);

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
				      channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding_satoshi,
				      &channel->our_config,
				      &channel->channel_info->their_config,
				      channel->channel_info->feerate_per_kw,
				      feerate_min(ld),
				      feerate_max(ld),
				      channel->last_sig,
				      cs, gossip_index,
				      &channel->channel_info->remote_fundingkey,
				      &channel->channel_info->theirbase.revocation,
				      &channel->channel_info->theirbase.payment,
				      &channel->channel_info->theirbase.htlc,
				      &channel->channel_info->theirbase.delayed_payment,
				      &channel->channel_info->remote_per_commit,
				      &channel->channel_info->old_remote_per_commit,
				      channel->funder,
				      cfg->fee_base,
				      cfg->fee_per_satoshi,
				      *channel->our_msatoshi,
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

/* FIXME: Unify with new_channel */
static struct channel *
wallet_commit_channel(struct lightningd *ld,
		      struct uncommitted_channel *uc,
		      struct bitcoin_tx *remote_commit,
		      secp256k1_ecdsa_signature *remote_commit_sig,
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      u64 funding_satoshi,
		      u64 push_msat,
		      u8 channel_flags,
		      const struct channel_info *channel_info,
		      u32 feerate)
{
	struct channel *channel;

	channel = new_channel(uc->peer, uc->dbid, uc->first_blocknum);
	channel->state = CHANNELD_AWAITING_LOCKIN;
	channel->funder = uc->fc ? LOCAL : REMOTE;
	tal_free(channel->log);
	channel->log = tal_steal(channel, uc->log);
	channel->channel_flags = channel_flags;
	channel->our_config = uc->our_config;
	channel->minimum_depth = uc->minimum_depth;
	channel->next_index[LOCAL] = channel->next_index[REMOTE] = 1;
	channel->next_htlc_id = 0;
	channel->funding_txid = tal_dup(channel, struct bitcoin_txid,
					funding_txid);
	channel->funding_outnum = funding_outnum;
	channel->funding_satoshi = funding_satoshi;
	channel->push_msat = push_msat;
	channel->remote_funding_locked = false;
	channel->scid = NULL;

	channel->our_msatoshi = tal(channel, u64);
	if (channel->funder == LOCAL)
		*channel->our_msatoshi
			= channel->funding_satoshi * 1000 - channel->push_msat;
	else
		*channel->our_msatoshi = channel->push_msat;

	channel->last_tx = tal_steal(channel, remote_commit);
	channel->last_sig = tal_dup(channel, secp256k1_ecdsa_signature,
				    remote_commit_sig);
	channel->last_htlc_sigs = NULL;

	channel->channel_info = tal_dup(channel, struct channel_info,
					channel_info);

	/* Feerates begin identical. */
	channel->channel_info->feerate_per_kw[LOCAL]
		= channel->channel_info->feerate_per_kw[REMOTE]
		= feerate;

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel->channel_info->old_remote_per_commit
		= channel->channel_info->remote_per_commit;

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void opening_funder_finished(struct subd *openingd, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	tal_t *tmpctx = tal_tmpctx(fc);
	u8 *msg;
	struct channel_info channel_info;
	struct bitcoin_tx *fundingtx;
	struct bitcoin_txid funding_txid, expected_txid;
	struct pubkey changekey;
	struct pubkey local_fundingkey;
	struct crypto_state cs;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u16 funding_outnum;
	u64 gossip_index;
	u32 feerate;
	struct channel *channel;
	struct lightningd *ld = openingd->ld;

	assert(tal_count(fds) == 2);

	/* This is a new channel_info->their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_opening_funder_reply(resp, resp, NULL,
					   &channel_info.their_config,
					   &remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &gossip_index,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &fc->uc->minimum_depth,
					   &channel_info.remote_fundingkey,
					   &expected_txid,
					   &feerate)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		command_fail(fc->cmd, "bad OPENING_FUNDER_REPLY %s",
			     tal_hex(fc->cmd, resp));
		goto failed;
	}
	log_debug(ld->log,
		  "%s", type_to_string(ltmp, struct pubkey,
				       &channel_info.remote_per_commit));

	/* Generate the funding tx. */
	if (fc->change
	    && !bip32_pubkey(ld->wallet->bip32_base,
			     &changekey, fc->change_keyindex))
		fatal("Error deriving change key %u", fc->change_keyindex);

	derive_basepoints(&fc->uc->seed, &local_fundingkey, NULL, NULL, NULL);

	fundingtx = funding_tx(tmpctx, &funding_outnum,
			       fc->utxomap, fc->funding_satoshi,
			       &local_fundingkey,
			       &channel_info.remote_fundingkey,
			       fc->change, &changekey,
			       ld->wallet->bip32_base);

	log_debug(fc->uc->log, "Funding tx has %zi inputs, %zu outputs:",
		  tal_count(fundingtx->input),
		  tal_count(fundingtx->output));

	for (size_t i = 0; i < tal_count(fundingtx->input); i++) {
		log_debug(fc->uc->log, "%zi: %"PRIu64" satoshi (%s) %s\n",
			  i, fc->utxomap[i]->amount,
			  fc->utxomap[i]->is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(ltmp, struct bitcoin_txid,
					 &fundingtx->input[i].txid));
	}

	bitcoin_txid(fundingtx, &funding_txid);

	if (!structeq(&funding_txid, &expected_txid)) {
		log_broken(fc->uc->log,
			   "Funding txid mismatch:"
			   " satoshi %"PRIu64" change %"PRIu64
			   " changeidx %u"
			   " localkey %s remotekey %s",
			   fc->funding_satoshi,
			   fc->change, fc->change_keyindex,
			   type_to_string(fc, struct pubkey,
					  &local_fundingkey),
			   type_to_string(fc, struct pubkey,
					  &channel_info.remote_fundingkey));
		command_fail(fc->cmd,
			     "Funding txid mismatch:"
			     " satoshi %"PRIu64" change %"PRIu64
			     " changeidx %u"
			     " localkey %s remotekey %s",
			     fc->funding_satoshi,
			     fc->change, fc->change_keyindex,
			     type_to_string(fc, struct pubkey,
					    &local_fundingkey),
			     type_to_string(fc, struct pubkey,
					    &channel_info.remote_fundingkey));
		goto failed;
	}

	/* Steals fields from uc */
	channel = wallet_commit_channel(ld, fc->uc,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					fc->funding_satoshi,
					fc->push_msat,
					fc->channel_flags,
					&channel_info,
					feerate);

	/* Get HSM to sign the funding tx. */
	log_debug(channel->log, "Getting HSM to sign funding tx");

	msg = towire_hsm_sign_funding(tmpctx, channel->funding_satoshi,
				      fc->change, fc->change_keyindex,
				      &local_fundingkey,
				      &channel_info.remote_fundingkey,
				      fc->utxomap);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	tal_free(tmpctx);

	msg = hsm_sync_read(fc, ld);
	opening_got_hsm_funding_sig(channel, fc->cmd, fc->utxomap,
				    fds[0], fds[1], msg, &cs, gossip_index);

	subd_release_channel(openingd, fc->uc);
	/* Frees fc too */
	tal_free(fc->uc);
	return;

failed:
	close(fds[0]);
	close(fds[1]);
	subd_release_channel(openingd, fc->uc);
	/* Frees fc too */
	tal_free(fc->uc);
}

static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	u8 *funding_signed;
	struct channel_info channel_info;
	struct crypto_state cs;
	u64 gossip_index;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	const tal_t *tmpctx = tal_tmpctx(uc);
	struct lightningd *ld = openingd->ld;
	struct bitcoin_txid funding_txid;
	u16 funding_outnum;
	u64 funding_satoshi, push_msat;
	u32 feerate;
	u8 channel_flags;
	struct channel *channel;

	log_debug(uc->log, "Got opening_fundee_finish_response");
	assert(tal_count(fds) == 2);

	/* This is a new channel_info->their_config, set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_opening_fundee_reply(tmpctx, reply, NULL,
					   &channel_info.their_config,
					   &remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &gossip_index,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &channel_info.remote_fundingkey,
					   &funding_txid,
					   &funding_outnum,
					   &funding_satoshi,
					   &push_msat,
					   &channel_flags,
					   &feerate,
					   &funding_signed)) {
		log_broken(uc->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		tal_free(uc);
		return;
	}

	/* Consumes uc */
	channel = wallet_commit_channel(ld, uc,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					funding_satoshi,
					push_msat,
					channel_flags,
					&channel_info,
					feerate);

	log_debug(channel->log, "Watching funding tx %s",
		     type_to_string(reply, struct bitcoin_txid,
				    channel->funding_txid));
	watch_txid(channel, ld->topology, channel, channel->funding_txid,
		   funding_lockin_cb, NULL);

	/* FIXME: Remove arg from cb? */
	watch_txo(channel, ld->topology, channel, channel->funding_txid,
		  channel->funding_outnum, funding_spent, NULL);

	/* On to normal operation! */
	peer_start_channeld(channel, &cs, gossip_index,
			    fds[0], fds[1], funding_signed, false);

	subd_release_channel(openingd, uc);
	tal_free(uc);
}

/* Negotiation failed, but we can keep gossipping */
static unsigned int opening_negotiation_failed(struct subd *openingd,
					       const u8 *msg,
					       const int *fds)
{
	struct uncommitted_channel *uc = openingd->channel;
	struct crypto_state cs;
	u64 gossip_index;
	char *why;
	struct lightningd *ld = openingd->ld;

	/* We need the peer fd and gossip fd. */
	if (tal_count(fds) == 0)
		return 2;

	if (!fromwire_opening_negotiation_failed(msg, msg, NULL,
						 &cs, &gossip_index, &why)) {
		log_broken(uc->log, "bad OPENING_NEGOTIATION_FAILED %s",
			   tal_hex(msg, msg));
		tal_free(openingd);
		return 0;
	}

	uncommitted_channel_to_gossipd(ld, uc, NULL,
				       &cs, gossip_index,
				       fds[0], fds[1],
				       "%s", why);

	/* Don't call opening_channel_errmsg, just free openingd */
	subd_release_channel(openingd, uc);
	tal_free(uc);
	return 0;
}

/* errmsg == NULL for local if daemon died */
static void opening_channel_errmsg(struct uncommitted_channel *uc,
				   enum side sender,
				   const struct channel_id *channel_id,
				   const char *desc,
				   const u8 *errmsg)
{
	if (uc->fc)
		command_fail(uc->fc->cmd, "%sERROR %s",
			     sender == LOCAL ? (errmsg ? "sent " : "")
			     : "received ",
			     desc);

	log_info(uc->log, "%sERROR %s",
		 sender == LOCAL ? (errmsg ? "sent " : "") : "received ",
		 desc);
	tal_free(uc);
}

static void destroy_uncommitted_channel(struct uncommitted_channel *uc)
{
	uc->peer->uncommitted_channel = NULL;

	/* Last one out frees */
	if (list_empty(&uc->peer->channels))
		delete_peer(uc->peer);
}

/* Returns NULL if there's already an opening or active channel for this peer */
static struct uncommitted_channel *
new_uncommitted_channel(struct lightningd *ld,
			struct funding_channel *fc,
			const struct pubkey *peer_id,
			const struct wireaddr *addr)
{
	struct uncommitted_channel *uc = tal(ld, struct uncommitted_channel);
	char *idname;

	/* We make a new peer if necessary. */
	uc->peer = peer_by_id(ld, peer_id);
	if (!uc->peer)
		uc->peer = new_peer(ld, 0, peer_id, addr);

	if (uc->peer->uncommitted_channel)
		return tal_free(uc);

	if (peer_active_channel(uc->peer))
		return tal_free(uc);

	uc->dbid = wallet_get_channel_dbid(ld->wallet);

	idname = type_to_string(uc, struct pubkey, &uc->peer->id);
	uc->log = new_log(uc, uc->peer->log_book, "%s chan #%"PRIu64":",
			  idname, uc->dbid);
	tal_free(idname);

	uc->fc = fc;
	uc->first_blocknum = get_block_height(ld->topology);
	uc->our_config.id = 0;

	derive_channel_seed(ld, &uc->seed, &uc->peer->id, uc->dbid);
	uc->peer->uncommitted_channel = uc;
	tal_add_destructor(uc, destroy_uncommitted_channel);

	return uc;
}

/* Peer has spontaneously exited from gossip due to open msg.  Return
 * NULL if we took over, otherwise hand back to gossipd with this
 * error.
 */
static u8 *peer_accept_channel(struct lightningd *ld,
			       const struct pubkey *peer_id,
			       const struct wireaddr *addr,
			       const struct crypto_state *cs,
			       u64 gossip_index,
			       const u8 *gfeatures, const u8 *lfeatures,
			       int peer_fd, int gossip_fd,
			       const struct channel_id *channel_id,
			       const u8 *open_msg)
{
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;
	struct uncommitted_channel *uc;

	assert(fromwire_peektype(open_msg) == WIRE_OPEN_CHANNEL);

	/* Fails if there's already one */
	uc = new_uncommitted_channel(ld, NULL, peer_id, addr);
	if (!uc)
		return towire_errorfmt(open_msg, channel_id,
				       "Multiple channels unsupported");

	uc->openingd = new_channel_subd(ld, "lightning_openingd", uc, uc->log,
					opening_wire_type_name,
					opening_negotiation_failed,
					opening_channel_errmsg,
					take(&peer_fd), take(&gossip_fd),
					NULL);
	if (!uc->openingd) {
		uncommitted_channel_to_gossipd(ld, uc, channel_id,
					       cs, gossip_index,
					       peer_fd, gossip_fd,
					       "Failed to subdaemon opening: %s",
					       strerror(errno));
		tal_free(uc);
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The sender SHOULD set `minimum_depth` to a number of blocks it
	 * considers reasonable to avoid double-spending of the funding
	 * transaction.
	 */
	uc->minimum_depth = ld->config.anchor_confirms;

	channel_config(ld, &uc->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	msg = towire_opening_init(uc, get_chainparams(ld)->index,
				  &uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, gossip_index, &uc->seed);

	subd_send_msg(uc->openingd, take(msg));

	/* BOLT #2:
	 *
	 * Given the variance in fees, and the fact that the transaction may
	 * be spent in the future, it's a good idea for the fee payer to keep
	 * a good margin, say 5x the expected fee requirement */
	msg = towire_opening_fundee(uc, uc->minimum_depth,
				    get_feerate(ld->topology, FEERATE_SLOW),
				    get_feerate(ld->topology, FEERATE_IMMEDIATE)
				    * 5,
				    open_msg);

	subd_req(uc, uc->openingd, take(msg), -1, 2,
		 opening_fundee_finished, uc);
	return NULL;
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

	fc->uc = new_uncommitted_channel(ld, fc, &fc->peerid, addr);

	/* We asked to release this peer, but another raced in?  Corner case,
	 * close this is easiest. */
	if (!fc->uc) {
		command_fail(fc->cmd, "Peer already active");
		close(peer_fd);
		close(gossip_fd);
		return;
	}

	/* Channel now owns fc; if it dies, we free fc. */
	tal_steal(fc->uc, fc);

	fc->uc->openingd = new_channel_subd(ld,
				    "lightning_openingd", fc->uc, fc->uc->log,
				    opening_wire_type_name,
				    opening_negotiation_failed,
				    opening_channel_errmsg,
				    take(&peer_fd), take(&gossip_fd),
				    NULL);
	if (!fc->uc->openingd) {
		uncommitted_channel_to_gossipd(ld, fc->uc, NULL,
					       cs, gossip_index,
					       peer_fd,  gossip_fd,
					       "Failed to launch openingd: %s",
					       strerror(errno));
		tal_free(fc->uc);
		return;
	}

	channel_config(ld, &fc->uc->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	msg = towire_opening_init(fc,
				  get_chainparams(ld)->index,
				  &fc->uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, gossip_index, &fc->uc->seed);
	subd_send_msg(fc->uc->openingd, take(msg));

	msg = towire_opening_funder(fc, fc->funding_satoshi,
				    fc->push_msat,
				    get_feerate(ld->topology, FEERATE_NORMAL),
				    max_minimum_depth,
				    fc->change, fc->change_keyindex,
				    fc->channel_flags,
				    fc->utxomap,
				    ld->wallet->bip32_base);

	subd_req(fc, fc->uc->openingd,
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
	struct channel *c;
	struct uncommitted_channel *uc;

	c = active_channel_by_id(ld, &fc->peerid, &uc);

	if (!fromwire_gossipctl_release_peer_reply(fc, resp, NULL, &addr, &cs,
						   &gossip_index,
						   &gfeatures, &lfeatures)) {
		if (!fromwire_gossipctl_release_peer_replyfail(resp, NULL)) {
			fatal("Gossip daemon gave invalid reply %s",
			      tal_hex(gossip, resp));
		}
 		if (uc)
			command_fail(fc->cmd, "Peer already OPENING");
		else if (c)
			command_fail(fc->cmd, "Peer already %s",
				     channel_state_name(c));
		else
			command_fail(fc->cmd, "Peer not connected");
		return;
	}
	assert(tal_count(fds) == 2);

	/* Gossipd should guarantee peer is unique: we would have killed any
	 * old connection when it was told us peer reconnected. */
	assert(!c);
	assert(!uc);

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

	if (!json_get_params(cmd, buffer, params,
			     "id", &peertok,
			     "satoshi", &satoshitok,
			     NULL)) {
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
	fc->channel_flags = OUR_CHANNEL_FLAGS;

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
	"Fund channel with {id} using {satoshi} satoshis"
};
AUTODATA(json_command, &fund_channel_command);

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
			log_info(uc->log, "close command called");

			/* Close openingd. */
			subd_release_channel(uc->openingd, uc);
			if (uc->fc)
				command_fail(uc->fc->cmd,
					     "close command called");
			tal_free(uc);
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
		assert(channel->funding_txid);

		/* This may be unnecessary, but it's harmless. */
		watch_txid(channel, ld->topology, channel, channel->funding_txid,
			   funding_lockin_cb, NULL);

		watch_txo(channel, ld->topology, channel,
			  channel->funding_txid, channel->funding_outnum,
			  funding_spent, NULL);
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
	if (!channel->last_tx) {
		command_fail(cmd, "Peer has no final transaction");
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
	json_add_txid(response, "funding_txid", forget->channel->funding_txid);
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

	if (!forget->channel->funding_txid) {
		process_dev_forget_channel(cmd->ld->topology->bitcoind, NULL, forget);
	} else {
		bitcoind_gettxout(cmd->ld->topology->bitcoind,
				  forget->channel->funding_txid,
				  forget->channel->funding_outnum,
				  process_dev_forget_channel, forget);
		command_still_pending(cmd);
	}
}

static const struct json_command dev_forget_channel_command = {
	"dev-forget-channel", json_dev_forget_channel,
	"Forget the channel with peer {id}, ignore UTXO check with {force}='true'.", false,
	"Forget the channel with peer {id}. Checks if the channel is still active by checking its funding transaction. Check can be ignored by setting {force} to 'true'"
};
AUTODATA(json_command, &dev_forget_channel_command);
#endif /* DEVELOPER */
