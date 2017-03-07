#include "lightningd.h"
#include "peer_control.h"
#include "subdaemon.h"
#include <bitcoin/tx.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <daemon/dns.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/build_utxos.h>
#include <lightningd/funding_tx.h>
#include <lightningd/gossip/gen_gossip_control_wire.h>
#include <lightningd/gossip/gen_gossip_status_wire.h>
#include <lightningd/handshake/gen_handshake_control_wire.h>
#include <lightningd/handshake/gen_handshake_status_wire.h>
#include <lightningd/hsm/gen_hsm_control_wire.h>
#include <lightningd/opening/gen_opening_control_wire.h>
#include <lightningd/opening/gen_opening_status_wire.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <wally_bip32.h>
#include <wire/gen_peer_wire.h>

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
	if (peer->fd >= 0)
		close(peer->fd);
	if (peer->connect_cmd)
		command_fail(peer->connect_cmd, "Failed after %s",
			     peer->condition);
}

static void bitcoin_pubkey(struct lightningd *ld,
			   struct pubkey *pubkey, u32 index)
{
	struct ext_key ext;

	assert(index < BIP32_INITIAL_HARDENED_CHILD);
	assert(index < ld->bip32_max_index);
	if (bip32_key_from_parent(ld->bip32_base, index,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK)
		fatal("BIP32 of %u failed", index);

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey->pubkey,
				       ext.pub_key, sizeof(ext.pub_key)))
		fatal("Parse of BIP32 child %u pubkey failed", index);
}

void peer_set_condition(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tal_free(peer->condition);
	peer->condition = tal_vfmt(peer, fmt, ap);
	va_end(ap);
	log_info(peer->log, "condition: %s", peer->condition);
}

static struct peer *new_peer(struct lightningd *ld,
			     struct io_conn *conn,
			     const char *in_or_out,
			     struct command *cmd)
{
	static u64 id_counter;
	struct peer *peer = tal(ld, struct peer);
	const char *netname;

	peer->ld = ld;
	peer->unique_id = id_counter++;
	peer->owner = NULL;
	peer->id = NULL;
	peer->fd = io_conn_fd(conn);
	peer->connect_cmd = cmd;
	/* Max 128k per peer. */
	peer->log_book = new_log_book(peer, 128*1024,
				      get_log_level(ld->dstate.log_book));
	peer->log = new_log(peer, peer->log_book,
			    "peer %"PRIu64":", peer->unique_id);

	/* FIXME: Don't assume protocol here! */
	if (!netaddr_from_fd(peer->fd, SOCK_STREAM, IPPROTO_TCP,
			     &peer->netaddr)) {
		log_unusual(ld->log, "Failed to get netaddr for outgoing: %s",
			    strerror(errno));
		return tal_free(peer);
	}
	netname = netaddr_name(peer, &peer->netaddr);
	peer->condition = tal_fmt(peer, "%s %s", in_or_out, netname);
	tal_free(netname);
	list_add_tail(&ld->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (p->unique_id == unique_id)
			return p;
	return NULL;
}

struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (pubkey_eq(p->id, id))
			return p;
	return NULL;
}

static void handshake_succeeded(struct subdaemon *hs, const u8 *msg,
				struct peer *peer)
{
	struct crypto_state cs;

	if (!peer->id) {
		struct pubkey id;

		if (!fromwire_handshake_responder_resp(msg, NULL, &id, &cs))
			goto err;
		peer->id = tal_dup(peer, struct pubkey, &id);
		log_info_struct(hs->log, "Peer in from %s",
				struct pubkey, peer->id);
	} else {
		if (!fromwire_handshake_initiator_resp(msg, NULL, &cs))
			goto err;
		log_info_struct(hs->log, "Peer out to %s",
				struct pubkey, peer->id);
	}

	/* FIXME: Look for peer duplicates! */

	/* Tell handshaked to exit. */
	subdaemon_req(peer->owner, take(towire_handshake_exit_req(msg)),
		      -1, NULL, NULL, NULL);

	peer->owner = peer->ld->gossip;
	tal_steal(peer->owner, peer);
	peer_set_condition(peer, "Beginning gossip");

	/* Tell gossip to handle it now. */
	msg = towire_gossipctl_new_peer(msg, peer->unique_id, &cs);
	subdaemon_req(peer->ld->gossip, msg, peer->fd, &peer->fd, NULL, NULL);

	/* Peer struct longer owns fd. */
	peer->fd = -1;

	return;

err:
	log_broken(hs->log, "Malformed resp: %s", tal_hex(peer, msg));
	close(peer->fd);
	tal_free(peer);
}

static void peer_got_handshake_hsmfd(struct subdaemon *hsm, const u8 *msg,
				     struct peer *peer)
{
	const u8 *req;

	if (!fromwire_hsmctl_hsmfd_fd_response(msg, NULL)) {
		log_unusual(peer->ld->log, "Malformed hsmfd response: %s",
			    tal_hex(peer, msg));
		goto error;
	}

	/* Give handshake daemon the hsm fd. */
	peer->owner = new_subdaemon(peer, peer->ld,
				    "lightningd_handshake",
				    handshake_status_wire_type_name,
				    handshake_control_wire_type_name,
				    NULL, NULL,
				    peer->hsmfd, peer->fd, -1);
	if (!peer->owner) {
		log_unusual(peer->ld->log, "Could not subdaemon handshake: %s",
			    strerror(errno));
		peer_set_condition(peer, "Failed to subdaemon handshake");
		goto error;
	}

	/* Peer struct longer owns fd. */
	peer->fd = -1;

	/* Now handshake owns peer: until it succeeds, peer vanishes
	 * when it does. */
	tal_steal(peer->owner, peer);

	if (peer->id) {
		req = towire_handshake_initiator_req(peer, &peer->ld->dstate.id,
						     peer->id);
		peer_set_condition(peer, "Starting handshake as initiator");
	} else {
		req = towire_handshake_responder_req(peer, &peer->ld->dstate.id);
		peer_set_condition(peer, "Starting handshake as responder");
	}

	/* Now hand peer request to the handshake daemon: hands it
	 * back on success */
	subdaemon_req(peer->owner, take(req), -1, &peer->fd,
		      handshake_succeeded, peer);
	return;

error:
	tal_free(peer);
}

/* FIXME: timeout handshake if taking too long? */
static struct io_plan *peer_in(struct io_conn *conn, struct lightningd *ld)
{
	struct peer *peer = new_peer(ld, conn, "Incoming from", NULL);

	if (!peer)
		return io_close(conn);

	/* Get HSM fd for this peer. */
	subdaemon_req(ld->hsm,
		      take(towire_hsmctl_hsmfd_ecdh(ld, peer->unique_id)),
		      -1, &peer->hsmfd, peer_got_handshake_hsmfd, peer);

	/* We don't need conn, we'll pass fd to handshaked. */
	return io_close_taken_fd(conn);
}

static int make_listen_fd(struct lightningd *ld,
			  int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(ld->log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			log_unusual(ld->log, "Failed setting socket reuse: %s",
				    strerror(errno));

		if (bind(fd, addr, len) != 0) {
			log_unusual(ld->log, "Failed to bind on %u socket: %s",
				    domain, strerror(errno));
			goto fail;
		}
	}

	if (listen(fd, 5) != 0) {
		log_unusual(ld->log, "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
		goto fail;
	}
	return fd;

fail:
	close_noerr(fd);
	return -1;
}

void setup_listeners(struct lightningd *ld)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;

	if (!ld->dstate.portnum) {
		log_debug(ld->log, "Zero portnum, not listening for incoming");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(ld->dstate.portnum);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(ld->dstate.portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(ld, AF_INET6, &addr6, sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(ld->log, "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
			fd1 = -1;
		} else {
			addr.sin_port = in6.sin6_port;
			assert(ld->dstate.portnum == ntohs(addr.sin_port));
			log_debug(ld->log, "Creating IPv6 listener on port %u",
				  ld->dstate.portnum);
			io_new_listener(ld, fd1, peer_in, ld);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(ld, AF_INET, &addr, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(ld->log, "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
			fd2 = -1;
		} else {
			assert(ld->dstate.portnum == ntohs(addr.sin_port));
			log_debug(ld->log, "Creating IPv4 listener on port %u",
				  ld->dstate.portnum);
			io_new_listener(ld, fd2, peer_in, ld);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address on port %u",
		      ld->dstate.portnum);
}

struct json_connecting {
	/* This owns us, so we're freed after command_fail or command_success */
	struct command *cmd;
	const char *name, *port;
	struct pubkey id;
};

/* FIXME: timeout handshake if taking too long? */
static struct io_plan *peer_out(struct io_conn *conn,
				struct lightningd_state *dstate,
				struct json_connecting *jc)
{
	struct lightningd *ld = ld_from_dstate(jc->cmd->dstate);
	struct peer *peer = new_peer(ld, conn, "Outgoing to", jc->cmd);

	if (!peer)
		return io_close(conn);

	/* We already know ID we're trying to reach. */
	peer->id = tal_dup(peer, struct pubkey, &jc->id);

	/* Get HSM fd for this peer. */
	subdaemon_req(ld->hsm,
		      take(towire_hsmctl_hsmfd_ecdh(ld, peer->unique_id)),
		      -1, &peer->hsmfd, peer_got_handshake_hsmfd, peer);

	/* We don't need conn, we'll pass fd to handshaked. */
	return io_close_taken_fd(conn);
}

static void connect_failed(struct lightningd_state *dstate,
			   struct json_connecting *connect)
{
	/* FIXME: Better diagnostics! */
	command_fail(connect->cmd, "Failed to connect to peer %s:%s",
		     connect->name, connect->port);
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_connecting *connect;
	jsmntok_t *host, *port, *idtok;
	const tal_t *tmpctx = tal_tmpctx(cmd);

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &port,
			     "id", &idtok,
			     NULL)) {
		command_fail(cmd, "Need host, port and id to connect");
		return;
	}

	connect = tal(cmd, struct json_connecting);
	connect->cmd = cmd;
	connect->name = tal_strndup(connect, buffer + host->start,
				    host->end - host->start);
	connect->port = tal_strndup(connect, buffer + port->start,
				    port->end - port->start);

	if (!pubkey_from_hexstr(buffer + idtok->start,
				idtok->end - idtok->start, &connect->id)) {
		command_fail(cmd, "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	if (!dns_resolve_and_connect(cmd->dstate, connect->name, connect->port,
				     peer_out, connect_failed, connect)) {
		command_fail(cmd, "DNS failed");
		return;
	}

	tal_free(tmpctx);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port} expecting node {id}",
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

static void json_getpeers(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct peer *p;
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *leveltok;
	struct log_info info;

	json_get_params(buffer, params, "?level", &leveltok, NULL);

	if (!leveltok)
		;
	else if (json_tok_streq(buffer, leveltok, "debug"))
		info.level = LOG_DBG;
	else if (json_tok_streq(buffer, leveltok, "info"))
		info.level = LOG_INFORM;
	else if (json_tok_streq(buffer, leveltok, "unusual"))
		info.level = LOG_UNUSUAL;
	else if (json_tok_streq(buffer, leveltok, "broken"))
		info.level = LOG_BROKEN;
	else {
		command_fail(cmd, "Invalid level param");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "peers");
	list_for_each(&ld->peers, p, list) {
		json_object_start(response, NULL);
		json_add_u64(response, "unique_id", p->unique_id);
		json_add_string(response, "condition", p->condition);
		json_add_string(response, "netaddr",
				netaddr_name(response, &p->netaddr));
		if (p->id)
			json_add_pubkey(response, "peerid", p->id);
		if (p->owner)
			json_add_string(response, "owner", p->owner->name);

		if (leveltok) {
			info.response = response;
			json_array_start(response, "log");
			log_each_line(p->log_book, log_to_json, &info);
			json_array_end(response);
		}
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getpeers_command = {
	"getpeers",
	json_getpeers,
	"List the current peers, if {level} is set, include {log}s",
	"Returns a 'peers' array"
};
AUTODATA(json_command, &getpeers_command);

static struct peer *find_peer_json(struct lightningd *ld,
				   const char *buffer,
				   jsmntok_t *peeridtok)
{
	struct pubkey peerid;

	if (!pubkey_from_hexstr(buffer + peeridtok->start,
				peeridtok->end - peeridtok->start, &peerid))
		return NULL;

	return peer_by_id(ld, &peerid);
}

struct funding_channel {
	struct peer *peer;
	struct command *cmd;
	u64 satoshi;
	const struct utxo **utxomap;
	u64 change;
	u32 change_keyindex;
	struct crypto_state *cs;

	struct pubkey local_fundingkey, remote_fundingkey;
	struct bitcoin_tx *funding_tx;
};

static void fail_fundchannel_command(struct funding_channel *fc)
{
	/* FIXME: More details? */
	command_fail(fc->cmd, "Peer died");
}

static void opening_got_hsm_funding_sig(struct subdaemon *hsm, const u8 *resp,
					struct funding_channel *fc)
{
	secp256k1_ecdsa_signature *sigs;

	if (!fromwire_hsmctl_sign_funding_response(fc, resp, NULL, &sigs))
		fatal("HSM gave bad sign_funding_response %s",
		      tal_hex(fc, resp));

	peer_set_condition(fc->peer, "Waiting for our funding tx");
	/* FIXME: Defer until after funding locked. */
	tal_del_destructor(fc, fail_fundchannel_command);
	command_success(fc->cmd, null_response(fc->cmd));
	fc->cmd = NULL;

	/* FIXME: broadcast tx... */
}

static void opening_release_tx(struct subdaemon *opening, const u8 *resp,
			       struct funding_channel *fc)
{
	u8 *msg;
	size_t i;
	/* FIXME: marshal code wants array, not array of pointers. */
	struct utxo *utxos = tal_arr(fc, struct utxo, tal_count(fc->utxomap));

	peer_set_condition(fc->peer, "Getting HSM to sign funding tx");

	/* Get HSM to sign the funding tx. */
	for (i = 0; i < tal_count(fc->utxomap); i++)
		utxos[i] = *fc->utxomap[i];

	msg = towire_hsmctl_sign_funding(fc, fc->satoshi, fc->change,
					 fc->change_keyindex,
					 &fc->local_fundingkey,
					 &fc->remote_fundingkey,
					 utxos);
	tal_free(utxos);
	subdaemon_req(fc->peer->ld->hsm, take(msg), -1, NULL,
		      opening_got_hsm_funding_sig, fc);
}

static void opening_gen_funding(struct subdaemon *opening, const u8 *resp,
				struct funding_channel *fc)
{
	u8 *msg;
	struct sha256_double txid;
	u32 outnum;
	struct pubkey changekey;

	peer_set_condition(fc->peer, "Created funding transaction for channel");
	if (!fromwire_opening_open_resp(resp, NULL,
					&fc->local_fundingkey,
					&fc->remote_fundingkey)) {
		log_broken(fc->peer->log, "Bad opening_open_resp %s",
			   tal_hex(fc, resp));
		tal_free(fc);
		return;
	}

	if (fc->change)
		bitcoin_pubkey(fc->peer->ld, &changekey, fc->change_keyindex);

	fc->funding_tx = funding_tx(fc, &outnum, fc->utxomap, fc->satoshi,
				    &fc->local_fundingkey,
				    &fc->remote_fundingkey,
				    fc->change, &changekey);
	bitcoin_txid(fc->funding_tx, &txid);

	msg = towire_opening_open_funding(fc, &txid, outnum);
	subdaemon_req(fc->peer->owner, take(msg), -1, &fc->peer->fd,
		      opening_release_tx, fc);
}

static void opening_accept_response(struct subdaemon *opening, const u8 *resp,
				    struct peer *peer)
{
	peer_set_condition(peer, "Waiting for their commitment tx");
	/* FIXME... */
}

static void channel_config(struct lightningd *ld,
			   struct channel_config *ours,
			   u32 *max_to_self_delay,
			   u32 *max_minimum_depth,
			   u64 *min_effective_htlc_capacity_msat)
{
	/* FIXME: depend on feerate. */
	*max_to_self_delay = ld->dstate.config.locktime_max;
	*max_minimum_depth = ld->dstate.config.anchor_confirms_max;
	/* This is 1c at $1000/BTC */
	*min_effective_htlc_capacity_msat = 1000000;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `dust-limit-satoshis` to a sufficient
	 * value to allow commitment transactions to propagate through
	 * the Bitcoin network.
	 */
	ours->dust_limit_satoshis = 546;
	ours->max_htlc_value_in_flight_msat = UINT64_MAX;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `minimum-depth` to an amount where
	 * the sender considers reorganizations to be low risk.
	 */
	ours->minimum_depth = ld->dstate.config.anchor_confirms;

	/* Don't care */
	ours->htlc_minimum_msat = 0;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `to-self-delay` sufficient to ensure
	 * the sender can irreversibly spend a commitment transaction
	 * output in case of misbehavior by the receiver.
	 */
	 ours->to_self_delay = ld->dstate.config.locktime_blocks;

	 /* Don't care. */
	 ours->max_accepted_htlcs = 511;

	 /* This is filled in by lightningd_opening, for consistency. */
	 ours->channel_reserve_satoshis = 0;
};

/* Peer has spontaneously exited from gossip due to msg */
void peer_accept_open(struct peer *peer,
		      const struct crypto_state *cs, const u8 *from_peer)
{
	struct lightningd *ld = peer->ld;
	struct privkey seed;
	struct channel_config ours;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;

	/* Note: gossipd handles unknown packets, so we don't have to worry
	 * about ignoring odd ones here. */
	if (fromwire_peektype(from_peer) != WIRE_OPEN_CHANNEL) {
		log_unusual(peer->log, "Strange message to exit gossip: %u",
			    fromwire_peektype(from_peer));
		peer_set_condition(peer, "Bad message during gossiping");
		tal_free(peer);
		return;
	}

	peer_set_condition(peer, "Starting opening daemon");
	peer->owner = new_subdaemon(peer, ld,
				    "lightningd_opening",
				    opening_status_wire_type_name,
				    opening_control_wire_type_name,
				    NULL, NULL,
				    peer->fd, -1);
	if (!peer->owner) {
		log_unusual(ld->log, "Could not subdaemon opening: %s",
			    strerror(errno));
		peer_set_condition(peer, "Failed to subdaemon opening");
		tal_free(peer);
		return;
	}
	tal_steal(peer->owner, peer);
	/* We handed off peer fd */
	peer->fd = -1;

	channel_config(ld, &ours,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	derive_peer_seed(ld, &seed, peer->id);
	msg = towire_opening_init(peer, &ours,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, &seed);

	subdaemon_req(peer->owner, take(msg), -1, NULL, NULL, NULL);
	/* FIXME: Real feerates! */
	msg = towire_opening_accept(peer, 7500, 150000, from_peer);

	/* Careful here!  Their message could push us overlength! */
	if (tal_len(msg) >= 65536) {
		peer_set_condition(peer, "Unacceptably long open_channel");
		tal_free(peer);
		return;
	}
	subdaemon_req(peer->owner, take(msg), -1, &peer->fd,
		      opening_accept_response, peer);
}

/* Peer has been released from gossip.  Start opening. */
static void gossip_peer_released(struct subdaemon *gossip,
				 const u8 *resp,
				 struct funding_channel *fc)
{
	struct lightningd *ld = fc->peer->ld;
	struct privkey seed;
	struct channel_config ours;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u64 id;
	u8 *msg;

	fc->cs = tal(fc, struct crypto_state);
	if (!fromwire_gossipctl_release_peer_response(resp, NULL, &id, fc->cs))
		fatal("Gossup daemon gave invalid response %s",
		      tal_hex(gossip, resp));

	if (id != fc->peer->unique_id)
		fatal("Gossup daemon release gave %"PRIu64" not %"PRIu64,
		      id, fc->peer->unique_id);

	peer_set_condition(fc->peer, "Starting opening daemon");
	fc->peer->owner = new_subdaemon(fc->peer, ld,
					"lightningd_opening",
					opening_status_wire_type_name,
					opening_control_wire_type_name,
					NULL, NULL,
					fc->peer->fd, -1);
	if (!fc->peer->owner) {
		log_unusual(ld->log, "Could not subdaemon opening: %s",
			    strerror(errno));
		peer_set_condition(fc->peer, "Failed to subdaemon opening");
		tal_free(fc);
		return;
	}
	/* They took our fd. */
	fc->peer->fd = -1;

	/* fc only lasts as long as this daemon does, for now. */
	tal_steal(fc->peer->owner, fc);

	channel_config(ld, &ours,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	derive_peer_seed(ld, &seed, fc->peer->id);
	msg = towire_opening_init(fc, &ours,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  fc->cs, &seed);

	subdaemon_req(fc->peer->owner, take(msg), -1, NULL, NULL, NULL);
	/* FIXME: Support push_msat? */
	/* FIXME: Real feerate! */
	msg = towire_opening_open(fc, fc->satoshi, 0, 15000, max_minimum_depth);
	subdaemon_req(fc->peer->owner, take(msg), -1, NULL,
		      opening_gen_funding, fc);
}

static void json_fund_channel(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	jsmntok_t *peertok, *satoshitok;
	struct funding_channel *fc = tal(cmd, struct funding_channel);
	u8 *msg;

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     "satoshi", &satoshitok,
			     NULL)) {
		command_fail(cmd, "Need peerid and satoshi");
		return;
	}

	fc->cmd = cmd;
	fc->peer = find_peer_json(ld, buffer, peertok);
	if (!fc->peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}
	if (fc->peer->owner != ld->gossip) {
		command_fail(cmd, "Peer not ready for connection");
		return;
	}

	if (!json_tok_u64(buffer, satoshitok, &fc->satoshi)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}

	/* Try to do this now, so we know if insufficient funds. */
	/* FIXME: Feerate & dustlimit */
	fc->utxomap = build_utxos(fc, ld, fc->satoshi, 15000, 600,
				  &fc->change, &fc->change_keyindex);
	if (!fc->utxomap) {
		command_fail(cmd, "Cannot afford funding transaction");
		return;
	}

	msg = towire_gossipctl_release_peer(cmd, fc->peer->unique_id);

	/* Tie this fc lifetime (and hence utxo release) to the peer */
	tal_steal(fc->peer, fc);
	tal_add_destructor(fc, fail_fundchannel_command);
	subdaemon_req(ld->gossip, msg, -1, &fc->peer->fd,
		      gossip_peer_released, fc);
}

static const struct json_command fund_channel_command = {
	"fundchannel",
	json_fund_channel,
	"Fund channel with {id} using {satoshi} satoshis",
	"Returns once channel established"
};
AUTODATA(json_command, &fund_channel_command);
