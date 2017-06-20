#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <daemon/chaintopology.h>
#include <daemon/dns.h>
#include <daemon/invoice.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <daemon/timeout.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/build_utxos.h>
#include <lightningd/channel.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/funding_tx.h>
#include <lightningd/gen_peer_state_names.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/key_derive.h>
#include <lightningd/new_connection.h>
#include <lightningd/opening/gen_opening_wire.h>
#include <lightningd/pay.h>
#include <lightningd/sphinx.h>
#include <netinet/in.h>
#include <overflows.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <wally_bip32.h>
#include <wire/gen_onion_wire.h>
#include <wire/gen_peer_wire.h>

/* FIXME: Define serialization primitive for this? */
struct channel_info {
	secp256k1_ecdsa_signature commit_sig;
	struct channel_config their_config;
	struct pubkey remote_fundingkey;
	struct basepoints theirbase;
	struct pubkey their_per_commit_point;
};

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
	if (peer->fd >= 0)
		close(peer->fd);
	if (peer->gossip_client_fd >= 0)
		close(peer->gossip_client_fd);
}

static struct peer *peer_by_pubkey(struct lightningd *ld, const struct pubkey *id)
{
	struct peer *peer;
	list_for_each(&ld->peers, peer, list) {
		if (pubkey_cmp(id, &peer->id) == 0)
			return peer;
	}
	return NULL;
}

/* Mutual recursion, sets timer. */
static void peer_reconnect(struct peer *peer);

static void reconnect_failed(struct lightningd_state *dstate,
			     struct connection *c)
{
	/* Figure out what peer, set reconnect timer. */
	struct lightningd *ld = ld_from_dstate(dstate);
	struct peer *peer = peer_by_pubkey(ld, connection_known_id(c));

	tal_free(c);
	peer_reconnect(peer);
}

static void try_reconnect(struct peer *peer)
{
	struct connection *c;
	struct netaddr *addrs;

	/* We may already be reconnected (another incoming connection) */
	if (peer->fd != -1) {
		log_debug(peer->log, "try_reconnect: already reconnected");
		return;
	}

	c = new_connection(peer, peer->ld, NULL, &peer->id);

	/* FIXME: Combine known address with gossip addresses and possibly
	 * DNS seed addresses. */
	addrs = tal_dup_arr(c, struct netaddr, &peer->netaddr, 1, 0);
	multiaddress_connect(&peer->ld->dstate, addrs,
			     connection_out, reconnect_failed, c);
}

static void peer_reconnect(struct peer *peer)
{
	new_reltimer(&peer->ld->dstate.timers,
		     peer, peer->ld->dstate.config.poll_time,
		     try_reconnect, peer);
}

void peer_fail(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_info(peer->log, "Peer failure in %s: ",
		 peer_state_name(peer->state));
	logv_add(peer->log, fmt, ap);
	va_end(ap);

	/* If we haven't reached awaiting locked, we don't need to reconnect */
	if (!peer_persists(peer)) {
		log_info(peer->log, "Only reached state %s: forgetting",
			 peer_state_name(peer->state));
		goto dont_talk;
	}

	/* Reconnect unless we've dropped to chain. */
	if (!peer_on_chain(peer)) {
		peer_reconnect(peer);
		return;
	}

dont_talk:
	/* In case we reconnected in the meantime. */
	if (peer->fd != -1) {
		/* FIXME: We should retransmit error if this happens. */
		close(peer->fd);
	}
	tal_free(peer);
	return;
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
}

static bool peer_start_channeld_hsmfd(struct subd *hsm, const u8 *resp,
				      const int *fds,
				      struct peer *peer);

/* Returns true if we consider this a reconnection. */
static bool peer_reconnected(struct lightningd *ld,
			     const struct pubkey *id,
			     int fd,
			     const struct crypto_state *cs)
{
	struct peer *peer = peer_by_id(ld, id);
	if (!peer)
		return false;

	log_info(peer->log, "Peer has reconnected, state %s",
		 peer_state_name(peer->state));

	/* Always copy cryptostate; at worst we'll throw it away. */
	tal_free(peer->cs);
	peer->cs = tal_dup(peer, struct crypto_state, cs);

	/* FIXME: We should close peer->gossip_client_fd when we're not
	 * connected, and get a new one from gossipd when we reconnect. */

	switch (peer->state) {
	/* This can't happen. */
	case UNINITIALIZED:
		abort();

	case GOSSIPD:
		/* Tell gossipd to kick that one out, will call peer_fail */
		subd_send_msg(peer->ld->gossip,
			      take(towire_gossipctl_fail_peer(peer,
							      peer->unique_id)));
		tal_free(peer);
		/* Continue with a new peer. */
		return false;

	case OPENINGD:
		/* Kill off openingd, forget old peer. */
		peer->owner->peer = NULL;
		tal_free(peer->owner);
		tal_free(peer);

		/* A fresh start. */
		return false;

	case GETTING_SIG_FROM_HSM:
		/* BOLT #2:
		 *
		 * On disconnection, the funder MUST remember the channel for
		 * reconnection if it has broadcast the funding transaction,
		 * otherwise it MUST NOT.
		 */
		/* Free peer, which will discard HSM response. */
		tal_free(peer);

		/* Start afresh */
		return false;

	case GETTING_HSMFD:
		/* Simply substitute old fd for new one. */
		assert(peer->fd != -1);
		close(peer->fd);
		peer->fd = fd;
		return true;

	case CHANNELD_AWAITING_LOCKIN:
		/* Kill off current channeld, if any. */
		if (peer->owner) {
			peer->owner->peer = NULL;
			peer->owner = tal_free(peer->owner);
		}
		assert(peer->fd == -1);
		peer->fd = fd;

		/* Start a new one: first get fresh hsm fd. */
		peer_set_condition(peer, CHANNELD_AWAITING_LOCKIN,
				   GETTING_HSMFD);

		/* Get fd from hsm. */
		subd_req(peer, peer->ld->hsm,
			 take(towire_hsmctl_hsmfd_channeld(peer,
							   peer->unique_id)),
			 -1, 1, peer_start_channeld_hsmfd, peer);
		return true;

	case CHANNELD_NORMAL:
		/* Kill off current channeld, if any */
		if (peer->owner) {
			peer->owner->peer = NULL;
			peer->owner = tal_free(peer->owner);
		}

		assert(peer->fd == -1);
		peer->fd = fd;

		/* Start a new one: first get fresh hsm fd. */
		peer_set_condition(peer, CHANNELD_NORMAL, GETTING_HSMFD);

		/* FIXME: Needs to reload state! */
		/* Get fd from hsm. */
		subd_req(peer, peer->ld->hsm,
			 take(towire_hsmctl_hsmfd_channeld(peer,
							   peer->unique_id)),
			 -1, 1, peer_start_channeld_hsmfd, peer);
		return true;

	case SHUTDOWND_SENT:
	case SHUTDOWND_RCVD:
	case CLOSINGD_SIGEXCHANGE:
	case ONCHAIND_CHEATED:
	case ONCHAIND_THEIR_UNILATERAL:
	case ONCHAIND_OUR_UNILATERAL:
	case ONCHAIND_MUTUAL:
		; /* FIXME: Implement! */
	}
	abort();
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

void add_peer(struct lightningd *ld, u64 unique_id,
	      int fd, const struct pubkey *id,
	      const struct crypto_state *cs)
{
	struct peer *peer;
	const char *netname, *idname;
	u8 *msg;

	/* It's a reconnect? */
	if (peer_reconnected(ld, id, fd, cs))
		return;

	/* Fresh peer. */
	peer = tal(ld, struct peer);
	peer->ld = ld;
	peer->unique_id = unique_id;
	peer->owner = NULL;
	peer->scid = NULL;
	peer->id = *id;
	peer->fd = fd;
	peer->gossip_client_fd = -1;
	peer->cs = tal_dup(peer, struct crypto_state, cs);
	peer->funding_txid = NULL;
	peer->seed = NULL;
	peer->balance = NULL;
	peer->state = UNINITIALIZED;
	peer->channel_info = NULL;

	idname = type_to_string(peer, struct pubkey, id);

	/* Max 128k per peer. */
	peer->log_book = new_log_book(peer, 128*1024,
				      get_log_level(ld->dstate.log_book));
	peer->log = new_log(peer, peer->log_book, "peer %s:", idname);
	set_log_outfn(peer->log_book, copy_to_parent_log, peer);

	/* FIXME: Don't assume protocol here! */
	if (!netaddr_from_fd(peer->fd, SOCK_STREAM, IPPROTO_TCP,
			     &peer->netaddr)) {
		log_unusual(ld->log, "Failed to get netaddr for outgoing: %s",
			    strerror(errno));
		tal_free(peer);
		return;
	}
	netname = netaddr_name(idname, &peer->netaddr);
	log_info(peer->log, "Connected from %s", netname);
	tal_free(idname);
	list_add_tail(&ld->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);

	/* Let gossip handle it from here. */
	peer->owner = peer->ld->gossip;
	tal_steal(peer->owner, peer);
	peer_set_condition(peer, UNINITIALIZED, GOSSIPD);

	msg = towire_gossipctl_new_peer(peer, peer->unique_id, peer->cs);
	subd_send_msg(peer->ld->gossip, take(msg));
	subd_send_fd(peer->ld->gossip, peer->fd);

	/* Peer struct longer owns fd. */
	peer->fd = -1;
	peer->cs = tal_free(peer->cs);
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
		if (pubkey_eq(&p->id, id))
			return p;
	return NULL;
}

/* When a per-peer subdaemon exits, see if we need to do anything. */
static void peer_owner_finished(struct subd *subd, int status)
{
	/* If peer has moved on, do nothing. */
	if (subd->peer->owner != subd) {
		log_debug(subd->ld->log, "Subdaemon %s died (%i), peer moved",
			  subd->name, status);
		return;
	}

	subd->peer->owner = NULL;
	peer_fail(subd->peer, "Owning subdaemon %s died (%i)",
		  subd->name, status);
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
			io_new_listener(ld, fd1, connection_in, ld);
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
			io_new_listener(ld, fd2, connection_in, ld);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address on port %u",
		      ld->dstate.portnum);
}

static void connect_failed(struct lightningd_state *dstate,
			   struct connection *c)
{
	tal_free(c);
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct connection *c;
	jsmntok_t *host, *porttok, *idtok;
	const tal_t *tmpctx = tal_tmpctx(cmd);
	struct pubkey id;
	char *name, *port;

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &porttok,
			     "id", &idtok,
			     NULL)) {
		command_fail(cmd, "Need host, port and id to connect");
		return;
	}

	if (!pubkey_from_hexstr(buffer + idtok->start,
				idtok->end - idtok->start, &id)) {
		command_fail(cmd, "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	c = new_connection(cmd, ld, cmd, &id);
	name = tal_strndup(tmpctx,
			   buffer + host->start, host->end - host->start);
	port = tal_strndup(tmpctx,
			   buffer + porttok->start,
			   porttok->end - porttok->start);
	if (!dns_resolve_and_connect(cmd->dstate, name, port,
				     connection_out, connect_failed, c)) {
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
		json_add_string(response, "state", peer_state_name(p->state));
		json_add_string(response, "netaddr",
				netaddr_name(response, &p->netaddr));
		json_add_pubkey(response, "peerid", &p->id);
		if (p->owner)
			json_add_string(response, "owner", p->owner->name);
		if (p->scid)
			json_add_short_channel_id(response, "channel", p->scid);
		if (p->balance) {
			json_add_u64(response, "msatoshi_to_us",
				     p->balance[LOCAL]);
			json_add_u64(response, "msatoshi_to_them",
				     p->balance[REMOTE]);
		}
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

struct peer *peer_from_json(struct lightningd *ld,
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

	/* Details we sent to openingd to create funding. */
	const struct utxo **utxomap;
	u64 change;
	u32 change_keyindex;

	/* Funding tx once we're ready to sign and send. */
	struct bitcoin_tx *funding_tx;
};

static void fail_fundchannel_command(struct funding_channel *fc)
{
	/* FIXME: More details? */
	command_fail(fc->cmd, "Peer died");
}

static void funding_broadcast_failed(struct peer *peer,
				     int exitstatus, const char *err)
{
	log_unusual(peer->log, "Funding broadcast exited with %i: %s",
		    exitstatus, err);
	/* FIXME: send PKT_ERR to peer if this happens. */
	tal_free(peer);
}

static enum watch_result funding_announce_cb(struct peer *peer,
					     unsigned int depth,
					     const struct sha256_double *txid,
					     void *unused)
{
	if (depth < ANNOUNCE_MIN_DEPTH) {
		return KEEP_WATCHING;
	}
	if (peer->state != CHANNELD_NORMAL || !peer->owner) {
		log_debug(peer->ld->log,
			  "Funding tx announce ready, but peer state %s %s",
			  peer_state_name(peer->state),
			  peer->owner ? peer->owner->name : "unowned");
		return KEEP_WATCHING;
	}
	subd_send_msg(peer->owner,
		      take(towire_channel_funding_announce_depth(peer)));
	return DELETE_WATCH;
}

static enum watch_result funding_lockin_cb(struct peer *peer,
					   unsigned int depth,
					   const struct sha256_double *txid,
					   void *unused)
{
	const char *txidstr = type_to_string(peer, struct sha256_double, txid);
	struct txlocator *loc;

	log_debug(peer->log, "Funding tx %s depth %u of %u",
		  txidstr, depth, peer->minimum_depth);
	tal_free(txidstr);

	if (depth < peer->minimum_depth)
		return KEEP_WATCHING;

	/* In theory, it could have been buried before we got back
	 * from accepting openingd or disconnected: just wait for next one. */
	if (!peer->owner || peer->state != CHANNELD_AWAITING_LOCKIN) {
		log_unusual(peer->log,
			    "Funding tx confirmed, but peer state %s %s",
			    peer_state_name(peer->state),
			    peer->owner ? peer->owner->name : "unowned");
		return KEEP_WATCHING;
	}

	loc = locate_tx(peer, peer->ld->topology, txid);

	peer->scid = tal(peer, struct short_channel_id);
	peer->scid->blocknum = loc->blkheight;
	peer->scid->txnum = loc->index;
	peer->scid->outnum = peer->funding_outnum;
	tal_free(loc);

	subd_send_msg(peer->owner,
		      take(towire_channel_funding_locked(peer, peer->scid)));

	/* BOLT #7:
	 *
	 * If sent, `announcement_signatures` messages MUST NOT be sent until
	 * `funding_locked` has been sent, and the funding transaction is has
	 * at least 6 confirmations.
	 */
	if (depth >= ANNOUNCE_MIN_DEPTH) {
		subd_send_msg(peer->owner,
			      take(towire_channel_funding_announce_depth(peer)));
	} else {
		watch_txid(peer, peer->ld->topology, peer, txid,
			   funding_announce_cb, NULL);
	}
	return DELETE_WATCH;
}

/* FIXME: Reshuffle. */
static void peer_start_channeld(struct peer *peer, enum peer_state oldstate,
				const u8 *funding_signed);

static bool opening_got_hsm_funding_sig(struct subd *hsm, const u8 *resp,
					const int *fds,
					struct funding_channel *fc)
{
	secp256k1_ecdsa_signature *sigs;
	struct bitcoin_tx *tx = fc->funding_tx;
	size_t i;

	if (!fromwire_hsmctl_sign_funding_reply(fc, resp, NULL, &sigs))
		fatal("HSM gave bad sign_funding_reply %s",
		      tal_hex(fc, resp));

	if (tal_count(sigs) != tal_count(tx->input))
		fatal("HSM gave %zu sigs, needed %zu",
		      tal_count(sigs), tal_count(tx->input));

	/* Create input parts from signatures. */
	for (i = 0; i < tal_count(tx->input); i++) {
		struct pubkey key;

		if (!bip32_pubkey(fc->peer->ld->bip32_base,
				  &key, fc->utxomap[i]->keyindex))
			fatal("Cannot generate BIP32 key for UTXO %u",
			      fc->utxomap[i]->keyindex);

		/* P2SH inputs have same witness. */
		tx->input[i].witness
			= bitcoin_witness_p2wpkh(tx, &sigs[i], &key);
	}

	/* Send it out and watch for confirms. */
	broadcast_tx(hsm->ld->topology, fc->peer, tx, funding_broadcast_failed);
	watch_tx(fc->peer, fc->peer->ld->topology, fc->peer, tx,
		 funding_lockin_cb, NULL);

	/* We could defer until after funding locked, but makes testing
	 * harder. */
	tal_del_destructor(fc, fail_fundchannel_command);
	command_success(fc->cmd, null_response(fc->cmd));

	/* Start normal channel daemon. */
	peer_start_channeld(fc->peer, GETTING_SIG_FROM_HSM, NULL);

	tal_free(fc);
	return true;
}

struct decoding_htlc {
	struct peer *peer;
	u64 id;
	u32 amount_msat;
	u32 cltv_expiry;
	struct sha256 payment_hash;
	u8 onion[TOTAL_PACKET_SIZE];
	struct secret shared_secret;
};

static void fail_htlc(struct peer *peer, struct htlc_end *hend, const u8 *msg)
{
	u8 *reply = wrap_onionreply(hend, hend->shared_secret, msg);
	subd_send_msg(peer->owner,
		      take(towire_channel_fail_htlc(peer, hend->htlc_id, reply)));
	if (taken(msg))
		tal_free(msg);
}

static void fail_local_htlc(struct peer *peer, struct htlc_end *hend, const u8 *msg)
{
	u8 *reply;
	enum onion_type failcode = fromwire_peektype(msg);
	log_broken(peer->log, "failed htlc %"PRIu64" code 0x%04x (%s)",
		   hend->htlc_id, failcode, onion_type_name(failcode));

	reply = create_onionreply(hend, hend->shared_secret, msg);
	fail_htlc(peer, hend, reply);
}

static u8 *make_failmsg(const tal_t *ctx, const struct htlc_end *hend,
			enum onion_type failcode)
{
	struct sha256 *onion_sha = NULL;
	u8 *channel_update = NULL;

	if (failcode & BADONION) {
		/* FIXME: need htlc_end->sha? */
	}
	if (failcode & UPDATE) {
		/* FIXME: Ask gossip daemon for channel_update. */
	}

	switch (failcode) {
	case WIRE_INVALID_REALM:
		return towire_invalid_realm(ctx);
	case WIRE_TEMPORARY_NODE_FAILURE:
		return towire_temporary_node_failure(ctx);
	case WIRE_PERMANENT_NODE_FAILURE:
		return towire_permanent_node_failure(ctx);
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
		return towire_required_node_feature_missing(ctx);
	case WIRE_INVALID_ONION_VERSION:
		return towire_invalid_onion_version(ctx, onion_sha);
	case WIRE_INVALID_ONION_HMAC:
		return towire_invalid_onion_hmac(ctx, onion_sha);
	case WIRE_INVALID_ONION_KEY:
		return towire_invalid_onion_key(ctx, onion_sha);
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		return towire_temporary_channel_failure(ctx, channel_update);
	case WIRE_CHANNEL_DISABLED:
		return towire_channel_disabled(ctx);
	case WIRE_PERMANENT_CHANNEL_FAILURE:
		return towire_permanent_channel_failure(ctx);
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		return towire_required_channel_feature_missing(ctx);
	case WIRE_UNKNOWN_NEXT_PEER:
		return towire_unknown_next_peer(ctx);
	case WIRE_AMOUNT_BELOW_MINIMUM:
		return towire_amount_below_minimum(ctx, hend->msatoshis, channel_update);
	case WIRE_FEE_INSUFFICIENT:
		return towire_fee_insufficient(ctx, hend->msatoshis, channel_update);
	case WIRE_INCORRECT_CLTV_EXPIRY:
		/* FIXME: ctlv! */
		return towire_incorrect_cltv_expiry(ctx, 0, channel_update);
	case WIRE_EXPIRY_TOO_SOON:
		return towire_expiry_too_soon(ctx, channel_update);
	case WIRE_UNKNOWN_PAYMENT_HASH:
		return towire_unknown_payment_hash(ctx);
	case WIRE_INCORRECT_PAYMENT_AMOUNT:
		return towire_incorrect_payment_amount(ctx);
	case WIRE_FINAL_EXPIRY_TOO_SOON:
		return towire_final_expiry_too_soon(ctx);
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		/* FIXME: ctlv! */
		return towire_final_incorrect_cltv_expiry(ctx, 0);
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		return towire_final_incorrect_htlc_amount(ctx, hend->msatoshis);
	}
	abort();
}

/* BOLT #4:
 *
 * * `amt_to_forward` - The amount in milli-satoshi to forward to the next
 *    (outgoing) hop specified within the routing information.
 *
 *    This value MUST factor in the computed fee for this particular hop. When
 *    processing an incoming Sphinx packet along with the HTLC message it's
 *    encapsulated within, if the following inequality doesn't hold, then the
 *    HTLC should be rejected as it indicates a prior node in the path has
 *    deviated from the specified parameters:
 *
 *       incoming_htlc_amt - fee >= amt_to_forward
 *
 *    Where `fee` is calculated according to the receiving node's advertised fee
 *    schema as described in [BOLT 7](https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#htlc-fees), or 0 if this node is the
 *    final hop.
 */
static bool check_amount(struct htlc_end *hend,
			 u64 amt_to_forward, u64 amt_in_htlc, u64 fee)
{
	if (amt_in_htlc - fee >= amt_to_forward)
		return true;
	log_debug(hend->peer->ld->log, "HTLC %"PRIu64" incorrect amount:"
		  " %"PRIu64" in, %"PRIu64" out, fee reqd %"PRIu64,
		  hend->htlc_id, amt_in_htlc, amt_to_forward, fee);
	return false;
}

/* BOLT #4:
 *
 *  * `outgoing_cltv_value` - The CLTV value that the _outgoing_ HTLC carrying
 *     the packet should have.
 *
 *        cltv_expiry - cltv_expiry_delta = outgoing_cltv_value
 *
 *     Inclusion of this field allows a node to both authenticate the information
 *     specified by the original sender and the parameters of the HTLC forwarded,
 *	 and ensure the original sender is using the current `cltv_expiry_delta`  value.
 *     If there is no next hop, `cltv_expiry_delta` is zero.
 *     If the values don't correspond, then the HTLC should be failed+rejected as
 *     this indicates the incoming node has tampered with the intended HTLC
 *     values, or the origin has an obsolete `cltv_expiry_delta` value.
 *     The node MUST be consistent in responding to an unexpected
 *     `outgoing_cltv_value` whether it is the final hop or not, to avoid
 *     leaking that information.
 */
static bool check_ctlv(struct htlc_end *hend,
		       u32 ctlv_expiry, u32 outgoing_cltv_value, u32 delta)
{
	if (ctlv_expiry - delta == outgoing_cltv_value)
		return true;
	log_debug(hend->peer->ld->log, "HTLC %"PRIu64" incorrect CLTV:"
		  " %u in, %u out, delta reqd %u",
		  hend->htlc_id, ctlv_expiry, outgoing_cltv_value, delta);
	return false;
}

static void fulfill_htlc(struct htlc_end *hend, const struct preimage *preimage)
{
	u8 *msg;

	hend->peer->balance[LOCAL] += hend->msatoshis;
	hend->peer->balance[REMOTE] -= hend->msatoshis;

	/* FIXME: fail the peer if it doesn't tell us that htlc fulfill is
	 * committed before deadline.
	 */
	msg = towire_channel_fulfill_htlc(hend->peer, hend->htlc_id, preimage);
	subd_send_msg(hend->peer->owner, take(msg));
}

static void handle_localpay(struct htlc_end *hend,
			    u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    u64 amt_to_forward,
			    u32 outgoing_cltv_value)
{
	u8 *err;
	struct invoice *invoice;

	/* BOLT #4:
	 *
	 * If the `amt_to_forward` is higher than `incoming_htlc_amt` of
	 * the HTLC at the final hop:
	 *
	 * 1. type: 19 (`final_incorrect_htlc_amount`)
	 * 2. data:
	 *    * [`4`:`incoming_htlc_amt`]
	 */
	if (!check_amount(hend, amt_to_forward, hend->msatoshis, 0)) {
		err = towire_final_incorrect_htlc_amount(hend, hend->msatoshis);
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the `outgoing_cltv_value` does not match the `ctlv_expiry` of
	 * the HTLC at the final hop:
	 *
	 * 1. type: 18 (`final_incorrect_cltv_expiry`)
	 * 2. data:
	 *   * [`4`:`cltv_expiry`]
	 */
	if (!check_ctlv(hend, cltv_expiry, outgoing_cltv_value, 0)) {
		err = towire_final_incorrect_cltv_expiry(hend, cltv_expiry);
		goto fail;
	}

	invoice = find_unpaid(hend->peer->ld->dstate.invoices, payment_hash);
	if (!invoice) {
		err = towire_unknown_payment_hash(hend);
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the amount paid is less than the amount expected, the final node
	 * MUST fail the HTLC.  If the amount paid is more than twice the
	 * amount expected, the final node SHOULD fail the HTLC.  This allows
	 * the sender to reduce information leakage by altering the amount,
	 * without allowing accidental gross overpayment:
	 *
	 * 1. type: PERM|16 (`incorrect_payment_amount`)
	 */
	if (hend->msatoshis < invoice->msatoshi) {
		err = towire_incorrect_payment_amount(hend);
		goto fail;
	} else if (hend->msatoshis > invoice->msatoshi * 2) {
		err = towire_incorrect_payment_amount(hend);
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the `cltv_expiry` is too low, the final node MUST fail the HTLC:
	 */
	if (get_block_height(hend->peer->ld->topology)
	    + hend->peer->ld->dstate.config.deadline_blocks >= cltv_expiry) {
		log_debug(hend->peer->log,
			  "Expiry cltv %u too close to current %u + deadline %u",
			  cltv_expiry,
			  get_block_height(hend->peer->ld->topology),
			  hend->peer->ld->dstate.config.deadline_blocks);
		err = towire_final_expiry_too_soon(hend);
		goto fail;
	}

	connect_htlc_end(&hend->peer->ld->htlc_ends, hend);

	log_info(hend->peer->ld->log, "Resolving invoice '%s' with HTLC %"PRIu64,
		 invoice->label, hend->htlc_id);
	fulfill_htlc(hend, &invoice->r);
	resolve_invoice(&hend->peer->ld->dstate, invoice);
	return;

fail:
	fail_local_htlc(hend->peer, hend, take(err));
	tal_free(hend);
}

/*
 * A catchall in case outgoing peer disconnects before getting fwd.
 *
 * We could queue this and wait for it to come back, but this is simple.
 */
static void hend_subd_died(struct htlc_end *hend)
{
	/* FIXME: Ask gossip daemon for channel_update. */
	u8 *channel_update = NULL;
	u8 *failmsg = towire_temporary_channel_failure(hend->other_end,
						       channel_update);
	u8 *msg = towire_channel_fail_htlc(hend->other_end,
					   hend->other_end->htlc_id,
					   failmsg);
	log_debug(hend->other_end->peer->owner->log,
		  "Failing HTLC %"PRIu64" due to peer death",
		  hend->other_end->htlc_id);
	subd_send_msg(hend->other_end->peer->owner, take(msg));
	tal_free(failmsg);
}

static bool rcvd_htlc_reply(struct subd *subd, const u8 *msg, const int *fds,
			    struct htlc_end *hend)
{
	u16 failure_code;
	u8 *failurestr;

	if (!fromwire_channel_offer_htlc_reply(msg, msg, NULL,
					       &hend->htlc_id,
					       &failure_code,
					       &failurestr)) {
		log_broken(subd->log, "Bad channel_offer_htlc_reply");
		tal_free(hend);
		return false;
	}

	if (failure_code) {
		log_debug(hend->other_end->peer->owner->log,
			  "HTLC failed from other daemon: %s (%.*s)",
			  onion_type_name(failure_code),
			  (int)tal_len(failurestr), (char *)failurestr);

		msg = make_failmsg(msg, hend->other_end, failure_code);
		subd_send_msg(hend->other_end->peer->owner, take(msg));
		tal_free(hend);
		return true;
	}

	tal_del_destructor(hend, hend_subd_died);

	/* Add it to lookup table. */
	connect_htlc_end(&hend->peer->ld->htlc_ends, hend);
	return true;
}

static void forward_htlc(struct htlc_end *hend,
			 u32 cltv_expiry,
			 const struct sha256 *payment_hash,
			 u64 amt_to_forward,
			 u32 outgoing_cltv_value,
			 const struct pubkey *next_hop,
			 const u8 next_onion[TOTAL_PACKET_SIZE])
{
	u8 *err, *msg;
	u64 fee;
	struct lightningd *ld = hend->peer->ld;
	struct peer *next = peer_by_pubkey(ld, next_hop);

	if (!next) {
		err = towire_unknown_next_peer(hend);
		goto fail;
	}

	if (!peer_can_add_htlc(next)) {
		log_info(next->log, "Attempt to forward HTLC but not ready");
		err = towire_unknown_next_peer(hend);
		goto fail;
	}

	/* BOLT #7:
	 *
	 * The node creating `channel_update` SHOULD accept HTLCs which pay a
	 * fee equal or greater than:
	 *
	 *    fee_base_msat + amount_msat * fee_proportional_millionths / 1000000
	 */
	if (mul_overflows_u64(amt_to_forward,
			      ld->dstate.config.fee_per_satoshi)) {
		/* FIXME: Add channel update */
		err = towire_fee_insufficient(hend, hend->msatoshis, NULL);
		goto fail;
	}
	fee = ld->dstate.config.fee_base
		+ amt_to_forward * ld->dstate.config.fee_per_satoshi / 1000000;
	if (!check_amount(hend, amt_to_forward, hend->msatoshis, fee)) {
		/* FIXME: Add channel update */
		err = towire_fee_insufficient(hend, hend->msatoshis, NULL);
		goto fail;
	}

	if (!check_ctlv(hend, cltv_expiry, outgoing_cltv_value,
			ld->dstate.config.deadline_blocks)) {
		/* FIXME: Add channel update */
		err = towire_incorrect_cltv_expiry(hend, cltv_expiry, NULL);
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the ctlv-expiry is too near, we tell them the the current channel
	 * setting for the outgoing channel:
	 * 1. type: UPDATE|14 (`expiry_too_soon`)
	 * 2. data:
	 *    * [`2`:`len`]
	 *    * [`len`:`channel_update`]
	 */
	if (get_block_height(next->ld->topology)
	    + next->ld->dstate.config.deadline_blocks >= outgoing_cltv_value) {
		log_debug(hend->peer->log,
			  "Expiry cltv %u too close to current %u + deadline %u",
			  outgoing_cltv_value,
			  get_block_height(next->ld->topology),
			  next->ld->dstate.config.deadline_blocks);
		/* FIXME: Add channel update */
		err = towire_expiry_too_soon(hend, NULL);
		goto fail;
	}

	/* Make sure daemon owns it, in case it fails. */
	hend->other_end = tal(next->owner, struct htlc_end);
	hend->other_end->which_end = HTLC_DST;
	hend->other_end->peer = next;
	hend->other_end->other_end = hend;
	hend->other_end->pay_command = NULL;
	hend->other_end->msatoshis = amt_to_forward;
	tal_add_destructor(hend->other_end, hend_subd_died);

	msg = towire_channel_offer_htlc(next, amt_to_forward,
					outgoing_cltv_value,
					payment_hash, next_onion);
	subd_req(next->owner, next->owner, take(msg), -1, 0,
		 rcvd_htlc_reply, hend->other_end);
	return;

fail:
	fail_local_htlc(hend->peer, hend, take(err));
	tal_free(hend);
}

/* We received a resolver reply, which gives us the node_ids of the
 * channel we want to forward over */
static bool channel_resolve_reply(struct subd *gossip, const u8 *msg,
				  const int *fds, struct htlc_end *hend)
{
	struct pubkey *nodes, *peer_id;

	if (!fromwire_gossip_resolve_channel_reply(msg, msg, NULL, &nodes)) {
		log_broken(gossip->log,
			   "bad fromwire_gossip_resolve_channel_reply %s",
			   tal_hex(msg, msg));
		return false;
	}

	if (tal_count(nodes) == 0) {
		fail_htlc(hend->peer, hend,
			  take(towire_unknown_next_peer(hend)));
		tal_free(hend);
		return true;
	} else if (tal_count(nodes) != 2) {
		log_broken(gossip->log,
			   "fromwire_gossip_resolve_channel_reply has %zu nodes",
			   tal_count(nodes));
		return false;
	}

	/* Get the other peer matching the id that is not us */
	if (pubkey_cmp(&nodes[0], &gossip->ld->dstate.id) == 0) {
		peer_id = &nodes[1];
	} else {
		peer_id = &nodes[0];
	}

	forward_htlc(hend, hend->cltv_expiry, &hend->payment_hash,
		     hend->amt_to_forward, hend->outgoing_cltv_value, peer_id,
		     hend->next_onion);
	/* FIXME(cdecker) Cleanup things we stuffed into hend before (maybe?) */
	return true;
}

static int peer_accepted_htlc(struct peer *peer, const u8 *msg)
{
	bool forward;
	struct htlc_end *hend;
	u8 *req;

	hend = tal(msg, struct htlc_end);
	hend->shared_secret = tal(hend, struct secret);
	if (!fromwire_channel_accepted_htlc(msg, NULL,
					    &hend->htlc_id, &hend->msatoshis,
					    &hend->cltv_expiry, &hend->payment_hash,
					    hend->next_onion, &forward,
					    &hend->amt_to_forward,
					    &hend->outgoing_cltv_value,
					    &hend->next_channel,
					    hend->shared_secret)) {
		log_broken(peer->log, "bad fromwire_channel_accepted_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	tal_steal(peer, hend);
	hend->which_end = HTLC_SRC;
	hend->peer = peer;
	hend->other_end = NULL;
	hend->pay_command = NULL;

	if (forward) {
		req = towire_gossip_resolve_channel_request(msg, &hend->next_channel);
		log_broken(peer->log, "Asking gossip to resolve channel %d/%d/%d", hend->next_channel.blocknum, hend->next_channel.txnum, hend->next_channel.outnum);
		subd_req(hend, peer->ld->gossip, req, -1, 0, channel_resolve_reply, hend);
		/* FIXME(cdecker) Stuff all this info into hend */
	} else
		handle_localpay(hend, hend->cltv_expiry, &hend->payment_hash,
				hend->amt_to_forward, hend->outgoing_cltv_value);
	return 0;
}

static int peer_fulfilled_htlc(struct peer *peer, const u8 *msg)
{
	u64 id;
	struct preimage preimage;
	struct htlc_end *hend;

	if (!fromwire_channel_fulfilled_htlc(msg, NULL, &id, &preimage)) {
		log_broken(peer->log, "bad fromwire_channel_fulfilled_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	hend = find_htlc_end(&peer->ld->htlc_ends, peer, id, HTLC_DST);
	if (!hend) {
		log_broken(peer->log,
			   "channel_fulfilled_htlc unknown htlc %"PRIu64,
			   id);
		return -1;
	}

	/* They fulfilled our HTLC.  Credit them, forward as required. */
	peer->balance[REMOTE] += hend->msatoshis;
	peer->balance[LOCAL] -= hend->msatoshis;

	if (hend->other_end)
		fulfill_htlc(hend->other_end, &preimage);
	else
		payment_succeeded(peer->ld, hend, &preimage);
	tal_free(hend);

	return 0;
}

static int peer_failed_htlc(struct peer *peer, const u8 *msg)
{
	u64 id;
	u8 *reason;
	struct htlc_end *hend;
	enum onion_type failcode;
	struct onionreply *reply;

	if (!fromwire_channel_failed_htlc(msg, msg, NULL, &id, &reason)) {
		log_broken(peer->log, "bad fromwire_channel_failed_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	hend = find_htlc_end(&peer->ld->htlc_ends, peer, id, HTLC_DST);
	if (!hend) {
		log_broken(peer->log,
			   "channel_failed_htlc unknown htlc %"PRIu64,
			   id);
		return -1;
	}

	if (hend->other_end) {
		fail_htlc(hend->other_end->peer, hend->other_end,
			  reason);
	} else {
		size_t numhops = tal_count(hend->path_secrets);
		struct secret *shared_secrets = tal_arr(hend, struct secret, numhops);
		for (size_t i=0; i<numhops; i++) {
			shared_secrets[i] = hend->path_secrets[i];
		}
		reply = unwrap_onionreply(msg, shared_secrets, numhops, reason);
		if (!reply) {
			log_info(peer->log, "htlc %"PRIu64" failed with bad reply (%s)",
				 id, tal_hex(msg, msg));
			failcode = WIRE_PERMANENT_NODE_FAILURE;
		} else {
			failcode = fromwire_peektype(reply->msg);
			log_info(peer->log, "htlc %"PRIu64" failed with code 0x%04x (%s)",
				 id, failcode, onion_type_name(failcode));
		}
		payment_failed(peer->ld, hend, NULL, failcode);
	}
	tal_free(hend);

	return 0;
}

/* FIXME: Encrypt! */
static u8 *malformed_msg(const tal_t *ctx, enum onion_type type,
			 const struct sha256 *sha256_of_onion)
{
	u8 *channel_update;

	/* FIXME: check the reported SHA matches what we sent! */
	switch (type) {
	case WIRE_INVALID_ONION_VERSION:
		return towire_invalid_onion_version(ctx, sha256_of_onion);
	case WIRE_INVALID_ONION_HMAC:
		return towire_invalid_onion_hmac(ctx, sha256_of_onion);
	case WIRE_INVALID_ONION_KEY:
		return towire_invalid_onion_key(ctx, sha256_of_onion);
	default:
		/* FIXME: Ask gossip daemon for channel_update. */
		channel_update = NULL;
		return towire_temporary_channel_failure(ctx, channel_update);
	}
}

static int peer_failed_malformed_htlc(struct peer *peer, const u8 *msg)
{
	u64 id;
	struct htlc_end *hend;
	struct sha256 sha256_of_onion;
	u16 failcode;

	if (!fromwire_channel_malformed_htlc(msg, NULL, &id,
					     &sha256_of_onion, &failcode)) {
		log_broken(peer->log, "bad fromwire_channel_malformed_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	hend = find_htlc_end(&peer->ld->htlc_ends, peer, id, HTLC_DST);
	if (!hend) {
		log_broken(peer->log,
			   "channel_malformed_htlc unknown htlc %"PRIu64,
			   id);
		return -1;
	}

	if (hend->other_end) {
		/* Not really a local failure, but since the failing
		 * peer could not derive its shared secret it cannot
		 * create a valid HMAC, so we do it on his behalf */
		fail_local_htlc(hend->other_end->peer, hend->other_end,
			  malformed_msg(msg, failcode, &sha256_of_onion));
	} else {
		payment_failed(peer->ld, hend, NULL, failcode);
	}
	tal_free(hend);

	return 0;
}

/* Create a node_announcement with the given signature. It may be NULL
 * in the case we need to create a provisional announcement for the
 * HSM to sign. */
static u8 *create_node_announcement(const tal_t *ctx, struct lightningd *ld,
				    secp256k1_ecdsa_signature *sig)
{
	u32 timestamp = time_now().ts.tv_sec;
	u8 rgb[3] = {0x77, 0x88, 0x99};
	u8 alias[32];
	u8 *features = NULL;
	u8 *addresses = tal_arr(ctx, u8, 0);
	u8 *announcement;
	if (!sig) {
		sig = tal(ctx, secp256k1_ecdsa_signature);
		memset(sig, 0, sizeof(*sig));
	}
	if (ld->dstate.config.ipaddr.type != ADDR_TYPE_PADDING) {
		towire_ipaddr(&addresses, &ld->dstate.config.ipaddr);
	}
	memset(alias, 0, sizeof(alias));
	announcement =
	    towire_node_announcement(ctx, sig, timestamp, &ld->dstate.id, rgb,
				     alias, features, addresses);
	return announcement;
}

/* We got the signature for out provisional node_announcement back
 * from the HSM, create the real announcement and forward it to
 * gossipd so it can take care of forwarding it. */
static bool send_node_announcement_got_sig(struct subd *hsm, const u8 *msg,
					   const int *fds,
					   struct lightningd *ld)
{
	tal_t *tmpctx = tal_tmpctx(hsm);
	secp256k1_ecdsa_signature sig;
	u8 *announcement, *wrappedmsg;
	if (!fromwire_hsmctl_node_announcement_sig_reply(msg, NULL, &sig)) {
		log_debug(ld->log,
			  "HSM returned an invalid node_announcement sig");
		return false;
	}
	announcement = create_node_announcement(tmpctx, ld, &sig);
	wrappedmsg = towire_gossip_forwarded_msg(tmpctx, announcement);
	subd_send_msg(ld->gossip, take(wrappedmsg));
	tal_free(tmpctx);
	return true;
}

/* We were informed by channeld that it announced the channel and sent
 * an update, so we can now start sending a node_announcement. The
 * first step is to build the provisional announcement and ask the HSM
 * to sign it. */
static void peer_channel_announced(struct peer *peer, const u8 *msg)
{
	struct lightningd *ld = peer->ld;
	tal_t *tmpctx = tal_tmpctx(ld);
	u8 *req;
	req = towire_hsmctl_node_announcement_sig_req(
		tmpctx, create_node_announcement(tmpctx, ld, NULL));
	subd_req(ld, ld->hsm, take(req), -1, 0,
		 send_node_announcement_got_sig, ld);
	tal_free(tmpctx);
}

static int channel_msg(struct subd *sd, const u8 *msg, const int *unused)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_NORMAL_OPERATION:
		peer_set_condition(sd->peer,
				   CHANNELD_AWAITING_LOCKIN, CHANNELD_NORMAL);
		break;
	case WIRE_CHANNEL_ACCEPTED_HTLC:
		return peer_accepted_htlc(sd->peer, msg);
	case WIRE_CHANNEL_FULFILLED_HTLC:
		return peer_fulfilled_htlc(sd->peer, msg);
	case WIRE_CHANNEL_FAILED_HTLC:
		return peer_failed_htlc(sd->peer, msg);
	case WIRE_CHANNEL_MALFORMED_HTLC:
		return peer_failed_malformed_htlc(sd->peer, msg);
	case WIRE_CHANNEL_ANNOUNCED:
		peer_channel_announced(sd->peer, msg);
		break;

	/* We never see fatal ones. */
	case WIRE_CHANNEL_BAD_COMMAND:
	case WIRE_CHANNEL_HSM_FAILED:
	case WIRE_CHANNEL_CRYPTO_FAILED:
	case WIRE_CHANNEL_GOSSIP_BAD_MESSAGE:
	case WIRE_CHANNEL_INTERNAL_ERROR:
	case WIRE_CHANNEL_PEER_WRITE_FAILED:
	case WIRE_CHANNEL_PEER_READ_FAILED:
	case WIRE_CHANNEL_PEER_BAD_MESSAGE:
	/* And we never get these from channeld. */
	case WIRE_CHANNEL_INIT:
	case WIRE_CHANNEL_FUNDING_LOCKED:
	case WIRE_CHANNEL_FUNDING_ANNOUNCE_DEPTH:
	case WIRE_CHANNEL_OFFER_HTLC:
	case WIRE_CHANNEL_FULFILL_HTLC:
	case WIRE_CHANNEL_FAIL_HTLC:
	case WIRE_CHANNEL_PING:
	/* Replies go to requests. */
	case WIRE_CHANNEL_OFFER_HTLC_REPLY:
	case WIRE_CHANNEL_PING_REPLY:
		break;
	}

	return 0;
}

/* We've got fd from HSM for channeld */
static bool peer_start_channeld_hsmfd(struct subd *hsm, const u8 *resp,
				      const int *fds,
				      struct peer *peer)
{
	u8 *initmsg;
	const struct config *cfg = &peer->ld->dstate.config;

	peer->owner = new_subd(peer->ld, peer->ld,
			       "lightningd_channel", peer,
			       channel_wire_type_name,
			       channel_msg,
			       peer_owner_finished,
			       take(&peer->fd),
			       &peer->gossip_client_fd,
			       take(&fds[0]), NULL);
	if (!peer->owner) {
		log_unusual(peer->log, "Could not subdaemon channel: %s",
			    strerror(errno));
		peer_fail(peer, "Failed to subdaemon channel");
		return true;
	}

	log_debug(peer->log, "Waiting for funding confirmations");
	peer_set_condition(peer, GETTING_HSMFD, CHANNELD_AWAITING_LOCKIN);

	initmsg = towire_channel_init(peer,
				      peer->funding_txid,
				      peer->funding_outnum,
				      &peer->our_config,
				      &peer->channel_info->their_config,
				      &peer->channel_info->commit_sig,
				      peer->cs,
				      &peer->channel_info->remote_fundingkey,
				      &peer->channel_info->theirbase.revocation,
				      &peer->channel_info->theirbase.payment,
				      &peer->channel_info->theirbase.delayed_payment,
				      &peer->channel_info->their_per_commit_point,
				      peer->funder == LOCAL,
				      cfg->fee_base,
				      cfg->fee_per_satoshi,
				      peer->funding_satoshi,
				      peer->push_msat,
				      peer->seed,
				      &peer->ld->dstate.id,
				      &peer->id,
				      time_to_msec(cfg->commit_time),
				      cfg->deadline_blocks,
				      peer->funding_signed);

	/* Don't need this any more (we never re-transmit it) */
	peer->funding_signed = tal_free(peer->funding_signed);

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(peer->owner, take(initmsg));

	peer->fd = -1;
	peer->cs = tal_free(peer->cs);
	return true;
}

/* opening is done, start lightningd_channel for peer. */
static void peer_start_channeld(struct peer *peer, enum peer_state oldstate,
				const u8 *funding_signed)
{
	/* Unowned: back to being owned by main daemon. */
	peer->owner = NULL;
	tal_steal(peer->ld, peer);

	log_debug(peer->log, "Waiting for HSM file descriptor");

	/* Now we can consider balance set. */
	peer->balance = tal_arr(peer, u64, NUM_SIDES);
	peer->balance[peer->funder] = peer->funding_satoshi * 1000 - peer->push_msat;
	peer->balance[!peer->funder] = peer->push_msat;

	peer_set_condition(peer, oldstate, GETTING_HSMFD);

	/* Save this for when we get HSM fd. */
	peer->funding_signed = funding_signed;

	/* Get fd from hsm. */
	subd_req(peer, peer->ld->hsm,
		 take(towire_hsmctl_hsmfd_channeld(peer, peer->unique_id)),
		 -1, 1, peer_start_channeld_hsmfd, peer);
}

static bool opening_funder_finished(struct subd *opening, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	u8 *msg;
	struct channel_info *channel_info;
	struct utxo *utxos;
	struct sha256_double funding_txid;
	struct pubkey changekey;
	struct pubkey local_fundingkey;

	assert(tal_count(fds) == 1);
	fc->peer->fd = fds[0];
	fc->peer->cs = tal(fc->peer, struct crypto_state);

	/* At this point, we care about peer */
	fc->peer->channel_info = channel_info
		= tal(fc->peer, struct channel_info);

	if (!fromwire_opening_funder_reply(resp, NULL,
					   &channel_info->their_config,
					   &channel_info->commit_sig,
					   fc->peer->cs,
					   &channel_info->theirbase.revocation,
					   &channel_info->theirbase.payment,
					   &channel_info->theirbase.delayed_payment,
					   &channel_info->their_per_commit_point,
					   &fc->peer->minimum_depth,
					   &channel_info->remote_fundingkey,
					   &funding_txid)) {
		log_broken(fc->peer->log, "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		tal_free(fc->peer);
		return false;
	}

	/* Generate the funding tx. */
	if (fc->change
	    && !bip32_pubkey(fc->peer->ld->bip32_base,
			     &changekey, fc->change_keyindex))
		fatal("Error deriving change key %u", fc->change_keyindex);

	derive_basepoints(fc->peer->seed, &local_fundingkey,
			  NULL, NULL, NULL, NULL, 0);

	fc->funding_tx = funding_tx(fc, &fc->peer->funding_outnum,
				    fc->utxomap, fc->peer->funding_satoshi,
				    &local_fundingkey,
				    &channel_info->remote_fundingkey,
				    fc->change, &changekey,
				    fc->peer->ld->bip32_base);
	fc->peer->funding_txid = tal(fc->peer, struct sha256_double);
	bitcoin_txid(fc->funding_tx, fc->peer->funding_txid);

	if (!structeq(fc->peer->funding_txid, &funding_txid)) {
		peer_fail(fc->peer, "Funding txid mismatch:"
			  " satoshi %"PRIu64" change %"PRIu64" changeidx %u"
			  " localkey %s remotekey %s",
			  fc->peer->funding_satoshi,
			  fc->change, fc->change_keyindex,
			  type_to_string(fc, struct pubkey, &local_fundingkey),
			  type_to_string(fc, struct pubkey,
					 &channel_info->remote_fundingkey));
		return false;
	}

	/* Get HSM to sign the funding tx. */
	log_debug(fc->peer->log, "Getting HSM to sign funding tx");

	utxos = from_utxoptr_arr(fc, fc->utxomap);
	msg = towire_hsmctl_sign_funding(fc, fc->peer->funding_satoshi,
					 fc->change, fc->change_keyindex,
					 &local_fundingkey,
					 &channel_info->remote_fundingkey,
					 utxos);
	tal_free(utxos);

	fc->peer->owner = NULL;
	peer_set_condition(fc->peer, OPENINGD, GETTING_SIG_FROM_HSM);
	subd_req(fc, fc->peer->ld->hsm, take(msg), -1, 0,
		 opening_got_hsm_funding_sig, fc);

	/* Tell opening daemon to exit. */
	return false;
}

static bool opening_fundee_finished(struct subd *opening,
					   const u8 *reply,
					   const int *fds,
					   struct peer *peer)
{
	u8 *funding_signed;
	struct channel_info *channel_info;

	log_debug(peer->log, "Got opening_fundee_finish_response");
	assert(tal_count(fds) == 1);
	peer->fd = fds[0];
	peer->cs = tal(peer, struct crypto_state);

	/* At this point, we care about peer */
	peer->channel_info = channel_info = tal(peer, struct channel_info);

	peer->funding_txid = tal(peer, struct sha256_double);
	if (!fromwire_opening_fundee_reply(peer, reply, NULL,
					   &channel_info->their_config,
					   &channel_info->commit_sig,
					   peer->cs,
					   &channel_info->theirbase.revocation,
					   &channel_info->theirbase.payment,
					   &channel_info->theirbase.delayed_payment,
					   &channel_info->their_per_commit_point,
					   &channel_info->remote_fundingkey,
					   peer->funding_txid,
					   &peer->funding_outnum,
					   &peer->funding_satoshi,
					   &peer->push_msat,
					   &funding_signed)) {
		log_broken(peer->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		return false;
	}

	log_debug(peer->log, "Watching funding tx %s",
		     type_to_string(reply, struct sha256_double,
				    peer->funding_txid));
	watch_txid(peer, peer->ld->topology, peer, peer->funding_txid,
		   funding_lockin_cb, NULL);

	/* On to normal operation! */
	peer->owner = NULL;
	peer_start_channeld(peer, OPENINGD, funding_signed);

	/* Tell opening daemon to exit. */
	return false;
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
	 ours->to_self_delay = ld->dstate.config.locktime_blocks;

	 /* BOLT #2:
	  *
	  * It MUST fail the channel if `max_accepted_htlcs` is greater than
	  * 483.
	  */
	 ours->max_accepted_htlcs = 483;

	 /* This is filled in by lightningd_opening, for consistency. */
	 ours->channel_reserve_satoshis = 0;
};

/* Peer has spontaneously exited from gossip due to msg */
void peer_fundee_open(struct peer *peer, const u8 *from_peer)
{
	struct lightningd *ld = peer->ld;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;

	/* Note: gossipd handles unknown packets, so we don't have to worry
	 * about ignoring odd ones here. */
	if (fromwire_peektype(from_peer) != WIRE_OPEN_CHANNEL) {
		log_unusual(peer->log, "Strange message to exit gossip: %u",
			    fromwire_peektype(from_peer));
		peer_fail(peer, "Bad message during gossiping: %s",
			  tal_hex(peer, from_peer));
		return;
	}

	peer_set_condition(peer, GOSSIPD, OPENINGD);
	peer->owner = new_subd(ld, ld, "lightningd_opening", peer,
			       opening_wire_type_name,
			       NULL, peer_owner_finished,
			       take(&peer->fd), &peer->gossip_client_fd,
			       NULL);
	if (!peer->owner) {
		peer_fail(peer, "Failed to subdaemon opening: %s",
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
	peer->minimum_depth = ld->dstate.config.anchor_confirms;

	channel_config(ld, &peer->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	peer->seed = tal(peer, struct privkey);
	derive_peer_seed(ld, peer->seed, &peer->id);
	msg = towire_opening_init(peer, &peer->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  peer->cs, peer->seed);
	peer->cs = tal_free(peer->cs);

	subd_send_msg(peer->owner, take(msg));
	msg = towire_opening_fundee(peer, peer->minimum_depth,
				    7500, 150000, from_peer);

	/* Careful here!  Their message could push us overlength! */
	if (tal_len(msg) >= 65536) {
		peer_fail(peer, "Unacceptably long open_channel");
		return;
	}
	subd_req(peer, peer->owner, take(msg), -1, 1,
		 opening_fundee_finished, peer);
}

/* Peer has been released from gossip.  Start opening. */
static bool gossip_peer_released(struct subd *gossip,
				 const u8 *resp,
				 const int *fds,
				 struct funding_channel *fc)
{
	struct lightningd *ld = fc->peer->ld;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u64 id;
	u8 *msg;
	struct subd *opening;
	struct utxo *utxos;
	u8 *bip32_base;

	assert(tal_count(fds) == 2);
	fc->peer->fd = fds[0];
	fc->peer->cs = tal(fc, struct crypto_state);
	fc->peer->gossip_client_fd = fds[1];

	if (!fromwire_gossipctl_release_peer_reply(resp, NULL, &id, fc->peer->cs))
		fatal("Gossup daemon gave invalid reply %s",
		      tal_hex(gossip, resp));

	/* This is how gossipd handles a reconnect (gossipctl_fail_peer) racing
	 * with us trying to connect. */
	if (id != fc->peer->unique_id) {
		tal_del_destructor(fc, fail_fundchannel_command);
		command_fail(fc->cmd, "Peer reconnected, try again");
		close(fds[0]);
		close(fds[1]);
		return true;
	}

	peer_set_condition(fc->peer, GOSSIPD, OPENINGD);
	opening = new_subd(fc->peer->ld, ld,
			   "lightningd_opening", fc->peer,
			   opening_wire_type_name,
			   NULL, peer_owner_finished,
			   take(&fc->peer->fd),
			   &fc->peer->gossip_client_fd, NULL);
	if (!opening) {
		peer_fail(fc->peer, "Failed to subdaemon opening: %s",
			  strerror(errno));
		return true;
	}
	fc->peer->owner = opening;

	/* We will fund channel */
	fc->peer->funder = LOCAL;
	channel_config(ld, &fc->peer->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	fc->peer->seed = tal(fc->peer, struct privkey);
	derive_peer_seed(ld, fc->peer->seed, &fc->peer->id);
	msg = towire_opening_init(fc, &fc->peer->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  fc->peer->cs, fc->peer->seed);

	fc->peer->cs = tal_free(fc->peer->cs);

	subd_send_msg(opening, take(msg));

	utxos = from_utxoptr_arr(fc, fc->utxomap);
	bip32_base = tal_arr(fc, u8, BIP32_SERIALIZED_LEN);
	if (bip32_key_serialize(fc->peer->ld->bip32_base, BIP32_FLAG_KEY_PUBLIC,
				bip32_base, tal_len(bip32_base))
	    != WALLY_OK)
		fatal("Can't serialize bip32 public key");

	/* FIXME: Real feerate! */
	msg = towire_opening_funder(fc, fc->peer->funding_satoshi,
				    fc->peer->push_msat,
				    15000, max_minimum_depth,
				    fc->change, fc->change_keyindex,
				    utxos, bip32_base);
	subd_req(fc, opening, take(msg), -1, 1, opening_funder_finished, fc);
	return true;
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
	fc->peer = peer_from_json(ld, buffer, peertok);
	if (!fc->peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}
	if (fc->peer->owner != ld->gossip) {
		command_fail(cmd, "Peer not ready for connection");
		return;
	}

	if (!json_tok_u64(buffer, satoshitok, &fc->peer->funding_satoshi)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}

	/* FIXME: Support push_msat? */
	fc->peer->push_msat = 0;

	/* Try to do this now, so we know if insufficient funds. */
	/* FIXME: Feerate & dustlimit */
	fc->utxomap = build_utxos(fc, ld, fc->peer->funding_satoshi, 15000, 600,
				  &fc->change, &fc->change_keyindex);
	if (!fc->utxomap) {
		command_fail(cmd, "Cannot afford funding transaction");
		return;
	}

	msg = towire_gossipctl_release_peer(cmd, fc->peer->unique_id);

	/* Tie this fc lifetime (and hence utxo release) to the peer */
	tal_steal(fc->peer, fc);
	tal_add_destructor(fc, fail_fundchannel_command);
	subd_req(fc, ld->gossip, msg, -1, 2, gossip_peer_released, fc);
}

static const struct json_command fund_channel_command = {
	"fundchannel",
	json_fund_channel,
	"Fund channel with {id} using {satoshi} satoshis",
	"Returns once channel established"
};
AUTODATA(json_command, &fund_channel_command);

const char *peer_state_name(enum peer_state state)
{
	size_t i;

	for (i = 0; enum_peer_state_names[i].name; i++)
		if (enum_peer_state_names[i].v == state)
			return enum_peer_state_names[i].name;
	return "unknown";
}
