#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <daemon/chaintopology.h>
#include <daemon/dns.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <daemon/timeout.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/build_utxos.h>
#include <lightningd/channel.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/funding_tx.h>
#include <lightningd/gen_peer_state_names.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/hsm_control.h>
#include <lightningd/key_derive.h>
#include <lightningd/new_connection.h>
#include <lightningd/opening/gen_opening_wire.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/status.h>
#include <netinet/in.h>
#include <overflows.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/gen_onion_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
}

/* Mutual recursion, sets timer. */
static void peer_reconnect(struct peer *peer);

static void reconnect_failed(struct lightningd_state *dstate,
			     struct connection *c)
{
	/* Figure out what peer, set reconnect timer. */
	struct lightningd *ld = ld_from_dstate(dstate);
	struct peer *peer = peer_by_id(ld, connection_known_id(c));

	tal_free(c);
	peer_reconnect(peer);
}

static void try_reconnect(struct peer *peer)
{
	struct connection *c;
	struct netaddr *addrs;

	/* We may already be reconnected (another incoming connection) */
	if (peer->owner) {
		log_debug(peer->log, "try_reconnect: already reconnected (%s)",
			  peer->owner->name);
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

static void drop_to_chain(struct peer *peer)
{
	/* FIXME: Implement. */
}

void peer_fail_permanent(struct peer *peer, const u8 *msg)
{
	/* BOLT #1:
	 *
	 * The channel is referred to by `channel_id` unless `channel_id` is
	 * zero (ie. all bytes zero), in which case it refers to all
	 * channels. */
	static const struct channel_id all_channels;

	log_unusual(peer->log, "Peer permanent failure in %s: %.*s",
		    peer_state_name(peer->state),
		    (int)tal_len(msg), (char *)msg);
	peer->error = towire_error(peer, &all_channels, msg);
	peer->owner = NULL;
	if (taken(msg))
		tal_free(msg);

	if (peer_persists(peer))
		drop_to_chain(peer);
	else
		tal_free(peer);
	return;
}

void peer_internal_error(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_broken(peer->log, "Peer internal error %s: ",
		   peer_state_name(peer->state));
	logv_add(peer->log, fmt, ap);
	va_end(ap);

	peer_fail_permanent(peer,
			    take((u8 *)tal_strdup(peer, "Internal error")));
}

void peer_fail_transient(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_info(peer->log, "Peer transient failure in %s: ",
		 peer_state_name(peer->state));
	logv_add(peer->log, fmt, ap);
	va_end(ap);

	peer->owner = NULL;

	/* If we haven't reached awaiting locked, we don't need to reconnect */
	if (!peer_persists(peer)) {
		log_info(peer->log, "Only reached state %s: forgetting",
			 peer_state_name(peer->state));
		tal_free(peer);
		return;
	}

	/* Reconnect unless we've dropped to chain. */
	if (!peer_on_chain(peer)) {
		peer_reconnect(peer);
		return;
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

	/* FIXME: save to db */
	peer->state = state;
}

/* FIXME: Reshuffle. */
static bool peer_start_channeld(struct peer *peer,
				enum peer_state old_state,
				const struct crypto_state *cs,
				int peer_fd, int gossip_fd,
				const u8 *funding_signed);

/* Send (encrypted) error message, then close. */
static struct io_plan *send_error(struct io_conn *conn,
				  struct peer_crypto_state *pcs)
{
	return peer_write_message(conn, pcs, pcs->peer->error, (void *)io_close_cb);
}

struct getting_gossip_fd {
	struct pubkey id;
	int peer_fd;
	struct crypto_state cs;
};

static bool get_peer_gossipfd_reply(struct subd *subd, const u8 *msg,
				    const int *fds,
				    struct getting_gossip_fd *ggf)
{
	struct peer *peer;

	if (!fromwire_gossipctl_get_peer_gossipfd_reply(msg, NULL)) {
		if (!fromwire_gossipctl_get_peer_gossipfd_replyfail(msg, NULL))
			fatal("Gossipd gave bad get_peer_gossipfd reply %s",
			      tal_hex(subd, msg));

		log_unusual(subd->log, "Gossipd could not get fds for peer %s",
			    type_to_string(ggf, struct pubkey, &ggf->id));

		/* This is an internal error, but could be transient.
		 * Hang up and let them retry. */
		goto forget;
	}

	/* Make sure it still needs gossipfd! */
	peer = peer_by_id(subd->ld, &ggf->id);
	if (!peer) {
		log_unusual(subd->log, "Gossipd gave fd, but peer %s gone",
			    type_to_string(ggf, struct pubkey, &ggf->id));
		goto close_gossipfd;
	}

	if (peer->state != CHANNELD_AWAITING_LOCKIN
	    && peer->state != CHANNELD_NORMAL) {
		log_unusual(subd->log, "Gossipd gave fd, but peer %s %s",
			    type_to_string(ggf, struct pubkey, &ggf->id),
			    peer_state_name(peer->state));
		goto close_gossipfd;
	}

	/* Kill off current channeld, if any */
	if (peer->owner) {
		peer->owner->peer = NULL;
		peer->owner = tal_free(peer->owner);
	}

	/* We never re-transmit funding_signed. */
	peer_start_channeld(peer, peer->state, &ggf->cs, ggf->peer_fd, fds[0],
			    NULL);
	goto out;

close_gossipfd:
	close(fds[0]);

forget:
	close(ggf->peer_fd);
out:
	tal_free(ggf);
	return true;
}

static void get_gossip_fd_for_reconnect(struct lightningd *ld,
					const struct pubkey *id,
					u64 unique_id,
					int peer_fd,
					const struct crypto_state *cs)
{
	struct getting_gossip_fd *ggf = tal(ld, struct getting_gossip_fd);
	u8 *req;

	ggf->peer_fd = peer_fd;
	ggf->id = *id;
	ggf->cs = *cs;

	/* FIXME: set sync to `initial_routing_sync` */
	req = towire_gossipctl_get_peer_gossipfd(ggf, unique_id, true);
	subd_req(ggf, ld->gossip, take(req), -1, 1,
		 get_peer_gossipfd_reply, ggf);
}

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

	/* BOLT #2:
	 *
	 * On reconnection, if a channel is in an error state, the node SHOULD
	 * retransmit the error packet and ignore any other packets for that
	 * channel, and the following requirements do not apply. */
	if (peer->error) {
		struct peer_crypto_state *pcs = tal(peer, struct peer_crypto_state);
		init_peer_crypto_state(peer, pcs);
		pcs->cs = *cs;
		tal_steal(io_new_conn(peer, fd, send_error, pcs), pcs);
		return true;
	}

	/* We need this for init */
	peer->reconnected = true;

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

	case CHANNELD_AWAITING_LOCKIN:
	case CHANNELD_NORMAL:
	case CHANNELD_SHUTTING_DOWN:
		/* We need the gossipfd now */
		get_gossip_fd_for_reconnect(ld, id, peer->unique_id, fd, cs);
		return true;

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
	peer->error = NULL;
	peer->unique_id = unique_id;
	peer->id = *id;
	peer->reconnected = false;
	peer->funding_txid = NULL;
	peer->remote_funding_locked = false;
	peer->scid = NULL;
	peer->seed = NULL;
	peer->balance = NULL;
	peer->state = UNINITIALIZED;
	peer->channel_info = NULL;
	peer->last_was_revoke = false;
	peer->last_sent_commit = NULL;
	peer->remote_shutdown_scriptpubkey = NULL;
	peer->local_shutdown_idx = -1;
	peer->next_index[LOCAL]
		= peer->next_index[REMOTE]
		= peer->num_revocations_received = 0;
	peer->next_htlc_id = 0;
	shachain_init(&peer->their_shachain);

	idname = type_to_string(peer, struct pubkey, id);

	/* Max 128k per peer. */
	peer->log_book = new_log_book(peer, 128*1024,
				      get_log_level(ld->dstate.log_book));
	peer->log = new_log(peer, peer->log_book, "peer %s:", idname);
	set_log_outfn(peer->log_book, copy_to_parent_log, peer);

	/* FIXME: Don't assume protocol here! */
	if (!netaddr_from_fd(fd, SOCK_STREAM, IPPROTO_TCP, &peer->netaddr)) {
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
	peer_set_condition(peer, UNINITIALIZED, GOSSIPD);

	msg = towire_gossipctl_new_peer(peer, peer->unique_id, cs);
	subd_send_msg(peer->ld->gossip, take(msg));
	subd_send_fd(peer->ld->gossip, fd);
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

	/* Don't do a transient error if it's already perm failed. */
	if (!subd->peer->error)
		peer_fail_transient(subd->peer, "Owning subdaemon %s died (%i)",
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
			json_add_u64(response, "msatoshi_to_us", *p->balance);
			json_add_u64(response, "msatoshi_total",
				     p->funding_satoshi * 1000);
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
	bool peer_ready;

	log_debug(peer->log, "Funding tx %s depth %u of %u",
		  txidstr, depth, peer->minimum_depth);
	tal_free(txidstr);

	if (depth < peer->minimum_depth)
		return KEEP_WATCHING;

	loc = locate_tx(peer, peer->ld->topology, txid);

	peer->scid = tal(peer, struct short_channel_id);
	peer->scid->blocknum = loc->blkheight;
	peer->scid->txnum = loc->index;
	peer->scid->outnum = peer->funding_outnum;
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

	/* BOLT #7:
	 *
	 * If sent, `announcement_signatures` messages MUST NOT be sent until
	 * `funding_locked` has been sent, and the funding transaction is has
	 * at least 6 confirmations.
	 */
	if (depth >= ANNOUNCE_MIN_DEPTH && peer_ready) {
		subd_send_msg(peer->owner,
			      take(towire_channel_funding_announce_depth(peer)));
	} else {
		/* Worst case, we'll send next block. */
		watch_txid(peer, peer->ld->topology, peer, txid,
			   funding_announce_cb, NULL);
	}
	return DELETE_WATCH;
}

static void opening_got_hsm_funding_sig(struct funding_channel *fc,
					int peer_fd, int gossip_fd,
					const u8 *resp,
					const struct crypto_state *cs)
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
	broadcast_tx(fc->peer->ld->topology, fc->peer, tx, funding_broadcast_failed);
	watch_tx(fc->peer, fc->peer->ld->topology, fc->peer, tx,
		 funding_lockin_cb, NULL);

	/* We could defer until after funding locked, but makes testing
	 * harder. */
	tal_del_destructor(fc, fail_fundchannel_command);
	command_success(fc->cmd, null_response(fc->cmd));

	/* Start normal channel daemon. */
	peer_start_channeld(fc->peer, OPENINGD, cs, peer_fd, gossip_fd, NULL);

	wallet_confirm_utxos(fc->peer->ld->wallet, fc->utxomap);
	tal_free(fc);
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

/* We were informed by channeld that it announced the channel and sent
 * an update, so we can now start sending a node_announcement. The
 * first step is to build the provisional announcement and ask the HSM
 * to sign it. */
static int peer_channel_announced(struct peer *peer, const u8 *msg)
{
	struct lightningd *ld = peer->ld;
	tal_t *tmpctx = tal_tmpctx(peer);
	secp256k1_ecdsa_signature sig;
	u8 *announcement, *wrappedmsg;

	if (!fromwire_channel_announced(msg, NULL)) {
		peer_internal_error(peer, "bad fromwire_channel_announced %s",
				    tal_hex(peer, msg));
		return -1;
	}

	msg = towire_hsmctl_node_announcement_sig_req(
		tmpctx, create_node_announcement(tmpctx, ld, NULL));

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsmctl_node_announcement_sig_reply(msg, NULL, &sig))
		fatal("HSM returned an invalid node_announcement sig");

	/* We got the signature for out provisional node_announcement back
	 * from the HSM, create the real announcement and forward it to
	 * gossipd so it can take care of forwarding it. */
	announcement = create_node_announcement(tmpctx, ld, &sig);
	wrappedmsg = towire_gossip_forwarded_msg(tmpctx, announcement);
	subd_send_msg(ld->gossip, take(wrappedmsg));
	tal_free(tmpctx);

	return 0;
}

static int peer_got_funding_locked(struct peer *peer, const u8 *msg)
{
	struct pubkey next_per_commitment_point;

	if (!fromwire_channel_got_funding_locked(msg, NULL,
						 &next_per_commitment_point)) {
		log_broken(peer->log, "bad channel_got_funding_locked %s",
			   tal_hex(peer, msg));
		return -1;
	}

	if (peer->remote_funding_locked) {
		log_broken(peer->log, "channel_got_funding_locked twice");
		return -1;
	}
	update_per_commit_point(peer, &next_per_commitment_point);

	log_debug(peer->log, "Got funding_locked");
	peer->remote_funding_locked = true;
	return 0;
}

static u8 *p2wpkh_for_keyidx(const tal_t *ctx, struct lightningd *ld, u64 keyidx)
{
	struct pubkey shutdownkey;

	if (!bip32_pubkey(ld->bip32_base, &shutdownkey, keyidx))
		return NULL;

	return scriptpubkey_p2wpkh(ctx, &shutdownkey);
}

static int peer_got_shutdown(struct peer *peer, const u8 *msg)
{
	u8 *scriptpubkey;

	if (!fromwire_channel_got_shutdown(peer, msg, NULL, &scriptpubkey)) {
		log_broken(peer->log, "bad channel_got_shutdown %s",
			   tal_hex(peer, msg));
		return -1;
	}

	/* FIXME: Add to spec that we must allow repeated shutdown! */
	peer->remote_shutdown_scriptpubkey
		= tal_free(peer->remote_shutdown_scriptpubkey);
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
	if (!is_p2pkh(scriptpubkey) && !is_p2sh(scriptpubkey)
	    && !is_p2wpkh(scriptpubkey) && !is_p2wsh(scriptpubkey)) {
		u8 *msg = (u8 *)tal_fmt(peer, "Bad shutdown scriptpubkey %s",
					tal_hex(peer, scriptpubkey));
		peer_fail_permanent(peer, take(msg));
		return -1;
	}

	/* FIXME: Save to db */

	if (peer->local_shutdown_idx == -1) {
		u8 *scriptpubkey;

		peer->local_shutdown_idx = wallet_get_newindex(peer->ld);
		if (peer->local_shutdown_idx == -1) {
			peer_internal_error(peer,
					    "Can't get local shutdown index");
			return -1;
		}
		/* FIXME: Save to db */

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
			return -1;
		}

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

	return 0;
}

static int peer_got_bad_message(struct peer *peer, const u8 *msg)
{
	u8 *err;

	/* Don't try to fail this (again!) when owner dies. */
	peer->owner = NULL;
	if (!fromwire_channel_peer_bad_message(peer, NULL, NULL, &err))
		err = (u8 *)tal_strdup(peer, "Internal error after bad message");
	peer_fail_permanent(peer, take(err));

	/* Kill daemon (though it's dying anyway) */
	return -1;
}

static int channel_msg(struct subd *sd, const u8 *msg, const int *unused)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_NORMAL_OPERATION:
		peer_set_condition(sd->peer,
				   CHANNELD_AWAITING_LOCKIN, CHANNELD_NORMAL);
		break;
	case WIRE_CHANNEL_SENDING_COMMITSIG:
		return peer_sending_commitsig(sd->peer, msg);
	case WIRE_CHANNEL_GOT_COMMITSIG:
		return peer_got_commitsig(sd->peer, msg);
	case WIRE_CHANNEL_GOT_REVOKE:
		return peer_got_revoke(sd->peer, msg);
	case WIRE_CHANNEL_ANNOUNCED:
		return peer_channel_announced(sd->peer, msg);
	case WIRE_CHANNEL_GOT_FUNDING_LOCKED:
		return peer_got_funding_locked(sd->peer, msg);
	case WIRE_CHANNEL_GOT_SHUTDOWN:
		return peer_got_shutdown(sd->peer, msg);

	/* We let peer_owner_finished handle these as transient errors. */
	case WIRE_CHANNEL_BAD_COMMAND:
	case WIRE_CHANNEL_HSM_FAILED:
	case WIRE_CHANNEL_CRYPTO_FAILED:
	case WIRE_CHANNEL_GOSSIP_BAD_MESSAGE:
	case WIRE_CHANNEL_INTERNAL_ERROR:
	case WIRE_CHANNEL_PEER_WRITE_FAILED:
	case WIRE_CHANNEL_PEER_READ_FAILED:
		return -1;

	/* This is a permanent error. */
	case WIRE_CHANNEL_PEER_BAD_MESSAGE:
		return peer_got_bad_message(sd->peer, msg);

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
	/* Replies go to requests. */
	case WIRE_CHANNEL_OFFER_HTLC_REPLY:
	case WIRE_CHANNEL_PING_REPLY:
		break;
	}

	return 0;
}

static bool peer_start_channeld(struct peer *peer,
				enum peer_state old_state,
				const struct crypto_state *cs,
				int peer_fd, int gossip_fd,
				const u8 *funding_signed)
{
	const tal_t *tmpctx = tal_tmpctx(peer);
	u8 *msg, *initmsg;
	int hsmfd;
	const struct config *cfg = &peer->ld->dstate.config;
	struct added_htlc *htlcs;
	enum htlc_state *htlc_states;
	struct fulfilled_htlc *fulfilled_htlcs;
	enum side *fulfilled_sides;
	struct failed_htlc *failed_htlcs;
	enum side *failed_sides;
	struct short_channel_id funding_channel_id;
	const u8 *shutdown_scriptpubkey;

	/* Now we can consider balance set. */
	peer->balance = tal(peer, u64);
	if (peer->funder == LOCAL)
		*peer->balance = peer->funding_satoshi * 1000 - peer->push_msat;
	else
		*peer->balance = peer->push_msat;

	msg = towire_hsmctl_hsmfd_channeld(tmpctx, peer->unique_id);
	if (!wire_sync_write(peer->ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, peer->ld);
	if (!fromwire_hsmctl_hsmfd_channeld_reply(msg, NULL))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	hsmfd = fdpass_recv(peer->ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	peer->owner = new_subd(peer->ld, peer->ld,
			       "lightningd_channel", peer,
			       channel_wire_type_name,
			       channel_msg,
			       peer_owner_finished,
			       take(&peer_fd),
			       take(&gossip_fd),
			       take(&hsmfd), NULL);
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
		peer_set_condition(peer, old_state, CHANNELD_NORMAL);
	} else {
		log_debug(peer->log, "Waiting for funding confirmations");
		peer_set_condition(peer, old_state, CHANNELD_AWAITING_LOCKIN);
		memset(&funding_channel_id, 0, sizeof(funding_channel_id));
	}

	if (peer->local_shutdown_idx != -1) {
		shutdown_scriptpubkey
			= p2wpkh_for_keyidx(tmpctx, peer->ld,
					    peer->local_shutdown_idx);
	} else
		shutdown_scriptpubkey = NULL;

	initmsg = towire_channel_init(tmpctx,
				      peer->funding_txid,
				      peer->funding_outnum,
				      peer->funding_satoshi,
				      &peer->our_config,
				      &peer->channel_info->their_config,
				      &peer->channel_info->commit_sig,
				      cs,
				      &peer->channel_info->remote_fundingkey,
				      &peer->channel_info->theirbase.revocation,
				      &peer->channel_info->theirbase.payment,
				      &peer->channel_info->theirbase.delayed_payment,
				      &peer->channel_info->remote_per_commit,
				      &peer->channel_info->old_remote_per_commit,
				      peer->funder == LOCAL,
				      cfg->fee_base,
				      cfg->fee_per_satoshi,
				      *peer->balance,
				      peer->seed,
				      &peer->ld->dstate.id,
				      &peer->id,
				      time_to_msec(cfg->commit_time),
				      cfg->deadline_blocks,
				      peer->last_was_revoke,
				      peer->last_sent_commit,
				      peer->next_index[LOCAL],
				      peer->next_index[REMOTE],
				      peer->num_revocations_received,
				      peer->next_htlc_id,
				      htlcs, htlc_states,
				      fulfilled_htlcs, fulfilled_sides,
				      failed_htlcs, failed_sides,
				      peer->scid != NULL,
				      peer->remote_funding_locked,
				      &funding_channel_id,
				      peer->reconnected,
				      shutdown_scriptpubkey,
				      funding_signed);

	/* We don't expect a response: we are triggered by funding_depth_cb. */
	subd_send_msg(peer->owner, take(initmsg));

	tal_free(tmpctx);
	return true;
}

static bool peer_commit_initial(struct peer *peer)
{
	peer->next_index[LOCAL] = peer->next_index[REMOTE] = 1;

	/* FIXME: Db channel_info, etc. */
	return true;
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
	struct crypto_state cs;

	assert(tal_count(fds) == 2);

	/* At this point, we care about peer */
	fc->peer->channel_info = channel_info
		= tal(fc->peer, struct channel_info);

	if (!fromwire_opening_funder_reply(resp, NULL,
					   &channel_info->their_config,
					   &channel_info->commit_sig,
					   &cs,
					   &channel_info->theirbase.revocation,
					   &channel_info->theirbase.payment,
					   &channel_info->theirbase.delayed_payment,
					   &channel_info->remote_per_commit,
					   &fc->peer->minimum_depth,
					   &channel_info->remote_fundingkey,
					   &funding_txid)) {
		log_broken(fc->peer->log, "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		tal_free(fc->peer);
		return false;
	}

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* Generate the funding tx. */
	if (fc->change
	    && !bip32_pubkey(fc->peer->ld->bip32_base,
			     &changekey, fc->change_keyindex))
		fatal("Error deriving change key %u", fc->change_keyindex);

	derive_basepoints(fc->peer->seed, &local_fundingkey, NULL, NULL, NULL);

	fc->funding_tx = funding_tx(fc, &fc->peer->funding_outnum,
				    fc->utxomap, fc->peer->funding_satoshi,
				    &local_fundingkey,
				    &channel_info->remote_fundingkey,
				    fc->change, &changekey,
				    fc->peer->ld->bip32_base);
	fc->peer->funding_txid = tal(fc->peer, struct sha256_double);
	bitcoin_txid(fc->funding_tx, fc->peer->funding_txid);

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
		return false;
	}

	if (!peer_commit_initial(fc->peer)) {
		peer_internal_error(fc->peer, "Initial peer to db failed");
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

	if (!wire_sync_write(fc->peer->ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(fc, fc->peer->ld);
	opening_got_hsm_funding_sig(fc, fds[0], fds[1], msg, &cs);

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
	struct crypto_state cs;

	log_debug(peer->log, "Got opening_fundee_finish_response");
	assert(tal_count(fds) == 2);

	/* At this point, we care about peer */
	peer->channel_info = channel_info = tal(peer, struct channel_info);
	peer->funding_txid = tal(peer, struct sha256_double);
	if (!fromwire_opening_fundee_reply(peer, reply, NULL,
					   &channel_info->their_config,
					   &channel_info->commit_sig,
					   &cs,
					   &channel_info->theirbase.revocation,
					   &channel_info->theirbase.payment,
					   &channel_info->theirbase.delayed_payment,
					   &channel_info->remote_per_commit,
					   &channel_info->remote_fundingkey,
					   peer->funding_txid,
					   &peer->funding_outnum,
					   &peer->funding_satoshi,
					   &peer->push_msat,
					   &peer->channel_flags,
					   &funding_signed)) {
		log_broken(peer->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		return false;
	}
	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	if (!peer_commit_initial(peer))
		return false;

	log_debug(peer->log, "Watching funding tx %s",
		     type_to_string(reply, struct sha256_double,
				    peer->funding_txid));
	watch_txid(peer, peer->ld->topology, peer, peer->funding_txid,
		   funding_lockin_cb, NULL);

	/* Unowned. */
	peer->owner = NULL;

	/* On to normal operation! */
	peer_start_channeld(peer, OPENINGD, &cs, fds[0], fds[1], funding_signed);

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
void peer_fundee_open(struct peer *peer, const u8 *from_peer,
		      const struct crypto_state *cs,
		      int peer_fd, int gossip_fd)
{
	struct lightningd *ld = peer->ld;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;

	/* Note: gossipd handles unknown packets, so we don't have to worry
	 * about ignoring odd ones here. */
	if (fromwire_peektype(from_peer) != WIRE_OPEN_CHANNEL) {
		char *msg = tal_fmt(peer, "Bad message %i (%s) before opening",
				    fromwire_peektype(from_peer),
				    wire_type_name(fromwire_peektype(from_peer)));
		log_unusual(peer->log, "Strange message to exit gossip: %u",
			    fromwire_peektype(from_peer));
		peer_fail_permanent(peer, (u8 *)take(msg));
		return;
	}

	peer_set_condition(peer, GOSSIPD, OPENINGD);
	peer->owner = new_subd(ld, ld, "lightningd_opening", peer,
			       opening_wire_type_name,
			       NULL, peer_owner_finished,
			       take(&peer_fd), take(&gossip_fd),
			       NULL);
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
	peer->minimum_depth = ld->dstate.config.anchor_confirms;

	channel_config(ld, &peer->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	peer->seed = tal(peer, struct privkey);
	derive_peer_seed(ld, peer->seed, &peer->id);
	msg = towire_opening_init(peer, &peer->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, peer->seed);

	subd_send_msg(peer->owner, take(msg));
	msg = towire_opening_fundee(peer, peer->minimum_depth,
				    7500, 150000, from_peer);

	/* Careful here!  Their message could push us overlength! */
	if (tal_len(msg) >= 65536) {
		char *err = tal_strdup(peer, "Unacceptably long open_channel");
		peer_fail_permanent(peer, (u8 *)take(err));
		return;
	}
	subd_req(peer, peer->owner, take(msg), -1, 2,
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
	u8 *msg;
	struct subd *opening;
	struct utxo *utxos;
	u8 *bip32_base;
	struct crypto_state cs;

	if (!fromwire_gossipctl_release_peer_reply(resp, NULL, &cs)) {
		if (!fromwire_gossipctl_release_peer_replyfail(resp, NULL)) {
			fatal("Gossip daemon gave invalid reply %s",
			      tal_hex(gossip, resp));
		}
		tal_del_destructor(fc, fail_fundchannel_command);
		command_fail(fc->cmd, "Peer reconnected, try again");
		return true;
	}

	assert(tal_count(fds) == 2);

	peer_set_condition(fc->peer, GOSSIPD, OPENINGD);
	opening = new_subd(fc->peer->ld, ld,
			   "lightningd_opening", fc->peer,
			   opening_wire_type_name,
			   NULL, peer_owner_finished,
			   take(&fds[0]), take(&fds[1]), NULL);
	if (!opening) {
		peer_fail_transient(fc->peer, "Failed to subdaemon opening: %s",
				    strerror(errno));
		return true;
	}
	fc->peer->owner = opening;

	/* We will fund channel */
	fc->peer->funder = LOCAL;
	channel_config(ld, &fc->peer->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	fc->peer->channel_flags = OUR_CHANNEL_FLAGS;

	fc->peer->seed = tal(fc->peer, struct privkey);
	derive_peer_seed(ld, fc->peer->seed, &fc->peer->id);
	msg = towire_opening_init(fc, &fc->peer->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  &cs, fc->peer->seed);

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
				    fc->peer->channel_flags,
				    utxos, bip32_base);
	subd_req(fc, opening, take(msg), -1, 2, opening_funder_finished, fc);
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

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	jsmntok_t *peertok;
	struct peer *peer;

	if (!json_get_params(buffer, params,
			     "id", &peertok,
			     NULL)) {
		command_fail(cmd, "Need id");
		return;
	}

	peer = peer_from_json(ld, buffer, peertok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that id");
		return;
	}

	/* Easy case: peer can simply be forgotten. */
	if (!peer_persists(peer)) {
		peer_fail_permanent(peer, NULL);
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
