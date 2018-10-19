#include <bitcoin/pubkey.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/timeout.h>
#include <common/wireaddr.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_wire.h>
#include <lightningd/channel.h>
#include <lightningd/connect_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/opening_control.h>
#include <lightningd/param.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire_sync.h>

struct connect {
	struct list_node list;
	struct pubkey id;
	struct command *cmd;
};

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
	list_add_tail(&ld->connects, &c->list);
	tal_add_destructor(c, destroy_connect);
	return c;
}

/* Finds first command which matches. */
static struct connect *find_connect(struct lightningd *ld,
				    const struct pubkey *id)
{
	struct connect *i;

	list_for_each(&ld->connects, i, list) {
		if (pubkey_eq(&i->id, id))
			return i;
	}
	return NULL;
}

static void connect_cmd_succeed(struct command *cmd, const struct pubkey *id)
{
	struct json_stream *response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_pubkey(response, "id", id);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	u32 *port;
	jsmntok_t *idtok;
	struct pubkey id;
	char *id_str;
	char *atptr;
	char *ataddr = NULL;
	const char *name;
	struct wireaddr_internal *addr;
	u8 *msg;
	const char *err_msg;
	struct peer *peer;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_tok, (const jsmntok_t **) &idtok),
		   p_opt("host", json_tok_string, &name),
		   p_opt("port", json_tok_number, &port),
		   NULL))
		return;

	/* Check for id@addrport form */
	id_str = tal_strndup(cmd, buffer + idtok->start,
			     idtok->end - idtok->start);
	atptr = strchr(id_str, '@');
	if (atptr) {
		int atidx = atptr - id_str;
		ataddr = tal_strdup(cmd, atptr + 1);
		/* Cut id. */
		idtok->end = idtok->start + atidx;
	}

	if (!json_to_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	if (name && ataddr) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Can't specify host as both xxx@yyy "
			     "and separate argument");
		return;
	}

	/* Get parseable host if provided somehow */
	if (!name && ataddr)
		name = ataddr;

	/* Port without host name? */
	if (port && !name) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Can't specify port without host");
		return;
	}

	/* If we know about peer, see if it's already connected. */
	peer = peer_by_id(cmd->ld, &id);
	if (peer) {
		struct channel *channel = peer_active_channel(peer);

		if (peer->uncommitted_channel
		    || (channel && channel->connected)) {
			connect_cmd_succeed(cmd, &id);
			return;
		}
	}

	/* Was there parseable host name? */
	if (name) {
		/* Is there a port? */
		if (!port) {
			port = tal(cmd, u32);
			*port = DEFAULT_PORT;
		}
		addr = tal(cmd, struct wireaddr_internal);
		if (!parse_wireaddr_internal(name, addr, *port, false,
					     !cmd->ld->use_proxy_always
					     && !cmd->ld->pure_tor_setup,
					     true,
					     &err_msg)) {
			command_fail(cmd, LIGHTNINGD, "Host %s:%u not valid: %s",
				     name, *port, err_msg ? err_msg : "port is 0");
			return;
		}
	} else
		addr = NULL;

	msg = towire_connectctl_connect_to_peer(NULL, &id, 0, addr);
	subd_send_msg(cmd->ld->connectd, take(msg));

	/* Leave this here for peer_connected or connect_failed. */
	new_connect(cmd->ld, &id, cmd);
	command_still_pending(cmd);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to {id} at {host} (which can end in ':port' if not default). "
	"{id} can also be of the form id@host"
};
AUTODATA(json_command, &connect_command);

struct delayed_reconnect {
	struct channel *channel;
	u32 seconds_delayed;
	struct wireaddr_internal *addrhint;
};

static void maybe_reconnect(struct delayed_reconnect *d)
{
	struct peer *peer = d->channel->peer;

	/* Might have gone onchain since we started timer. */
	if (channel_active(d->channel)) {
		u8 *msg = towire_connectctl_connect_to_peer(NULL, &peer->id,
							    d->seconds_delayed,
							    d->addrhint);
		subd_send_msg(peer->ld->connectd, take(msg));
	}
	tal_free(d);
}

void delay_then_reconnect(struct channel *channel, u32 seconds_delay,
			  const struct wireaddr_internal *addrhint)
{
	struct delayed_reconnect *d;
	struct lightningd *ld = channel->peer->ld;

	if (!ld->reconnect)
		return;

	d = tal(channel, struct delayed_reconnect);
	d->channel = channel;
	d->seconds_delayed = seconds_delay;
	if (addrhint)
		d->addrhint = tal_dup(d, struct wireaddr_internal, addrhint);
	else
		d->addrhint = NULL;

	log_debug(channel->log, "Will try reconnect in %u seconds",
		  seconds_delay);

	/* We fuzz the timer by up to 1 second, to avoid getting into
	 * simultanous-reconnect deadlocks with peer. */
	notleak(new_reltimer(&ld->timers, d,
			     timerel_add(time_from_sec(seconds_delay),
					 time_from_usec(pseudorand(1000000))),
			     maybe_reconnect, d));
}

static void connect_failed(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;
	char *err;
	struct connect *c;
	u32 seconds_to_delay;
	struct wireaddr_internal *addrhint;
	struct channel *channel;

	if (!fromwire_connectctl_connect_failed(tmpctx, msg, &id, &err,
						&seconds_to_delay, &addrhint))
		fatal("Connect gave bad CONNECTCTL_CONNECT_FAILED message %s",
		      tal_hex(msg, msg));

	/* We can have multiple connect commands: fail them all */
	while ((c = find_connect(ld, &id)) != NULL) {
		/* They delete themselves from list */
		command_fail(c->cmd, LIGHTNINGD, "%s", err);
	}

	/* If we have an active channel, then reconnect. */
	channel = active_channel_by_id(ld, &id, NULL);
	if (channel)
		delay_then_reconnect(channel, seconds_to_delay, addrhint);
}

void connect_succeeded(struct lightningd *ld, const struct pubkey *id)
{
	struct connect *c;

	/* We can have multiple connect commands: fail them all */
	while ((c = find_connect(ld, id)) != NULL) {
		/* They delete themselves from list */
		connect_cmd_succeed(c->cmd, id);
	}
}

static void peer_please_disconnect(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;
	struct channel *c;
	struct uncommitted_channel *uc;

	if (!fromwire_connect_reconnected(msg, &id))
		fatal("Bad msg %s from connectd", tal_hex(tmpctx, msg));

	c = active_channel_by_id(ld, &id, &uc);
	if (uc)
		kill_uncommitted_channel(uc, "Reconnected");
	else if (c)
		channel_fail_transient(c, "Reconnected");
}

static unsigned connectd_msg(struct subd *connectd, const u8 *msg, const int *fds)
{
	enum connect_wire_type t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_CONNECTCTL_INIT:
	case WIRE_CONNECTCTL_ACTIVATE:
	case WIRE_CONNECTCTL_CONNECT_TO_PEER:
	case WIRE_CONNECTCTL_PEER_DISCONNECTED:
	/* This is a reply, so never gets through to here. */
	case WIRE_CONNECTCTL_INIT_REPLY:
	case WIRE_CONNECTCTL_ACTIVATE_REPLY:
		break;

	case WIRE_CONNECT_RECONNECTED:
		peer_please_disconnect(connectd->ld, msg);
		break;

	case WIRE_CONNECT_PEER_CONNECTED:
		if (tal_count(fds) != 2)
			return 2;
		peer_connected(connectd->ld, msg, fds[0], fds[1]);
		break;

	case WIRE_CONNECTCTL_CONNECT_FAILED:
		connect_failed(connectd->ld, msg);
		break;
	}
	return 0;
}

static void connect_init_done(struct subd *connectd,
			      const u8 *reply,
			      const int *fds UNUSED,
			      void *unused UNUSED)
{
	struct lightningd *ld = connectd->ld;

	if (!fromwire_connectctl_init_reply(ld, reply,
					    &ld->binding,
					    &ld->announcable))
		fatal("Bad connectctl_activate_reply: %s",
		      tal_hex(reply, reply));

	/* Break out of loop, so we can begin */
	io_break(connectd);
}

int connectd_init(struct lightningd *ld)
{
	int fds[2];
	u8 *msg;
	int hsmfd;
	struct wireaddr_internal *wireaddrs = ld->proposed_wireaddr;
	enum addr_listen_announce *listen_announce = ld->proposed_listen_announce;
	bool allow_localhost = false;
#if DEVELOPER
	if (ld->dev_allow_localhost)
		allow_localhost = true;
#endif

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		fatal("Could not socketpair for connectd<->gossipd");

	hsmfd = hsm_get_global_fd(ld, HSM_CAP_ECDH);

	ld->connectd = new_global_subd(ld, "lightning_connectd",
				       connect_wire_type_name, connectd_msg,
				       take(&hsmfd), take(&fds[1]), NULL);
	if (!ld->connectd)
		err(1, "Could not subdaemon connectd");

	/* If no addr specified, hand wildcard to connectd */
	if (tal_count(wireaddrs) == 0 && ld->autolisten) {
		wireaddrs = tal_arrz(tmpctx, struct wireaddr_internal, 1);
		listen_announce = tal_arr(tmpctx, enum addr_listen_announce, 1);
		wireaddrs->itype = ADDR_INTERNAL_ALLPROTO;
		wireaddrs->u.port = ld->portnum;
		*listen_announce = ADDR_LISTEN_AND_ANNOUNCE;
	}

	msg = towire_connectctl_init(
	    tmpctx, &ld->id,
	    get_offered_globalfeatures(tmpctx),
	    get_offered_localfeatures(tmpctx), wireaddrs,
	    listen_announce,
	    ld->proxyaddr, ld->use_proxy_always || ld->pure_tor_setup,
	    allow_localhost, ld->config.use_dns,
	    ld->tor_service_password ? ld->tor_service_password : "");

	subd_req(ld->connectd, ld->connectd, take(msg), -1, 0,
		 connect_init_done, NULL);

	/* Wait for init_reply */
	io_loop(NULL, NULL);

	return fds[0];
}

static void connect_activate_done(struct subd *connectd,
				  const u8 *reply UNUSED,
				  const int *fds UNUSED,
				  void *unused UNUSED)
{
	/* Break out of loop, so we can begin */
	io_break(connectd);
}

void connectd_activate(struct lightningd *ld)
{
	const u8 *msg = towire_connectctl_activate(NULL, ld->listen);

	subd_req(ld->connectd, ld->connectd, take(msg), -1, 0,
		 connect_activate_done, NULL);

	/* Wait for activate_reply */
	io_loop(NULL, NULL);
}

