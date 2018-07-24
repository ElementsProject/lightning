#include <bitcoin/pubkey.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/wireaddr.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <hsmd/capabilities.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <lightningd/channel.h>
#include <lightningd/connect_control.h>
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

static void connectd_connect_result(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;
	bool connected;
	char *err;
	struct connect *c;

	if (!fromwire_connectctl_connect_to_peer_result(tmpctx, msg,
						       &id,
						       &connected,
						       &err))
		fatal("Connect gave bad CONNECTCTL_CONNECT_TO_PEER_RESULT message %s",
		      tal_hex(msg, msg));


	/* We can have multiple connect commands: complete them all */
	while ((c = find_connect(ld, &id)) != NULL) {
		if (connected) {
			struct json_result *response = new_json_result(c->cmd);
			json_object_start(response, NULL);
			json_add_pubkey(response, "id", &id);
			json_object_end(response);
			command_success(c->cmd, response);
		} else {
			command_fail(c->cmd, LIGHTNINGD, "%s", err);
		}
		/* They delete themselves from list */
	}
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	const jsmntok_t *hosttok, *porttok;
	jsmntok_t *idtok;
	struct pubkey id;
	char *id_str;
	char *atptr;
	char *ataddr = NULL;
	const char *name;
	struct wireaddr_internal addr;
	u8 *msg;
	const char *err_msg;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_tok, (const jsmntok_t **) &idtok),
		   p_opt_tok("host", &hosttok),
		   p_opt_tok("port", &porttok),
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

	if (!json_tok_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	if (hosttok && ataddr) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Can't specify host as both xxx@yyy "
			     "and separate argument");
		return;
	}

	/* Get parseable host if provided somehow */
	if (hosttok)
		name = tal_strndup(cmd, buffer + hosttok->start,
				   hosttok->end - hosttok->start);
	else if (ataddr)
		name = ataddr;
	else
		name = NULL;

	/* Port without host name? */
	if (porttok && !name) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Can't specify port without host");
		return;
	}

	/* Was there parseable host name? */
	if (name) {
		u32 port;
		/* Is there a port? */
		if (porttok) {
			if (!json_tok_number(buffer, porttok, &port) || !port) {
				command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					     "Port %.*s not valid",
					     porttok->end - porttok->start,
					     buffer + porttok->start);
				return;
			}
		} else {
			port = DEFAULT_PORT;
		}
		if (!parse_wireaddr_internal(name, &addr, port, false,
					     !cmd->ld->use_proxy_always
					     && !cmd->ld->pure_tor_setup,
					     true,
					     &err_msg)) {
			command_fail(cmd, LIGHTNINGD, "Host %s:%u not valid: %s",
				     name, port, err_msg ? err_msg : "port is 0");
			return;
		}

		/* Tell it about the address. */
		msg = towire_connectctl_peer_addrhint(cmd, &id, &addr);
		subd_send_msg(cmd->ld->connectd, take(msg));
	}

	/* If there isn't already a connect command, tell connectd */
	if (!find_connect(cmd->ld, &id)) {
		msg = towire_connectctl_connect_to_peer(NULL, &id);
		subd_send_msg(cmd->ld->connectd, take(msg));
	}
	/* Leave this here for connect_connect_result */
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

static void peer_nongossip(struct subd *connectd, const u8 *msg,
			   int peer_fd, int gossip_fd)
{
	struct pubkey id;
	struct crypto_state cs;
	struct wireaddr_internal addr;
	u8 *gfeatures, *lfeatures, *in_pkt;

	if (!fromwire_connect_peer_nongossip(msg, msg,
					    &id, &addr, &cs,
					    &gfeatures,
					    &lfeatures,
					    &in_pkt))
		fatal("Connectd gave bad CONNECT_PEER_NONGOSSIP message %s",
		      tal_hex(msg, msg));

	/* We already checked the features when it first connected. */
	if (!features_supported(gfeatures, lfeatures)) {
		log_unusual(connectd->log,
			    "Connectd gave unsupported features %s/%s",
			    tal_hex(msg, gfeatures),
			    tal_hex(msg, lfeatures));
		close(peer_fd);
		close(gossip_fd);
		return;
	}

	peer_sent_nongossip(connectd->ld, &id, &addr, &cs,
			    gfeatures, lfeatures,
			    peer_fd, gossip_fd, in_pkt);
}

static unsigned connectd_msg(struct subd *connectd, const u8 *msg, const int *fds)
{
	enum connect_wire_type t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_CONNECTCTL_INIT:
	case WIRE_CONNECTCTL_ACTIVATE:
	case WIRE_CONNECT_GETPEERS_REQUEST:
	case WIRE_CONNECTCTL_PEER_ADDRHINT:
	case WIRE_CONNECTCTL_CONNECT_TO_PEER:
	case WIRE_CONNECTCTL_PEER_IMPORTANT:
	case WIRE_CONNECTCTL_RELEASE_PEER:
	case WIRE_CONNECTCTL_HAND_BACK_PEER:
	case WIRE_CONNECTCTL_PEER_DISCONNECTED:
	case WIRE_CONNECTCTL_PEER_DISCONNECT:
	/* This is a reply, so never gets through to here. */
	case WIRE_CONNECTCTL_INIT_REPLY:
	case WIRE_CONNECTCTL_ACTIVATE_REPLY:
	case WIRE_CONNECT_GETPEERS_REPLY:
	case WIRE_CONNECTCTL_RELEASE_PEER_REPLY:
	case WIRE_CONNECTCTL_RELEASE_PEER_REPLYFAIL:
	case WIRE_CONNECTCTL_PEER_DISCONNECT_REPLY:
	case WIRE_CONNECTCTL_PEER_DISCONNECT_REPLYFAIL:
		break;

	case WIRE_CONNECT_RECONNECTED:
		peer_please_disconnect(connectd->ld, msg);
		break;

	case WIRE_CONNECT_PEER_CONNECTED:
		if (tal_count(fds) != 2)
			return 2;
		peer_connected(connectd->ld, msg, fds[0], fds[1]);
		break;
	case WIRE_CONNECT_PEER_NONGOSSIP:
		if (tal_count(fds) != 2)
			return 2;
		peer_nongossip(connectd, msg, fds[0], fds[1]);
		break;
	case WIRE_CONNECTCTL_CONNECT_TO_PEER_RESULT:
		connectd_connect_result(connectd->ld, msg);
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
	u64 capabilities = HSM_CAP_ECDH;
	struct wireaddr_internal *wireaddrs = ld->proposed_wireaddr;
	enum addr_listen_announce *listen_announce = ld->proposed_listen_announce;
	bool allow_localhost = false;
#if DEVELOPER
	if (ld->dev_allow_localhost)
		allow_localhost = true;
#endif

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		fatal("Could not socketpair for connectd<->gossipd");

	msg = towire_hsm_client_hsmfd(tmpctx, &ld->id, 0, capabilities);
	if (!wire_sync_write(ld->hsm_fd, msg))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsm_client_hsmfd_reply(msg))
		fatal("Malformed hsmfd response: %s", tal_hex(msg, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

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
	    get_offered_global_features(tmpctx),
	    get_offered_local_features(tmpctx), wireaddrs,
	    listen_announce, ld->reconnect,
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

