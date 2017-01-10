#include "gossip_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subdaemon.h"
#include <ccan/err/err.h>
#include <ccan/take/take.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <inttypes.h>
#include <lightningd/gossip/gen_gossip_control_wire.h>
#include <lightningd/gossip/gen_gossip_status_wire.h>

static void gossip_finished(struct subdaemon *gossip, int status)
{
	if (WIFEXITED(status))
		errx(1, "Gossip failed (exit status %i), exiting.",
		     WEXITSTATUS(status));
	errx(1, "Gossip failed (signal %u), exiting.", WTERMSIG(status));
}

static void peer_bad_message(struct subdaemon *gossip, const u8 *msg)
{
	u64 unique_id;
	struct peer *peer;
	u8 *err;

	if (!fromwire_gossipstatus_peer_bad_msg(msg, msg, NULL,
						&unique_id, &err))
		fatal("Gossip gave bad PEER_BAD message %s", tal_hex(msg, msg));

	peer = peer_by_unique_id(gossip->ld, unique_id);
	if (!peer)
		fatal("Gossip gave bad peerid %"PRIu64, unique_id);

	log_debug(gossip->log, "Peer %s gave bad msg %s",
		  type_to_string(msg, struct pubkey, peer->id),
		  tal_hex(msg, msg));
	peer_set_condition(peer, "Bad message %s during gossip phase",
			   gossip_status_wire_type_name(fromwire_peektype(msg)));
	tal_free(peer);
}

static void peer_nongossip(struct subdaemon *gossip, const u8 *msg, int fd)
{
	u64 unique_id;
	struct peer *peer;
	u8 *inner;
	struct crypto_state *cs;

	if (!fromwire_gossipstatus_peer_nongossip(msg, msg, NULL,
						  &unique_id, &cs, &inner))
		fatal("Gossip gave bad PEER_NONGOSSIP message %s",
		      tal_hex(msg, msg));

	peer = peer_by_unique_id(gossip->ld, unique_id);
	if (!peer)
		fatal("Gossip gave bad peerid %"PRIu64, unique_id);

	log_debug(gossip->log, "Peer %s said %s",
		  type_to_string(msg, struct pubkey, peer->id),
		  gossip_status_wire_type_name(fromwire_peektype(inner)));
	peer_set_condition(peer, "Gossip ended up receipt of %s",
			 gossip_status_wire_type_name(fromwire_peektype(inner)));

	/* FIXME: create new daemon to handle peer. */
}

static void peer_ready(struct subdaemon *gossip, const u8 *msg)
{
	u64 unique_id;
	struct peer *peer;

	if (!fromwire_gossipstatus_peer_ready(msg, NULL, &unique_id))
		fatal("Gossip gave bad PEER_READY message %s",
		      tal_hex(msg, msg));

	peer = peer_by_unique_id(gossip->ld, unique_id);
	if (!peer)
		fatal("Gossip gave bad peerid %"PRIu64, unique_id);

	log_debug_struct(gossip->log, "Peer %s ready for channel open",
			 struct pubkey, peer->id);

	if (peer->connect_cmd) {
		struct json_result *response;
		response = new_json_result(peer->connect_cmd);

		json_object_start(response, NULL);
		json_add_pubkey(response, "id", peer->id);
		json_object_end(response);
		command_success(peer->connect_cmd, response);
		peer->connect_cmd = NULL;
	}

	peer_set_condition(peer, "Exchanging gossip");
}

static enum subdaemon_status gossip_status(struct subdaemon *gossip,
					   const u8 *msg, int fd)
{
	enum gossip_status_wire_type t = fromwire_peektype(msg);

	switch (t) {
	/* We don't get told about fatal errors. */
	case WIRE_GOSSIPSTATUS_INIT_FAILED:
	case WIRE_GOSSIPSTATUS_BAD_NEW_PEER_REQUEST:
	case WIRE_GOSSIPSTATUS_BAD_REQUEST:
	case WIRE_GOSSIPSTATUS_FDPASS_FAILED:
	case WIRE_GOSSIPSTATUS_BAD_RELEASE_REQUEST:
		break;
	case WIRE_GOSSIPSTATUS_PEER_BAD_MSG:
		peer_bad_message(gossip, msg);
		break;
	case WIRE_GOSSIPSTATUS_PEER_NONGOSSIP:
		if (fd == -1)
			return STATUS_NEED_FD;
		peer_nongossip(gossip, msg, fd);
		break;
	case WIRE_GOSSIPSTATUS_PEER_READY:
		peer_ready(gossip, msg);
		break;
	}
	return STATUS_COMPLETE;
}

void gossip_init(struct lightningd *ld)
{
	ld->gossip = new_subdaemon(ld, ld, "lightningd_gossip",
				   gossip_status_wire_type_name,
				   gossip_control_wire_type_name,
				   gossip_status, gossip_finished, -1);
	if (!ld->gossip)
		err(1, "Could not subdaemon gossip");
}
