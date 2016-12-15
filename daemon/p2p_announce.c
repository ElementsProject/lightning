#include "daemon/chaintopology.h"
#include "daemon/log.h"
#include "daemon/p2p_announce.h"
#include "daemon/packets.h"
#include "daemon/peer.h"
#include "daemon/routing.h"
#include "daemon/secrets.h"
#include "daemon/timeout.h"

#include <arpa/inet.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>

struct queued_message {
	int type;

	/* Unique tag specifying the msg origin */
	void *tag;

	/* Timestamp for `channel_update`s and `node_announcement`s, 0
	 * for `channel_announcement`s */
	u32 timestamp;

	/* Serialized payload */
	u8 *payload;

	struct list_node list;

	/* who told us about this message? */
	struct peer *origin;
};

u8 ipv4prefix[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xFF, 0xFF
};

/* Read an IP from `srcip` and convert it into the dotted
 * notation. Handles both IPv4 and IPv6 addresses and converts
 * accordingly. We differentiate the two by using the RFC 4291
 * IPv4-mapped IPv6 format */
static char* read_ip(const tal_t *ctx, const struct ipv6 *srcip)
{
	char tempaddr[INET6_ADDRSTRLEN];

	if (memcmp(srcip, ipv4prefix, sizeof(ipv4prefix)) == 0) {
		inet_ntop(AF_INET, srcip + 12, tempaddr, sizeof(tempaddr));
	}else{
		inet_ntop(AF_INET6, srcip, tempaddr, sizeof(tempaddr));
	}
	return tal_strdup(ctx, tempaddr);
}

/* Serialize the IP address in `srcip` into a 16 byte
 * representation. It handles both IPv6 and IPv4 addresses, prefixing
 * IPv4 addresses with the prefix described in RFC 4291. */
static void write_ip(struct ipv6 *dstip, char *srcip)
{
	if (!strchr(srcip, ':')) {
		memcpy(dstip, ipv4prefix, sizeof(ipv4prefix));
		inet_pton(AF_INET, srcip, dstip);
	} else {
		inet_pton(AF_INET6, srcip, dstip);
	}
}

static void broadcast(struct lightningd_state *dstate,
		      int type, u8 *pkt,
		      struct peer *origin)
{
	struct peer *p;
	list_for_each(&dstate->peers, p, list) {
		if (state_is_normal(p->state) && origin != p)
			queue_pkt_nested(p, type, pkt);
	}
}

static void queue_broadcast(struct lightningd_state *dstate,
			    const int type,
			    const u32 timestamp,
			    const u8 *tag,
			    const u8 *payload,
			    struct peer *origin)
{
	struct queued_message *el, *msg;
	list_for_each(&dstate->broadcast_queue, el, list) {
		if (el->type == type &&
		    tal_count(tag) == tal_count(el->tag) &&
		    memcmp(el->tag, tag, tal_count(tag)) == 0 &&
		    el->timestamp < timestamp){
			/* Found a replacement */
			el->payload = tal_free(el->payload);
			el->payload = tal_dup_arr(el, u8, payload, tal_count(payload), 0);
			el->timestamp = timestamp;
			el->origin = origin;
			return;
		}
	}

	/* No match found, add a new message to the queue */
	msg = tal(dstate, struct queued_message);
	msg->type = type;
	msg->timestamp = timestamp;
	msg->tag = tal_dup_arr(msg, u8, tag, tal_count(tag), 0);
	msg->payload = tal_dup_arr(msg, u8, payload, tal_count(payload), 0);
	msg->origin = origin;
	list_add_tail(&dstate->broadcast_queue, &msg->list);
}

static bool add_channel_direction(struct lightningd_state *dstate,
				  const struct pubkey *from,
				  const struct pubkey *to,
				  const int direction,
				  const struct channel_id *channel_id
	)
{
	struct node_connection *c = get_connection(dstate, from, to);
	if (c){
		/* Do not clobber connections added otherwise */
		memcpy(&c->channel_id, channel_id, sizeof(c->channel_id));
		c->flags = direction;
		printf("Found node_connection via get_connection");
		return false;
	}else if(get_connection_by_cid(dstate, channel_id, direction)) {
		return false;
	}
	half_add_connection(dstate,
			    from,
			    to,
			    channel_id, direction);
	return true;
}

void handle_channel_announcement(
	struct peer *peer,
	const struct msg_channel_announcement *msg)
{
	u8 *serialized;
	bool forward = false;
	if (!msg)
		return;

	//FIXME(cdecker) Check signatures, when the spec is settled
	//FIXME(cdecker) Check chain topology for the anchor TX

	log_debug(peer->log, "Received channel_announcement for channel %d:%d:%d",
			  msg->channel_id.blocknum,
			  msg->channel_id.txnum,
			  msg->channel_id.outnum
		);
	forward |= add_channel_direction(peer->dstate, &msg->node_id_1,
					 &msg->node_id_2, 0, &msg->channel_id);
	forward |= add_channel_direction(peer->dstate, &msg->node_id_2,
					 &msg->node_id_1, 1, &msg->channel_id);
	if (!forward){
		log_debug(peer->log, "Not forwarding channel_announcement");
		return;
	}

	serialized = towire_channel_announcement(msg, msg);

	u8 *tag = tal_arr(msg, u8, 0);
	towire_channel_id(&tag, &msg->channel_id);
	queue_broadcast(peer->dstate,
			WIRE_CHANNEL_ANNOUNCEMENT,
			0, /* `channel_announcement`s do not have a timestamp */
			tag,
			serialized, peer);
	tal_free(msg);
}

void handle_channel_update(struct peer *peer, const struct msg_channel_update *msg)
{
	if (!msg)
		return;

	u8 *serialized;
	struct node_connection *c;

	log_debug(peer->log, "Received channel_update for channel %d:%d:%d(%d)",
		  msg->channel_id.blocknum,
		  msg->channel_id.txnum,
		  msg->channel_id.outnum,
		  msg->flags & 0x01
		);

	c = get_connection_by_cid(peer->dstate, &msg->channel_id, msg->flags & 0x1);

	if (!c) {
		log_debug(peer->log, "Ignoring update for unknown channel %d:%d:%d",
			  msg->channel_id.blocknum,
			  msg->channel_id.txnum,
			  msg->channel_id.outnum
			);
		return;
	} else if (c->last_timestamp >= msg->timestamp) {
		log_debug(peer->log, "Ignoring outdated update.");
		return;
	}

	//FIXME(cdecker) Check signatures
	serialized = towire_channel_update(msg, msg);

	c->last_timestamp = msg->timestamp;
	c->delay = msg->expiry;
	c->htlc_minimum_msat = msg->htlc_minimum_msat;
	c->base_fee = msg->fee_base_msat;
	c->proportional_fee = msg->fee_proportional_millionths;
	c->active = true;
	log_debug(peer->log, "Channel %d:%d:%d(%d) was updated.",
		  msg->channel_id.blocknum,
		  msg->channel_id.txnum,
		  msg->channel_id.outnum,
		  msg->flags
		);

	u8 *tag = tal_arr(msg, u8, 0);
	towire_channel_id(&tag, &msg->channel_id);
	queue_broadcast(peer->dstate,
			WIRE_CHANNEL_UPDATE,
			msg->timestamp,
			tag,
			serialized, peer);
	tal_free(msg);
}

void handle_node_announcement(
	struct peer *peer, const struct msg_node_announcement *msg)
{
	u8 *serialized;
	struct sha256_double hash;
	struct node *node;

	if (!msg)
		return;

	log_debug_struct(peer->log,
			 "Received node_announcement for node %s",
			 struct pubkey, &msg->node_id);

	serialized = towire_node_announcement(msg, msg);
	sha256_double(&hash, serialized + 64, tal_count(serialized) - 64);
	if (!check_signed_hash(&hash, &msg->signature, &msg->node_id)) {
		log_debug(peer->dstate->base_log,
			  "Ignoring node announcement, signature verification failed.");
		return;
	}
	node = get_node(peer->dstate, &msg->node_id);

	if (!node) {
		log_debug(peer->dstate->base_log,
			  "Node not found, was the node_announcement preceeded by at least channel_announcement?");
		return;
	} else if (node->last_timestamp >= msg->timestamp) {
		log_debug(peer->dstate->base_log,
			  "Ignoring node announcement, it's outdated.");
		return;
	}

	node->last_timestamp = msg->timestamp;
	if (node->hostname)
		node->hostname = tal_free(node->hostname);
	node->hostname = read_ip(node, &msg->ipv6);
	node->port = msg->port;
	memcpy(node->rgb_color, msg->rgb_color, 3);

	u8 *tag = tal_arr(msg, u8, 0);
	towire_pubkey(&tag, &msg->node_id);
	queue_broadcast(peer->dstate,
			WIRE_NODE_ANNOUNCEMENT,
			msg->timestamp,
			tag,
			serialized, peer);
	tal_free(msg);
}

static void broadcast_channel_update(struct lightningd_state *dstate, struct peer *peer)
{
	struct msg_channel_update *msg;
	struct txlocator *loc;
	u8 *serialized;

	msg = tal(peer, struct msg_channel_update);
	loc = locate_tx(msg, dstate, &peer->anchor.txid);

	msg->timestamp = timeabs_to_timeval(time_now()).tv_sec;
	msg->channel_id.blocknum = loc->blkheight;
	msg->channel_id.txnum = loc->index;
	msg->channel_id.outnum = peer->anchor.index;
	msg->flags = pubkey_cmp(&dstate->id, peer->id) > 0;
	msg->expiry = dstate->config.min_htlc_expiry;
	msg->htlc_minimum_msat = 1;
	msg->fee_base_msat = dstate->config.fee_base;
	msg->fee_proportional_millionths = dstate->config.fee_per_satoshi;

	/* Avoid triggering memcheck */
	memset(&msg->signature, 0, sizeof(msg->signature));
	serialized = towire_channel_update(msg, msg);
	privkey_sign(dstate, serialized + 64, tal_count(serialized) - 64, &msg->signature);
	serialized = towire_channel_update(msg, msg);

	broadcast(dstate, WIRE_CHANNEL_UPDATE, serialized, NULL);
	tal_free(msg);
}

static void broadcast_node_announcement(struct lightningd_state *dstate)
{
	u8 *serialized;

	/* Are we listeing for incoming connections at all? */
	if (!dstate->external_ip || !dstate->portnum)
		return;

	struct msg_node_announcement *msg = tal(dstate, struct msg_node_announcement);
	msg->timestamp = timeabs_to_timeval(time_now()).tv_sec;
	msg->node_id = dstate->id;
	write_ip(&msg->ipv6, dstate->external_ip);
	msg->port = dstate->portnum;
	memset(&msg->rgb_color, 0x00, 3);

	serialized = towire_node_announcement(msg, msg);
	privkey_sign(dstate, serialized + 64, tal_count(serialized) - 64, &msg->signature);
	serialized = towire_node_announcement(msg, msg);
	broadcast(dstate, WIRE_NODE_ANNOUNCEMENT, serialized, NULL);
	tal_free(msg);

}

static void broadcast_channel_announcement(struct lightningd_state *dstate, struct peer *peer)
{
	struct msg_channel_announcement *msg = tal(peer, struct msg_channel_announcement);
	struct txlocator *loc;
	struct signature *my_node_signature;
	struct signature *my_bitcoin_signature;
	u8 *serialized;

	loc = locate_tx(msg, dstate, &peer->anchor.txid);

	msg->channel_id.blocknum = loc->blkheight;
	msg->channel_id.txnum = loc->index;
	msg->channel_id.outnum = peer->anchor.index;


	/* Set all sigs to zero */
	memset(&msg->node_signature_1, 0, sizeof(msg->node_signature_1));
	memset(&msg->bitcoin_signature_1, 0, sizeof(msg->bitcoin_signature_1));
	memset(&msg->node_signature_2, 0, sizeof(msg->node_signature_2));
	memset(&msg->bitcoin_signature_2, 0, sizeof(msg->bitcoin_signature_2));

	//FIXME(cdecker) Copy remote stored signatures into place
	if (pubkey_cmp(&dstate->id, peer->id) > 0) {
		msg->node_id_1 = *peer->id;
		msg->node_id_2 = dstate->id;
		msg->bitcoin_key_1 = *peer->id;
		msg->bitcoin_key_2 = dstate->id;
		my_node_signature = &msg->node_signature_2;
		my_bitcoin_signature = &msg->bitcoin_signature_2;
	} else {
		msg->node_id_2 = *peer->id;
		msg->node_id_1 = dstate->id;
		msg->bitcoin_key_2 = *peer->id;
		msg->bitcoin_key_1 = dstate->id;
		my_node_signature = &msg->node_signature_1;
		my_bitcoin_signature = &msg->bitcoin_signature_1;
	}
	/* Sign the node_id with the bitcoin_key, proves delegation */
	serialized = tal_arr(msg, u8, 0);
	towire_pubkey(&serialized, &dstate->id);
	privkey_sign(dstate, serialized, tal_count(serialized), my_bitcoin_signature);

	/* Sign the entire packet with `node_id`, proves integrity and origin */
	serialized = towire_channel_announcement(msg, msg);
	privkey_sign(dstate, serialized + 128, tal_count(serialized) - 128, my_node_signature);

	serialized = towire_channel_announcement(msg, msg);
	broadcast(dstate, WIRE_CHANNEL_ANNOUNCEMENT, serialized, NULL);
	tal_free(msg);
}

static void announce(struct lightningd_state *dstate)
{
	struct peer *p;
	int nchan = 0;

	new_reltimer(dstate, dstate, time_from_sec(5*60*60), announce, dstate);

	list_for_each(&dstate->peers, p, list) {
		if (state_is_normal(p->state)) {
			broadcast_channel_announcement(dstate, p);
			broadcast_channel_update(dstate, p);
			nchan += 1;
		}
	}

	/* No point in broadcasting our node if we don't have a channel */
	if (nchan > 0)
		broadcast_node_announcement(dstate);
}

void announce_channel(struct lightningd_state *dstate, struct peer *peer)
{
	broadcast_channel_announcement(dstate, peer);
	broadcast_channel_update(dstate, peer);
	broadcast_node_announcement(dstate);

}

static void process_broadcast_queue(struct lightningd_state *dstate)
{
	new_reltimer(dstate, dstate, time_from_sec(30), process_broadcast_queue, dstate);
	struct queued_message *el;
	while ((el = list_pop(&dstate->broadcast_queue, struct queued_message, list)) != NULL) {
		broadcast(dstate, el->type, el->payload, NULL);
		tal_free(el);
	}
}

void setup_p2p_announce(struct lightningd_state *dstate)
{
	new_reltimer(dstate, dstate, time_from_sec(5*60*60), announce, dstate);
	new_reltimer(dstate, dstate, time_from_sec(30), process_broadcast_queue, dstate);
}
