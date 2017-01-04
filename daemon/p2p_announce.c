#include "daemon/chaintopology.h"
#include "daemon/log.h"
#include "daemon/p2p_announce.h"
#include "daemon/packets.h"
#include "daemon/peer.h"
#include "daemon/routing.h"
#include "daemon/secrets.h"
#include "daemon/timeout.h"
#include "utils.h"

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
			    const u8 *payload)
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
			return;
		}
	}

	/* No match found, add a new message to the queue */
	msg = tal(dstate, struct queued_message);
	msg->type = type;
	msg->timestamp = timestamp;
	msg->tag = tal_dup_arr(msg, u8, tag, tal_count(tag), 0);
	msg->payload = tal_dup_arr(msg, u8, payload, tal_count(payload), 0);
	list_add_tail(&dstate->broadcast_queue, &msg->list);
}

static bool add_channel_direction(struct lightningd_state *dstate,
				  const struct pubkey *from,
				  const struct pubkey *to,
				  const int direction,
				  const struct channel_id *channel_id,
				  const u8 *announcement)
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

	c = half_add_connection(dstate, from, to, channel_id, direction);

	/* Remember the announcement so we can forward it to new peers */
	tal_free(c->channel_announcement);
	c->channel_announcement = tal_dup_arr(c, u8, announcement,
					      tal_count(announcement), 0);
	return true;
}

void handle_channel_announcement(
	struct peer *peer,
	const u8 *announce, size_t len)
{
	u8 *serialized;
	bool forward = false;
	struct signature node_signature_1;
	struct signature node_signature_2;
	struct channel_id channel_id;
	struct signature bitcoin_signature_1;
	struct signature bitcoin_signature_2;
	struct pubkey node_id_1;
	struct pubkey node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;
	const tal_t *tmpctx = tal_tmpctx(peer);

	serialized = tal_dup_arr(tmpctx, u8, announce, len, 0);
	/* FIXME: use NULL arg to mean tal_count() here! */
	if (!fromwire_channel_announcement(serialized, &len,
					   &node_signature_1, &node_signature_2,
					   &channel_id,
					   &bitcoin_signature_1,
					   &bitcoin_signature_2,
					   &node_id_1, &node_id_2,
					   &bitcoin_key_1, &bitcoin_key_2)) {
		tal_free(tmpctx);
		return;
	}

	//FIXME(cdecker) Check signatures, when the spec is settled
	//FIXME(cdecker) Check chain topology for the anchor TX

	log_debug(peer->log,
		  "Received channel_announcement for channel %d:%d:%d",
		  channel_id.blocknum,
		  channel_id.txnum,
		  channel_id.outnum
		);

	forward |= add_channel_direction(peer->dstate, &node_id_1,
					 &node_id_2, 0, &channel_id,
					 serialized);
	forward |= add_channel_direction(peer->dstate, &node_id_2,
					 &node_id_1, 1, &channel_id,
					 serialized);
	if (!forward){
		log_debug(peer->log, "Not forwarding channel_announcement");
		tal_free(tmpctx);
		return;
	}

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_channel_id(&tag, &channel_id);
	queue_broadcast(peer->dstate, WIRE_CHANNEL_ANNOUNCEMENT,
			0, /* `channel_announcement`s do not have a timestamp */
			tag, serialized);

	tal_free(tmpctx);
}

void handle_channel_update(struct peer *peer, const u8 *update, size_t len)
{
	u8 *serialized;
	struct node_connection *c;
	struct signature signature;
	struct channel_id channel_id;
	u32 timestamp;
	u16 flags;
	u16 expiry;
	u32 htlc_minimum_msat;
	u32 fee_base_msat;
	u32 fee_proportional_millionths;
	const tal_t *tmpctx = tal_tmpctx(peer);

	serialized = tal_dup_arr(tmpctx, u8, update, len, 0);
	/* FIXME: use NULL arg to mean tal_count() here! */
	if (!fromwire_channel_update(serialized, &len, &signature, &channel_id,
				     &timestamp, &flags, &expiry,
				     &htlc_minimum_msat, &fee_base_msat,
				     &fee_proportional_millionths)) {
		tal_free(tmpctx);
		return;
	}


	log_debug(peer->log, "Received channel_update for channel %d:%d:%d(%d)",
		  channel_id.blocknum,
		  channel_id.txnum,
		  channel_id.outnum,
		  flags & 0x01
		);

	c = get_connection_by_cid(peer->dstate, &channel_id, flags & 0x1);

	if (!c) {
		log_debug(peer->log, "Ignoring update for unknown channel %d:%d:%d",
			  channel_id.blocknum,
			  channel_id.txnum,
			  channel_id.outnum
			);
		tal_free(tmpctx);
		return;
	} else if (c->last_timestamp >= timestamp) {
		log_debug(peer->log, "Ignoring outdated update.");
		tal_free(tmpctx);
		return;
	}

	//FIXME(cdecker) Check signatures
	c->last_timestamp = timestamp;
	c->delay = expiry;
	c->htlc_minimum_msat = htlc_minimum_msat;
	c->base_fee = fee_base_msat;
	c->proportional_fee = fee_proportional_millionths;
	c->active = true;
	log_debug(peer->log, "Channel %d:%d:%d(%d) was updated.",
		  channel_id.blocknum,
		  channel_id.txnum,
		  channel_id.outnum,
		  flags
		);

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_channel_id(&tag, &channel_id);
	queue_broadcast(peer->dstate,
			WIRE_CHANNEL_UPDATE,
			timestamp,
			tag,
			serialized);

	tal_free(c->channel_update);
	c->channel_update = tal_steal(c, serialized);
	tal_free(tmpctx);
}

void handle_node_announcement(
	struct peer *peer, const u8 *node_ann, size_t len)
{
	u8 *serialized;
	struct sha256_double hash;
	struct node *node;
	struct signature signature;
	u32 timestamp;
	struct ipv6 ipv6;
	u16 port;
	struct pubkey node_id;
	u8 rgb_color[3];
	u8 alias[32];
	const tal_t *tmpctx = tal_tmpctx(peer);

	serialized = tal_dup_arr(tmpctx, u8, node_ann, len, 0);
	/* FIXME: use NULL arg to mean tal_count() here! */
	if (!fromwire_node_announcement(serialized, &len,
					&signature, &timestamp, &ipv6, &port,
					&node_id, rgb_color, alias)) {
		tal_free(tmpctx);
		return;
	}

	log_debug_struct(peer->log,
			 "Received node_announcement for node %s",
			 struct pubkey, &node_id);

	sha256_double(&hash, serialized + 64, tal_count(serialized) - 64);
	if (!check_signed_hash(&hash, &signature, &node_id)) {
		log_debug(peer->dstate->base_log,
			  "Ignoring node announcement, signature verification failed.");
		tal_free(tmpctx);
		return;
	}
	node = get_node(peer->dstate, &node_id);

	if (!node) {
		log_debug(peer->dstate->base_log,
			  "Node not found, was the node_announcement preceeded by at least channel_announcement?");
		tal_free(tmpctx);
		return;
	} else if (node->last_timestamp >= timestamp) {
		log_debug(peer->dstate->base_log,
			  "Ignoring node announcement, it's outdated.");
		tal_free(tmpctx);
		return;
	}

	node->last_timestamp = timestamp;
	node->hostname = tal_free(node->hostname);
	node->hostname = read_ip(node, &ipv6);
	node->port = port;
	memcpy(node->rgb_color, rgb_color, 3);

	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_pubkey(&tag, &node_id);
	queue_broadcast(peer->dstate,
			WIRE_NODE_ANNOUNCEMENT,
			timestamp,
			tag,
			serialized);
	tal_free(node->node_announcement);
	node->node_announcement = tal_steal(node, serialized);
	tal_free(tmpctx);
}

static void broadcast_channel_update(struct lightningd_state *dstate, struct peer *peer)
{
	struct txlocator *loc;
	u8 *serialized;
	struct signature signature;
	struct channel_id channel_id;
	u32 timestamp = time_now().ts.tv_sec;
	const tal_t *tmpctx = tal_tmpctx(dstate);

	loc = locate_tx(tmpctx, dstate, &peer->anchor.txid);
	channel_id.blocknum = loc->blkheight;
	channel_id.txnum = loc->index;
	channel_id.outnum = peer->anchor.index;

	/* Avoid triggering memcheck */
	memset(&signature, 0, sizeof(signature));

	serialized = towire_channel_update(tmpctx, &signature, &channel_id,
					   timestamp,
					   pubkey_cmp(&dstate->id, peer->id) > 0,
					   dstate->config.min_htlc_expiry,
	//FIXME(cdecker) Make the minimum HTLC configurable
					   1,
					   dstate->config.fee_base,
					   dstate->config.fee_per_satoshi);
	privkey_sign(dstate, serialized + 64, tal_count(serialized) - 64,
		     &signature);
	serialized = towire_channel_update(tmpctx, &signature, &channel_id,
					   timestamp,
					   pubkey_cmp(&dstate->id, peer->id) > 0,
					   dstate->config.min_htlc_expiry,
					   1,
					   dstate->config.fee_base,
					   dstate->config.fee_per_satoshi);

	broadcast(dstate, WIRE_CHANNEL_UPDATE, serialized, NULL);
	tal_free(tmpctx);
}

static void broadcast_node_announcement(struct lightningd_state *dstate)
{
	u8 *serialized;
	struct signature signature;
	struct ipv6 ipv6;
	static const u8 rgb_color[3];
	static const u8 alias[32];
	u32 timestamp = time_now().ts.tv_sec;
	const tal_t *tmpctx = tal_tmpctx(dstate);

	/* Are we listening for incoming connections at all? */
	if (!dstate->external_ip || !dstate->portnum) {
		tal_free(tmpctx);
		return;
	}

	/* Avoid triggering memcheck */
	memset(&signature, 0, sizeof(signature));

	write_ip(&ipv6, dstate->external_ip);
	serialized = towire_node_announcement(tmpctx, &signature,
					      timestamp,
					      &ipv6, dstate->portnum,
					      &dstate->id, rgb_color, alias);
	privkey_sign(dstate, serialized + 64, tal_count(serialized) - 64,
		     &signature);
	serialized = towire_node_announcement(tmpctx, &signature,
					      timestamp,
					      &ipv6, dstate->portnum,
					      &dstate->id, rgb_color, alias);
	broadcast(dstate, WIRE_NODE_ANNOUNCEMENT, serialized, NULL);
	tal_free(tmpctx);
}

static void broadcast_channel_announcement(struct lightningd_state *dstate, struct peer *peer)
{
	struct txlocator *loc;
	struct channel_id channel_id;
	struct signature node_signature[2];
	struct signature bitcoin_signature[2];
	const struct pubkey *node_id[2];
	const struct pubkey *bitcoin_key[2];
	struct signature *my_node_signature;
	struct signature *my_bitcoin_signature;
	u8 *serialized;
	const tal_t *tmpctx = tal_tmpctx(dstate);

	loc = locate_tx(tmpctx, dstate, &peer->anchor.txid);

	channel_id.blocknum = loc->blkheight;
	channel_id.txnum = loc->index;
	channel_id.outnum = peer->anchor.index;

	/* Set all sigs to zero */
	memset(node_signature, 0, sizeof(node_signature));
	memset(bitcoin_signature, 0, sizeof(bitcoin_signature));

	//FIXME(cdecker) Copy remote stored signatures into place
	if (pubkey_cmp(&dstate->id, peer->id) > 0) {
		node_id[0] = peer->id;
		node_id[1] = &dstate->id;
		bitcoin_key[0] = peer->id;
		bitcoin_key[1] = &dstate->id;
		my_node_signature = &node_signature[1];
		my_bitcoin_signature = &bitcoin_signature[1];
	} else {
		node_id[1] = peer->id;
		node_id[0] = &dstate->id;
		bitcoin_key[1] = peer->id;
		bitcoin_key[0] = &dstate->id;
		my_node_signature = &node_signature[0];
		my_bitcoin_signature = &bitcoin_signature[0];
	}

	/* Sign the node_id with the bitcoin_key, proves delegation */
	serialized = tal_arr(tmpctx, u8, 0);
	towire_pubkey(&serialized, &dstate->id);
	privkey_sign(dstate, serialized, tal_count(serialized), my_bitcoin_signature);

	/* Sign the entire packet with `node_id`, proves integrity and origin */
	serialized = towire_channel_announcement(tmpctx, &node_signature[0],
						 &node_signature[1],
						 &channel_id,
						 &bitcoin_signature[0],
						 &bitcoin_signature[1],
						 node_id[0],
						 node_id[1],
						 bitcoin_key[0],
						 bitcoin_key[1]);
	privkey_sign(dstate, serialized + 128, tal_count(serialized) - 128, my_node_signature);

	serialized = towire_channel_announcement(tmpctx, &node_signature[0],
						 &node_signature[1],
						 &channel_id,
						 &bitcoin_signature[0],
						 &bitcoin_signature[1],
						 node_id[0],
						 node_id[1],
						 bitcoin_key[0],
						 bitcoin_key[1]);
	broadcast(dstate, WIRE_CHANNEL_ANNOUNCEMENT, serialized, NULL);
	tal_free(tmpctx);
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
