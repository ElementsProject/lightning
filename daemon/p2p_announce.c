#include "daemon/broadcast.h"
#include "daemon/chaintopology.h"
#include "daemon/log.h"
#include "daemon/p2p_announce.h"
#include "daemon/packets.h"
#include "daemon/peer.h"
#include "daemon/peer_internal.h"
#include "daemon/routing.h"
#include "daemon/secrets.h"
#include "daemon/timeout.h"
#include "utils.h"

#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>

static void broadcast_channel_update(struct lightningd_state *dstate, struct peer *peer)
{
	struct txlocator *loc;
	u8 *serialized;
	secp256k1_ecdsa_signature signature;
	struct short_channel_id short_channel_id;
	u32 timestamp = time_now().ts.tv_sec;
	const tal_t *tmpctx = tal_tmpctx(dstate);

	loc = locate_tx(tmpctx, dstate->topology, &peer->anchor.txid);
	short_channel_id.blocknum = loc->blkheight;
	short_channel_id.txnum = loc->index;
	short_channel_id.outnum = peer->anchor.index;

	/* Avoid triggering memcheck */
	memset(&signature, 0, sizeof(signature));

	serialized = towire_channel_update(tmpctx, &signature, &short_channel_id,
					   timestamp,
					   pubkey_cmp(&dstate->id, peer->id) > 0,
					   dstate->config.min_htlc_expiry,
	//FIXME(cdecker) Make the minimum HTLC configurable
					   1,
					   dstate->config.fee_base,
					   dstate->config.fee_per_satoshi);
	privkey_sign(dstate, serialized + 66, tal_count(serialized) - 66,
		     &signature);
	serialized = towire_channel_update(tmpctx, &signature, &short_channel_id,
					   timestamp,
					   pubkey_cmp(&dstate->id, peer->id) > 0,
					   dstate->config.min_htlc_expiry,
					   1,
					   dstate->config.fee_base,
					   dstate->config.fee_per_satoshi);
	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_short_channel_id(&tag, &short_channel_id);
	queue_broadcast(dstate->rstate->broadcasts, WIRE_CHANNEL_UPDATE, tag, serialized);
	tal_free(tmpctx);
}

static void broadcast_node_announcement(struct lightningd_state *dstate)
{
	u8 *serialized;
	secp256k1_ecdsa_signature signature;
	static const u8 rgb_color[3];
	static const u8 alias[32];
	u32 timestamp = time_now().ts.tv_sec;
	const tal_t *tmpctx = tal_tmpctx(dstate);
	u8 *address;

	/* Are we listening for incoming connections at all? */
	if (!dstate->external_ip || !dstate->portnum) {
		tal_free(tmpctx);
		return;
	}

	/* Avoid triggering memcheck */
	memset(&signature, 0, sizeof(signature));

	address = write_ip(tmpctx, dstate->external_ip, dstate->portnum);
	serialized = towire_node_announcement(tmpctx, &signature,
					      timestamp,
					      &dstate->id, rgb_color, alias,
					      NULL,
					      address);
	privkey_sign(dstate, serialized + 66, tal_count(serialized) - 66,
		     &signature);
	serialized = towire_node_announcement(tmpctx, &signature,
					      timestamp,
					      &dstate->id, rgb_color, alias,
					      NULL,
					      address);
	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_pubkey(&tag, &dstate->id);
	queue_broadcast(dstate->rstate->broadcasts, WIRE_NODE_ANNOUNCEMENT, tag,
			serialized);
	tal_free(tmpctx);
}

static void broadcast_channel_announcement(struct lightningd_state *dstate, struct peer *peer)
{
	struct txlocator *loc;
	struct short_channel_id short_channel_id;
	secp256k1_ecdsa_signature node_signature[2];
	secp256k1_ecdsa_signature bitcoin_signature[2];
	const struct pubkey *node_id[2];
	const struct pubkey *bitcoin_key[2];
	secp256k1_ecdsa_signature *my_node_signature;
	secp256k1_ecdsa_signature *my_bitcoin_signature;
	u8 *serialized;
	const tal_t *tmpctx = tal_tmpctx(dstate);

	loc = locate_tx(tmpctx, dstate->topology, &peer->anchor.txid);

	short_channel_id.blocknum = loc->blkheight;
	short_channel_id.txnum = loc->index;
	short_channel_id.outnum = peer->anchor.index;

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

	/* BOLT #7:
	 *
	 * The creating node MUST compute the double-SHA256 hash `h` of the
	 * message, starting at offset 256, up to the end of the message.
	 */
	serialized = towire_channel_announcement(tmpctx, &node_signature[0],
						 &node_signature[1],
						 &bitcoin_signature[0],
						 &bitcoin_signature[1],
						 &short_channel_id,
						 node_id[0],
						 node_id[1],
						 bitcoin_key[0],
						 bitcoin_key[1],
						 NULL);
	privkey_sign(dstate, serialized + 256, tal_count(serialized) - 256, my_node_signature);

	serialized = towire_channel_announcement(tmpctx, &node_signature[0],
						 &node_signature[1],
						 &bitcoin_signature[0],
						 &bitcoin_signature[1],
						 &short_channel_id,
						 node_id[0],
						 node_id[1],
						 bitcoin_key[0],
						 bitcoin_key[1],
						 NULL);
	u8 *tag = tal_arr(tmpctx, u8, 0);
	towire_short_channel_id(&tag, &short_channel_id);
	queue_broadcast(dstate->rstate->broadcasts, WIRE_CHANNEL_ANNOUNCEMENT,
			tag, serialized);
	tal_free(tmpctx);
}

static void announce(struct lightningd_state *dstate)
{
	struct peer *p;
	int nchan = 0;

	new_reltimer(&dstate->timers, dstate, time_from_sec(5*60*60), announce, dstate);

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
	struct peer *p;
	struct queued_message *msg;
	new_reltimer(&dstate->timers, dstate, time_from_sec(30), process_broadcast_queue, dstate);
	list_for_each(&dstate->peers, p, list) {
		if (!state_is_normal(p->state))
			continue;
		msg = next_broadcast_message(dstate->rstate->broadcasts,
					     &p->broadcast_index);
		while (msg != NULL) {
			queue_pkt_nested(p, msg->type, msg->payload);
			msg = next_broadcast_message(dstate->rstate->broadcasts,
						     &p->broadcast_index);
		}
	}
}

void setup_p2p_announce(struct lightningd_state *dstate)
{
	new_reltimer(&dstate->timers, dstate, time_from_sec(5*60*60), announce, dstate);
	new_reltimer(&dstate->timers, dstate, time_from_sec(30), process_broadcast_queue, dstate);
}
