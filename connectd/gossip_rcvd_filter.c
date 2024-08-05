#include "config.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable.h>
#include <ccan/ptrint/ptrint.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <connectd/gossip_rcvd_filter.h>
#include <wire/peer_wire.h>

/* We stash raw integers into ptrs, but leave two bits for htable code to use. */
static size_t msg_key(const u8 *msg)
{
	size_t key = siphash24(siphash_seed(), msg, tal_bytelen(msg));

	/* Avoid 0 and 1, which are invalid in the htable code. */
	return key | 0x3;
}

static size_t rehash(const void *key, void *unused)
{
	return ptr2int(key);
}

static struct htable *new_msg_map(const tal_t *ctx)
{
	struct htable *ht = tal(ctx, struct htable);

	htable_init(ht, rehash, NULL);
	return ht;
}

/* We age by keeping two maps, a current and an old one */
struct gossip_rcvd_filter {
	struct htable *cur, *old;
};

struct gossip_rcvd_filter *new_gossip_rcvd_filter(const tal_t *ctx)
{
	struct gossip_rcvd_filter *f = tal(ctx, struct gossip_rcvd_filter);

	f->cur = new_msg_map(f);
	f->old = new_msg_map(f);
	return f;
}

static bool is_msg_gossip_broadcast(const u8 *cursor)
{
	switch ((enum peer_wire)fromwire_peektype(cursor)) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
		return true;
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_ONION_MESSAGE:
	case WIRE_WARNING:
	case WIRE_INIT:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_READY:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_GOSSIP_STATUS:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_TX_INIT_RBF:
	case WIRE_TX_ACK_RBF:
	case WIRE_TX_ABORT:
	case WIRE_PEER_STORAGE:
	case WIRE_YOUR_PEER_STORAGE:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_STFU:
	case WIRE_SPLICE:
	case WIRE_SPLICE_ACK:
	case WIRE_SPLICE_LOCKED:
		break;
	}
	return false;
}

static bool extract_msg_key(const u8 *msg, size_t *key)
{
	if (!is_msg_gossip_broadcast(msg))
		return false;

	*key = msg_key(msg);
	return true;
}

/* Add a gossip msg to the received map */
void gossip_rcvd_filter_add(struct gossip_rcvd_filter *f, const u8 *msg)
{
	size_t key;

	if (extract_msg_key(msg, &key)) {
		htable_add(f->cur, key, int2ptr(key));
		/* Don't let it fill up forever. */
		if (htable_count(f->cur) > 500)
			gossip_rcvd_filter_age(f);
	}
}

/* htable is fast, but it's also horribly manual. */
static bool msg_map_remove(struct htable *ht, size_t key)
{
	struct htable_iter i;
	void *c;

	for (c = htable_firstval(ht, &i, key);
	     c;
	     c = htable_nextval(ht, &i, key)) {
		if (ptr2int(c) == key) {
			htable_del(ht, key, c);
			return true;
		}
	}
	return false;
}

/* Is a gossip msg in the received map? (Removes it) */
bool gossip_rcvd_filter_del(struct gossip_rcvd_filter *f, const u8 *msg)
{
	size_t key;

	if (!extract_msg_key(msg, &key))
		return false;

	/* Look in both for gossip. */
	return msg_map_remove(f->cur, key) || msg_map_remove(f->old, key);
}

/* Flush out old entries. */
void gossip_rcvd_filter_age(struct gossip_rcvd_filter *f)
{
	tal_free(f->old);
	f->old = f->cur;
	f->cur = new_msg_map(f);
}
