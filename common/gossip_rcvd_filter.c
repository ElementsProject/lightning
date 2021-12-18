#include "config.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable.h>
#include <common/gossip_rcvd_filter.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <wire/peer_wire.h>

static u64 msg_key(const u8 *msg)
{
	return siphash24(siphash_seed(), msg, tal_bytelen(msg));
}

static size_t rehash(const void *key, void *unused)
{
	return *(u64 *)key;
}

static void destroy_msg_map(struct htable *ht)
{
	htable_clear(ht);
}

static struct htable *new_msg_map(const tal_t *ctx)
{
	struct htable *ht = tal(ctx, struct htable);

	htable_init(ht, rehash, NULL);
	tal_add_destructor(ht, destroy_msg_map);
	return ht;
}

/* We age by keeping two maps, a current and an old one */
struct gossip_rcvd_filter {
	struct htable *cur, *old;
};

#if DEVELOPER
static void memleak_help_gossip_rcvd_filter(struct htable *memtable,
					    struct gossip_rcvd_filter *grf)
{
	memleak_remove_htable(memtable, grf->cur);
	memleak_remove_htable(memtable, grf->old);
}
#endif

struct gossip_rcvd_filter *new_gossip_rcvd_filter(const tal_t *ctx)
{
	struct gossip_rcvd_filter *f = tal(ctx, struct gossip_rcvd_filter);

	f->cur = new_msg_map(f);
	f->old = new_msg_map(f);
	memleak_add_helper(f, memleak_help_gossip_rcvd_filter);
	return f;
}

static bool extract_msg_key(const u8 *msg, u64 *key)
{
	int type = fromwire_peektype(msg);

	if (type != WIRE_CHANNEL_ANNOUNCEMENT
	    && type != WIRE_NODE_ANNOUNCEMENT
	    && type != WIRE_CHANNEL_UPDATE)
		return false;

	*key = msg_key(msg);
	return true;
}

/* Add a gossip msg to the received map */
void gossip_rcvd_filter_add(struct gossip_rcvd_filter *f, const u8 *msg)
{
	u64 key;

	/* We don't attach destructor here directly to tag; would be neat,
	 * but it's also an extra allocation. */
	if (extract_msg_key(msg, &key)) {
		htable_add(f->cur, key, tal_dup(f->cur, u64, &key));
		/* Don't let it fill up forever though. */
		if (htable_count(f->cur) > 10000)
			gossip_rcvd_filter_age(f);
	}
}

/* htable is fast, but it's also horribly manual. */
static bool msg_map_remove(struct htable *ht, u64 key)
{
	struct htable_iter i;
	u64 *c;

	for (c = htable_firstval(ht, &i, key);
	     c;
	     c = htable_nextval(ht, &i, key)) {
		if (*c == key) {
			htable_del(ht, key, c);
			tal_free(c);
			return true;
		}
	}
	return false;
}

/* Is a gossip msg in the received map? (Removes it) */
bool gossip_rcvd_filter_del(struct gossip_rcvd_filter *f, const u8 *msg)
{
	u64 key;

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
