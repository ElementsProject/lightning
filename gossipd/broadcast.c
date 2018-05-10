#include <ccan/mem/mem.h>
#include <gossipd/broadcast.h>

struct queued_message {
	/* Broadcast index. */
	u64 index;

	/* Serialized payload */
	const u8 *payload;
};

struct broadcast_state *new_broadcast_state(tal_t *ctx)
{
	struct broadcast_state *bstate = tal(ctx, struct broadcast_state);
	uintmap_init(&bstate->broadcasts);
	/* Skip 0 because we initialize peers with 0 */
	bstate->next_index = 1;
	return bstate;
}

static void destroy_queued_message(struct queued_message *msg,
				   struct broadcast_state *bstate)
{
	uintmap_del(&bstate->broadcasts, msg->index);
}

static struct queued_message *new_queued_message(const tal_t *ctx,
						 struct broadcast_state *bstate,
						 const u8 *payload,
						 u64 index)
{
	struct queued_message *msg = tal(ctx, struct queued_message);
	msg->payload = payload;
	msg->index = index;
	uintmap_add(&bstate->broadcasts, index, msg);
	tal_add_destructor2(msg, destroy_queued_message, bstate);
	return msg;
}

void insert_broadcast(struct broadcast_state *bstate, const u8 *payload)
{
	/* Free payload, free index. */
	new_queued_message(payload, bstate, payload, bstate->next_index++);
}

const u8 *next_broadcast(struct broadcast_state *bstate, u64 *last_index)
{
	struct queued_message *m;

	m = uintmap_after(&bstate->broadcasts, last_index);
	if (m)
		return m->payload;
	return NULL;
}
