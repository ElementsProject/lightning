#include <ccan/mem/mem.h>
#include <gossipd/broadcast.h>

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
						 const u8 *payload TAKES,
						 u64 index)
{
	struct queued_message *msg = tal(ctx, struct queued_message);
	msg->payload = tal_dup_arr(msg, u8, payload, tal_len(payload), 0);
	msg->index = index;
	uintmap_add(&bstate->broadcasts, index, msg);
	tal_add_destructor2(msg, destroy_queued_message, bstate);
	return msg;
}

bool replace_broadcast(const tal_t *ctx,
		       struct broadcast_state *bstate,
		       u64 *index,
		       const u8 *payload TAKES)
{
	struct queued_message *msg;
	bool evicted = false;

	msg = uintmap_get(&bstate->broadcasts, *index);
	if (msg) {
		tal_free(msg);
		evicted = true;
	}

	/* Now add the message to the queue */
	msg = new_queued_message(ctx, bstate, payload, bstate->next_index++);
	*index = msg->index;
	return evicted;
}

struct queued_message *next_broadcast_message(struct broadcast_state *bstate, u64 last_index)
{
	return uintmap_after(&bstate->broadcasts, &last_index);
}
