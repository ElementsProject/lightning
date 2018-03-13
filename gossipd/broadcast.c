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

static struct queued_message *new_queued_message(tal_t *ctx,
						 const u8 *tag,
						 const u8 *payload)
{
	struct queued_message *msg = tal(ctx, struct queued_message);
	msg->tag = tal_dup_arr(msg, u8, tag, tal_len(tag), 0);
	msg->payload = tal_dup_arr(msg, u8, payload, tal_len(payload), 0);
	return msg;
}

bool replace_broadcast(struct broadcast_state *bstate, u64 *index,
		       const u8 *tag, const u8 *payload)
{
	struct queued_message *msg;
	bool evicted = false;

	msg = uintmap_get(&bstate->broadcasts, *index);
	if (msg) {
		assert(memeq(msg->tag, tal_len(msg->tag), tag, tal_len(tag)));
		uintmap_del(&bstate->broadcasts, *index);
		tal_free(msg);
		evicted = true;
	}

	*index = bstate->next_index;
	/* Now add the message to the queue */
	msg = new_queued_message(bstate, tag, payload);
	uintmap_add(&bstate->broadcasts, *index, msg);
	bstate->next_index++;
	return evicted;
}

struct queued_message *next_broadcast_message(struct broadcast_state *bstate, u64 last_index)
{
	return uintmap_after(&bstate->broadcasts, &last_index);
}
