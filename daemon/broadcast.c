#include "daemon/broadcast.h"

struct broadcast_state *new_broadcast_state(tal_t *ctx)
{
	struct broadcast_state *bstate = tal(ctx, struct broadcast_state);
	uintmap_init(&bstate->broadcasts);
	/* Skip 0 because we initialize peers with 0 */
	bstate->next_index = 1;
	return bstate;
}

static struct queued_message *new_queued_message(tal_t *ctx,
						 const int type,
						 const u8 *tag,
						 const u8 *payload)
{
	struct queued_message *msg = tal(ctx, struct queued_message);
	msg->type = type;
	msg->tag = tal_dup_arr(msg, u8, tag, tal_count(tag), 0);
	msg->payload = tal_dup_arr(msg, u8, payload, tal_count(payload), 0);
	return msg;
}

void queue_broadcast(struct broadcast_state *bstate,
		     const int type,
		     const u8 *tag,
		     const u8 *payload)
{
	struct queued_message *msg = new_queued_message(bstate, type, tag, payload);

	/*FIXME(cdecker) Walk through old messages and purge collisions */
	uintmap_add(&bstate->broadcasts, bstate->next_index, msg);
	bstate->next_index += 1;
}

struct queued_message *next_broadcast_message(struct broadcast_state *bstate, u64 *last_index)
{
	return uintmap_after(&bstate->broadcasts, last_index);
}
