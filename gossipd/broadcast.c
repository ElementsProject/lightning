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
						 const int type,
						 const u8 *tag,
						 const u8 *payload)
{
	struct queued_message *msg = tal(ctx, struct queued_message);
	msg->type = type;
	msg->tag = tal_dup_arr(msg, u8, tag, tal_len(tag), 0);
	msg->payload = tal_dup_arr(msg, u8, payload, tal_len(payload), 0);
	return msg;
}

bool replace_broadcast(struct broadcast_state *bstate, u64 *index,
		       const int type, const u8 *tag, const u8 *payload)
{
	struct queued_message *msg;
	bool evicted = false;

	msg = uintmap_get(&bstate->broadcasts, *index);
	if (msg && msg->type == type &&
	    memeq(msg->tag, tal_len(msg->tag), tag, tal_len(tag))) {
		uintmap_del(&bstate->broadcasts, *index);
		tal_free(msg);
		evicted = true;
	}

	*index = bstate->next_index;
	/* Now add the message to the queue */
	msg = new_queued_message(bstate, type, tag, payload);
	uintmap_add(&bstate->broadcasts, *index, msg);
	bstate->next_index++;
	return evicted;
}

bool queue_broadcast(struct broadcast_state *bstate,
		     const int type,
		     const u8 *tag,
		     const u8 *payload)
{
	struct queued_message *msg;
	u64 index;
	bool evicted = false;

	memcheck(tag, tal_len(tag));

	/* Remove any tag&type collisions */
	for (msg = uintmap_first(&bstate->broadcasts, &index);
	     msg;
	     msg = uintmap_after(&bstate->broadcasts, &index)) {
		if (msg->type == type &&
		    memeq(msg->tag, tal_len(msg->tag), tag, tal_len(tag))) {
			uintmap_del(&bstate->broadcasts, index);
			tal_free(msg);
			evicted = true;
			break;
		}
	}

	/* Now add the message to the queue */
	msg = new_queued_message(bstate, type, tag, payload);
	uintmap_add(&bstate->broadcasts, bstate->next_index, msg);
	bstate->next_index += 1;
	return evicted;
}

struct queued_message *next_broadcast_message(struct broadcast_state *bstate, u64 last_index)
{
	return uintmap_after(&bstate->broadcasts, &last_index);
}
