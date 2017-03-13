#include <lightningd/msg_queue.h>

void msg_queue_init(struct msg_queue *q, const tal_t *ctx)
{
	q->q = tal_arr(ctx, const u8 *, 0);
	q->ctx = ctx;
}

void msg_enqueue(struct msg_queue *q, const u8 *add)
{
	size_t n = tal_count(q->q);
	tal_resize(&q->q, n+1);
	q->q[n] = tal_dup_arr(q->ctx, u8, add, tal_len(add), 0);

	/* In case someone is waiting */
	io_wake(q);
}

const u8 *msg_dequeue(struct msg_queue *q)
{
	size_t n = tal_count(q->q);
	const u8 *msg;

	if (!n)
		return NULL;

	msg = q->q[0];
	memmove(q->q, q->q + 1, sizeof(*q->q) * (n-1));
	tal_resize(&q->q, n-1);
	return msg;
}
