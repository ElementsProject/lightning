#include <assert.h>
#include <ccan/take/take.h>
#include <common/msg_queue.h>
#include <wire/wire.h>

void msg_queue_init(struct msg_queue *q, const tal_t *ctx)
{
	q->q = tal_arr(ctx, const u8 *, 0);
	q->ctx = ctx;
}

static void do_enqueue(struct msg_queue *q, const u8 *add)
{
	size_t n = tal_count(q->q);
	tal_resize(&q->q, n+1);
	q->q[n] = tal_dup_arr(q->ctx, u8, add, tal_count(add), 0);

	/* In case someone is waiting */
	io_wake(q);
}

void msg_enqueue(struct msg_queue *q, const u8 *add)
{
	assert(fromwire_peektype(add) != MSG_PASS_FD);
	do_enqueue(q, add);
}

void msg_enqueue_fd(struct msg_queue *q, int fd)
{
	u8 *fdmsg = tal_arr(q->ctx, u8, 0);
	towire_u16(&fdmsg, MSG_PASS_FD);
	towire_u32(&fdmsg, fd);
	do_enqueue(q, take(fdmsg));
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

int msg_extract_fd(const u8 *msg)
{
	const u8 *p = msg + sizeof(u16);
	size_t len = tal_count(msg) - sizeof(u16);

	if (fromwire_peektype(msg) != MSG_PASS_FD)
		return -1;

	return fromwire_u32(&p, &len);
}

void msg_wake(const struct msg_queue *q)
{
	io_wake(q);
}
