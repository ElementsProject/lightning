#include "config.h"
#include <assert.h>
#include <ccan/cast/cast.h>
#include <common/msg_queue.h>
#include <common/utils.h>
#include <wire/wire.h>

struct msg_queue {
	bool fd_passing;
	const u8 **q;
};

static int extract_fd(const u8 *msg)
{
	const u8 *p = msg + sizeof(u16);
	size_t len = tal_count(msg) - sizeof(u16);

	if (fromwire_peektype(msg) != MSG_PASS_FD)
		return -1;

	return fromwire_u32(&p, &len);
}

/* Close any fds left in queue! */
static void destroy_msg_queue(struct msg_queue *q)
{
	for (size_t i = 0; i < tal_count(q->q); i++) {
		int fd = extract_fd(q->q[i]);
		if (fd != -1)
			close(fd);
	}
}

struct msg_queue *msg_queue_new(const tal_t *ctx, bool fd_passing)
{
	struct msg_queue *q = tal(ctx, struct msg_queue);
	q->fd_passing = fd_passing;
	q->q = tal_arr(q, const u8 *, 0);

	if (q->fd_passing)
		tal_add_destructor(q, destroy_msg_queue);
	return q;
}

static void do_enqueue(struct msg_queue *q, const u8 *add TAKES)
{
	tal_arr_expand(&q->q, tal_dup_talarr(q, u8, add));

	/* In case someone is waiting */
	io_wake(q);
}

size_t msg_queue_length(const struct msg_queue *q)
{
	return tal_count(q->q);
}

void msg_enqueue(struct msg_queue *q, const u8 *add)
{
	if (q->fd_passing)
		assert(fromwire_peektype(add) != MSG_PASS_FD);
	do_enqueue(q, add);
}

void msg_enqueue_fd(struct msg_queue *q, int fd)
{
	u8 *fdmsg = tal_arr(q, u8, 0);
	assert(q->fd_passing);
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

int msg_extract_fd(const struct msg_queue *q, const u8 *msg)
{
	assert(q->fd_passing);

	return extract_fd(msg);
}

void msg_wake(const struct msg_queue *q)
{
	io_wake(q);
}
