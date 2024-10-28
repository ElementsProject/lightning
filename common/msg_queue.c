#include "config.h"
#include <assert.h>
#include <ccan/cast/cast.h>
#include <ccan/membuf/membuf.h>
#include <common/daemon.h>
#include <common/msg_queue.h>
#include <common/utils.h>
#include <wire/wire.h>

static bool warned_once;

struct msg_queue {
	bool fd_passing;
	MEMBUF(const u8 *) mb;
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
	const u8 **elems = membuf_elems(&q->mb);
	for (size_t i = 0; i < membuf_num_elems(&q->mb); i++) {
		int fd = extract_fd(elems[i]);
		if (fd != -1)
			close(fd);
	}
}

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb, void *rawelems,
				size_t newsize)
{
	char *p = rawelems;

	tal_resize(&p, newsize);
	return p;
}

struct msg_queue *msg_queue_new(const tal_t *ctx, bool fd_passing)
{
	struct msg_queue *q = tal(ctx, struct msg_queue);
	q->fd_passing = fd_passing;
	membuf_init(&q->mb, tal_arr(q, const u8 *, 0), 0, membuf_tal_realloc);

	if (q->fd_passing)
		tal_add_destructor(q, destroy_msg_queue);
	return q;
}

static void do_enqueue(struct msg_queue *q, const u8 *add TAKES)
{
	const u8 **msg = membuf_add(&q->mb, 1);

	*msg = tal_dup_talarr(q, u8, add);

	if (!warned_once && msg_queue_length(q) > 100000) {
		/* Can cause re-entry, so set flag first! */
		warned_once = true;
		send_backtrace("excessive queue length");
	}

	/* In case someone is waiting */
	io_wake(q);
}

size_t msg_queue_length(const struct msg_queue *q)
{
	return membuf_num_elems(&q->mb);
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
	size_t n = msg_queue_length(q);

	if (!n)
		return NULL;

	return membuf_consume(&q->mb, 1)[0];
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
