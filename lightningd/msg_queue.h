/* Helper for simple message queues. */
#ifndef LIGHTNING_LIGHTNINGD_MSG_QUEUE_H
#define LIGHTNING_LIGHTNINGD_MSG_QUEUE_H
#include "config.h"
#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>

/* Reserved type used to indicate we're actually passing an fd. */
#define MSG_PASS_FD 0xFFFF

struct msg_queue {
	const u8 **q;
	const tal_t *ctx;
};

void msg_queue_init(struct msg_queue *q, const tal_t *ctx);

/* If add is taken(), freed after sending. */
void msg_enqueue(struct msg_queue *q, const u8 *add);

/* Fd is closed after sending. */
void msg_enqueue_fd(struct msg_queue *q, int fd);

/* Returns NULL if nothing to do. */
const u8 *msg_dequeue(struct msg_queue *q);

/* Returns -1 if not an fd: close after sending. */
int msg_is_fd(const u8 *msg);

#define msg_queue_wait(conn, q, next, arg) \
	io_out_wait((conn), (q), (next), (arg))

#endif /* LIGHTNING_LIGHTNINGD_MSG_QUEUE_H */
