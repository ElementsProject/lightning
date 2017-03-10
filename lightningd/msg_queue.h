/* Helper for simple message queues. */
#ifndef LIGHTNING_LIGHTNINGD_MSG_QUEUE_H
#define LIGHTNING_LIGHTNINGD_MSG_QUEUE_H
#include "config.h"
#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>

struct msg_queue {
	const u8 **q;
};

void msg_queue_init(struct msg_queue *q, const tal_t *ctx);

void msg_enqueue(struct msg_queue *q, const u8 *add);

const u8 *msg_dequeue(struct msg_queue *q);

#define msg_queue_wait(conn, q, next, arg) \
	io_out_wait((conn), (q), (next), (arg))

#endif /* LIGHTNING_LIGHTNINGD_MSG_QUEUE_H */
