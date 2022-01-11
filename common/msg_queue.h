/* Helper for simple message queues. */
#ifndef LIGHTNING_COMMON_MSG_QUEUE_H
#define LIGHTNING_COMMON_MSG_QUEUE_H
#include "config.h"
#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>

/* Reserved type used to indicate we're actually passing an fd. */
#define MSG_PASS_FD 0xFFFF

/* Allocate a new msg queue; if we control all msgs we send/receive,
 * we can pass fds.  Otherwise, set @fd_passing to false. */
struct msg_queue *msg_queue_new(const tal_t *ctx, bool fd_passing);

/* If add is taken(), freed after sending.  msg_wake() implied. */
void msg_enqueue(struct msg_queue *q, const u8 *add TAKES);

/* Get current queue length */
size_t msg_queue_length(const struct msg_queue *q);

/* Fd is closed after sending.  msg_wake() implied. */
void msg_enqueue_fd(struct msg_queue *q, int fd);

/* Explicitly wake up a msg_queue_wait */
void msg_wake(const struct msg_queue *q);

/* Returns NULL if nothing to do. */
const u8 *msg_dequeue(struct msg_queue *q);

/* Returns -1 if not an fd: close after sending. */
int msg_extract_fd(const struct msg_queue *q, const u8 *msg);

#define msg_queue_wait(conn, q, next, arg) \
	io_out_wait((conn), (q), (next), (arg))

#endif /* LIGHTNING_COMMON_MSG_QUEUE_H */
