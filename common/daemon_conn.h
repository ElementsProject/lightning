#ifndef LIGHTNING_COMMON_DAEMON_CONN_H
#define LIGHTNING_COMMON_DAEMON_CONN_H

#include "config.h"
#include <common/msg_queue.h>

/**
 * daemon_conn_new - Allocate a new daemon connection
 *
 * @ctx: context to allocate the daemon_conn's conn from
 * @fd: socket file descriptor to wrap
 * @recv: callback function to be called upon receiving a message
 * @outq_empty: callback function to be called when queue is empty: returns
 *     true if it added something to the queue.  Can be NULL.
 */
#define daemon_conn_new(ctx, fd, recv, outq_empty, arg)		       \
	daemon_conn_new_((ctx), (fd),				       \
			 typesafe_cb_preargs(struct io_plan *, void *, \
					     (recv), (arg), 	       \
					     struct io_conn *,		\
					     const u8 *),		\
			 typesafe_cb(void, void *,  (outq_empty), (arg)), \
			 arg)

struct daemon_conn *daemon_conn_new_(const tal_t *ctx, int fd,
				     struct io_plan *(*recv)(struct io_conn *,
							     const u8 *,
							     void *),
				     void (*outq_empty)(void *),
				     void *arg);

/**
 * daemon_conn_send - Enqueue an outgoing message to be sent
 */
void daemon_conn_send(struct daemon_conn *dc, const u8 *msg);

/**
 * daemon_conn_wake - Wake queue (fires msg_queue_cleared_cb if queue empty)
 */
void daemon_conn_wake(struct daemon_conn *dc);

/**
 * daemon_conn_send_fd - Enqueue a file descriptor to be sent (closed after)
 */
void daemon_conn_send_fd(struct daemon_conn *dc, int fd);

/**
 * daemon_conn_read_next - Read the next message
 */
struct io_plan *daemon_conn_read_next(struct io_conn *conn,
				      struct daemon_conn *dc);

/**
 * daemon_conn_sync_flush - Flush connection by sending all messages now..
 */
bool daemon_conn_sync_flush(struct daemon_conn *dc);

/**
 * daemon_conn_queue_length - Get number of message in outgoing queue.
 */
size_t daemon_conn_queue_length(const struct daemon_conn *dc);

#endif /* LIGHTNING_COMMON_DAEMON_CONN_H */
