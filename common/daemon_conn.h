#ifndef LIGHTNING_COMMON_DAEMON_CONN_H
#define LIGHTNING_COMMON_DAEMON_CONN_H

#include "config.h"
#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>
#include <common/msg_queue.h>

struct daemon_conn {
	/* Context to tallocate all things from, possibly the
	 * container of this connection. */
	tal_t *ctx;

	/* Last message we received */
	u8 *msg_in;

	/* Queue of outgoing messages */
	struct msg_queue out;

	/* Underlying connection */
	struct io_conn *conn;

	/* Callback for incoming messages */
	struct io_plan *(*daemon_conn_recv)(struct io_conn *conn,
					    struct daemon_conn *);

	/* Called whenever we've cleared the msg_out queue. If it returns
	 * true, it has added packets to msg_out queue. */
	bool (*msg_queue_cleared_cb)(struct io_conn *, struct daemon_conn *);
};

/**
 * daemon_conn_init - Initialize a new daemon connection
 *
 * @ctx: context to allocate from
 * @dc: daemon_conn to initialize
 * @fd: socket file descriptor to wrap
 * @daemon_conn_recv: callback function to be called upon receiving a message
 * @finish: finish function if connection is closed (can be NULL)
 */
void daemon_conn_init(tal_t *ctx, struct daemon_conn *dc, int fd,
		      struct io_plan *(*daemon_conn_recv)(
			  struct io_conn *, struct daemon_conn *),
		      void (*finish)(struct io_conn *, struct daemon_conn *));

/**
 * daemon_conn_clear - discard a daemon conn without triggering finish.
 * @dc: the daemon_conn to clean up.
 *
 * This is used by gossipd when a peer is handed back, and we no longer
 * want to deal with it via daemon_conn.  @dc must not be used after this!
 */
void daemon_conn_clear(struct daemon_conn *dc);

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
 * daemon_conn_write_next - Continue writing from the msg-queue
 *
 * Exposed here so that, if `msg_queue_cleared_cb` is used to break
 * out of the write-loop, we can get back in.
 */
struct io_plan *daemon_conn_write_next(struct io_conn *conn,
				       struct daemon_conn *dc);

/**
 * daemon_conn_read_next - Read the next message
 */
struct io_plan *daemon_conn_read_next(struct io_conn *conn,
				      struct daemon_conn *dc);

/**
 * daemon_conn_sync_flush - Flush connection by sending all messages now..
 */
bool daemon_conn_sync_flush(struct daemon_conn *dc);
#endif /* LIGHTNING_COMMON_DAEMON_CONN_H */
