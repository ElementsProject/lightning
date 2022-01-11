#include "config.h"
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <common/daemon_conn.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

struct daemon_conn {
	/* Last message we received */
	u8 *msg_in;

	/* Queue of outgoing messages */
	struct msg_queue *out;

	/* Underlying connection: we're freed if it closes, and vice versa */
	struct io_conn *conn;

	/* Callback for incoming messages */
	struct io_plan *(*recv)(struct io_conn *conn, const u8 *, void *);

	/* Called whenever we've cleared the msg_out queue. */
	void (*outq_empty)(void *);

	/* Arg for both callbacks. */
	void *arg;
};

static struct io_plan *handle_read(struct io_conn *conn,
				      struct daemon_conn *dc)
{
	return dc->recv(conn, dc->msg_in, dc->arg);
}

struct io_plan *daemon_conn_read_next(struct io_conn *conn,
				      struct daemon_conn *dc)
{
	/* FIXME: We could use disposable parent instead, and recv() could
	 * tal_steal() it?  If they did that now, we'd free it here. */
	tal_free(dc->msg_in);
	return io_read_wire(conn, dc, &dc->msg_in, handle_read, dc);
}

static struct io_plan *daemon_conn_write_next(struct io_conn *conn,
					      struct daemon_conn *dc)
{
	const u8 *msg;

	msg = msg_dequeue(dc->out);

	/* If nothing in queue, give empty callback a chance to queue somthing */
	if (!msg && dc->outq_empty) {
		dc->outq_empty(dc->arg);
		msg = msg_dequeue(dc->out);
	}

	if (msg) {
		int fd = msg_extract_fd(dc->out, msg);
		if (fd >= 0) {
			tal_free(msg);
			return io_send_fd(conn, fd, true,
					  daemon_conn_write_next, dc);
		}
		return io_write_wire(conn, take(msg), daemon_conn_write_next,
				     dc);
	}
	return msg_queue_wait(conn, dc->out, daemon_conn_write_next, dc);
}

bool daemon_conn_sync_flush(struct daemon_conn *dc)
{
	const u8 *msg;
	int daemon_fd;

	/* Flush any current packet. */
	if (!io_flush_sync(dc->conn))
		return false;

	/* Make fd blocking for the duration */
	daemon_fd = io_conn_fd(dc->conn);
	if (!io_fd_block(daemon_fd, true))
		return false;

	/* Flush existing messages. */
	while ((msg = msg_dequeue(dc->out)) != NULL) {
		int fd = msg_extract_fd(dc->out, msg);
		if (fd >= 0) {
			tal_free(msg);
			if (!fdpass_send(daemon_fd, fd))
				break;
		} else if (!wire_sync_write(daemon_fd, take(msg)))
			break;
	}
	io_fd_block(daemon_fd, false);

	/* Success if and only if we flushed them all. */
	return msg == NULL;
}

static struct io_plan *daemon_conn_start(struct io_conn *conn,
					 struct daemon_conn *dc)
{
	return io_duplex(conn, daemon_conn_read_next(conn, dc),
			 /* Could call daemon_conn_write_next, but we don't
			  * want it to call empty_cb just yet! */
			 msg_queue_wait(conn, dc->out,
					daemon_conn_write_next, dc));
}

static void destroy_dc_from_conn(struct io_conn *conn, struct daemon_conn *dc)
{
	/* Harmless free loop if conn is being destroyed because dc freed */
	tal_free(dc);
}

struct daemon_conn *daemon_conn_new_(const tal_t *ctx, int fd,
				     struct io_plan *(*recv)(struct io_conn *,
							     const u8 *,
							     void *),
				     void (*outq_empty)(void *),
				     void *arg)
{
	struct daemon_conn *dc = tal(NULL, struct daemon_conn);

	dc->recv = recv;
	dc->outq_empty = outq_empty;
	dc->arg = arg;
	dc->msg_in = NULL;
	dc->out = msg_queue_new(dc, true);

	dc->conn = io_new_conn(dc, fd, daemon_conn_start, dc);
	tal_add_destructor2(dc->conn, destroy_dc_from_conn, dc);
	return dc;
}

void daemon_conn_send(struct daemon_conn *dc, const u8 *msg)
{
	msg_enqueue(dc->out, msg);
}

void daemon_conn_send_fd(struct daemon_conn *dc, int fd)
{
	msg_enqueue_fd(dc->out, fd);
}

void daemon_conn_wake(struct daemon_conn *dc)
{
	msg_wake(dc->out);
}

size_t daemon_conn_queue_length(const struct daemon_conn *dc)
{
	return msg_queue_length(dc->out);
}
