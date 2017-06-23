#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/take/take.h>
#include <lightningd/daemon_conn.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

struct io_plan *daemon_conn_read_next(struct io_conn *conn,
				      struct daemon_conn *dc)
{
	dc->msg_in = tal_free(dc->msg_in);
	return io_read_wire(conn, dc->ctx, &dc->msg_in, dc->daemon_conn_recv,
			    dc);
}

struct io_plan *daemon_conn_write_next(struct io_conn *conn,
				       struct daemon_conn *dc)
{
	const u8 *msg = msg_dequeue(&dc->out);
	if (msg) {
		int fd = msg_extract_fd(msg);
		if (fd >= 0)
			return io_send_fd(conn, fd, true,
					  daemon_conn_write_next, dc);
		return io_write_wire(conn, take(msg), daemon_conn_write_next,
				     dc);
	} else if (dc->msg_queue_cleared_cb) {
		return dc->msg_queue_cleared_cb(conn, dc);
	} else {
		return msg_queue_wait(conn, &dc->out,
				      daemon_conn_write_next, dc);
	}
}

bool daemon_conn_sync_flush(struct daemon_conn *dc)
{
	const u8 *msg;

	/* Flush any current packet. */
	if (!io_flush_sync(dc->conn))
		return false;

	/* Flush existing messages. */
	while ((msg = msg_dequeue(&dc->out)) != NULL) {
		int fd = msg_extract_fd(msg);
		if (fd >= 0) {
			if (!fdpass_send(io_conn_fd(dc->conn), fd))
				return false;
		} else if (!wire_sync_write(io_conn_fd(dc->conn), take(msg)))
			return false;
	}
	return true;
}

static struct io_plan *daemon_conn_start(struct io_conn *conn,
					 struct daemon_conn *dc)
{
	dc->conn = conn;
	return io_duplex(conn, daemon_conn_read_next(conn, dc),
			 daemon_conn_write_next(conn, dc));
}

void daemon_conn_init(tal_t *ctx, struct daemon_conn *dc, int fd,
		      struct io_plan *(*daemon_conn_recv)(struct io_conn *,
							  struct daemon_conn *),
		      void (*finish)(struct io_conn *, struct daemon_conn *dc))
{
	struct io_conn *conn;

	dc->daemon_conn_recv = daemon_conn_recv;

	dc->ctx = ctx;
	dc->msg_in = NULL;
	msg_queue_init(&dc->out, dc->ctx);
	dc->msg_queue_cleared_cb = NULL;
	conn = io_new_conn(ctx, fd, daemon_conn_start, dc);
	if (finish)
		io_set_finish(conn, finish, dc);
}

void daemon_conn_send(struct daemon_conn *dc, const u8 *msg)
{
	msg_enqueue(&dc->out, msg);
}

void daemon_conn_send_fd(struct daemon_conn *dc, int fd)
{
	msg_enqueue_fd(&dc->out, fd);
}
