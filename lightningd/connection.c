#include "connection.h"
#include <ccan/take/take.h>
#include <wire/wire_io.h>

static void daemon_conn_enqueue(struct daemon_conn *dc, u8 *msg)
{
	size_t n = tal_count(dc->msg_out);
	tal_resize(&dc->msg_out, n + 1);
	dc->msg_out[n] = tal_dup_arr(dc->ctx, u8, msg, tal_count(msg), 0);
}

static const u8 *daemon_conn_dequeue(struct daemon_conn *dc)
{
	const u8 *msg;
	size_t n = tal_count(dc->msg_out);

	if (n == 0)
		return NULL;
	msg = dc->msg_out[0];
	memmove(dc->msg_out, dc->msg_out + 1, sizeof(dc->msg_in[0]) * (n - 1));
	tal_resize(&dc->msg_out, n - 1);
	return msg;
}

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
	const u8 *msg = daemon_conn_dequeue(dc);
	if (msg) {
		return io_write_wire(conn, take(msg), daemon_conn_write_next,
				     dc);
	} else if (dc->msg_queue_cleared_cb) {
		return dc->msg_queue_cleared_cb(conn, dc);
	} else {
		return io_out_wait(conn, dc, daemon_conn_write_next, dc);
	}
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
							  struct daemon_conn *))
{
	dc->daemon_conn_recv = daemon_conn_recv;

	dc->ctx = ctx;
	dc->msg_in = NULL;
	dc->msg_out = tal_arr(ctx, u8 *, 0);
	dc->conn_fd = fd;
	dc->msg_queue_cleared_cb = NULL;
	io_new_conn(ctx, fd, daemon_conn_start, dc);
}

void daemon_conn_send(struct daemon_conn *dc, u8 *msg)
{
	daemon_conn_enqueue(dc, msg);
	io_wake(dc);
}
