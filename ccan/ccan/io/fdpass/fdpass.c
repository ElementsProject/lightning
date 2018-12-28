/* GNU LGPL version 2 (or later) - see LICENSE file for details */
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io_plan.h>
#include <errno.h>

static int do_fd_send(int fd, struct io_plan_arg *arg)
{
	if (!fdpass_send(fd, arg->u1.s)) {
		/* In case ccan/io ever gets smart with non-blocking. */
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -1;
	}
	if (arg->u2.s)
		close(arg->u1.s);
	return 1;
}

struct io_plan *io_send_fd_(struct io_conn *conn,
			    int fd,
			    bool fdclose,
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_OUT);

	arg->u1.s = fd;
	arg->u2.s = fdclose;

	return io_set_plan(conn, IO_OUT, do_fd_send, next, next_arg);
}

static int do_fd_recv(int fd, struct io_plan_arg *arg)
{
	int fdin = fdpass_recv(fd);

	if (fdin < 0) {
		/* In case ccan/io ever gets smart with non-blocking. */
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -1;
	}
	*(int *)arg->u1.vp = fdin;
	return 1;
}

struct io_plan *io_recv_fd_(struct io_conn *conn,
			    int *fd,
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	arg->u1.vp = fd;

	return io_set_plan(conn, IO_IN, do_fd_recv, next, next_arg);
}
