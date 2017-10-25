#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>

static struct io_conn *out_conn;

/* Write one byte at a time. */
static int do_slow_write(int fd, struct io_plan_arg *arg)
{
	ssize_t ret = write(fd, arg->u1.cp, 1);
	if (ret < 0)
		return -1;

	arg->u1.cp += ret;
	arg->u2.s -= ret;
	return arg->u2.s == 0;
}

static struct io_plan *io_slow_write(struct io_conn *conn,
				     const void *data, size_t len,
				     struct io_plan *(*next)(struct io_conn *,
							     void *),
				     void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_OUT);

	arg->u1.const_vp = data;
	arg->u2.s = len;

	return io_set_plan(conn, IO_OUT, do_slow_write, next, next_arg);
}

static struct io_plan *out_conn_done(struct io_conn *conn, void *unused)
{
	ok1(!io_plan_out_started(conn));
	return io_close(conn);
}

static struct io_plan *init_out_conn(struct io_conn *conn, void *unused)
{
	ok1(!io_plan_out_started(conn));
	return io_slow_write(conn, "12", 2, out_conn_done, NULL);
}

static int do_nothing(int fd, struct io_plan_arg *arg)
{
	return 1;
}

static struct io_plan *dummy_read(struct io_conn *conn,
				  struct io_plan *(*next)
				  (struct io_conn *, void *),
				  void *next_arg)
{
	io_plan_arg(conn, IO_IN);
	return io_set_plan(conn, IO_IN, do_nothing, next, next_arg);
}

static struct io_plan *in_post_read(struct io_conn *conn, void *buf)
{
	/* It might not have started yet: try again. */
	if (!io_plan_out_started(out_conn))
		return dummy_read(conn, in_post_read, NULL);
	ok1(io_plan_out_started(out_conn));

	/* Final read, then close */
	return io_read(conn, (char *)buf+1, 1, io_close_cb, NULL);
}

static struct io_plan *init_in_conn(struct io_conn *conn, char *buf)
{
	return io_read(conn, buf, 1, in_post_read, buf);
}

int main(void)
{
	int fds[2];
	const tal_t *ctx = tal(NULL, char);
	char *buf = tal_arr(ctx, char, 3);

	/* This is how many tests you plan to run */
	plan_tests(4);

	if (pipe(fds) != 0)
		abort();

	buf[2] = '\0';

	io_new_conn(ctx, fds[0], init_in_conn, buf);
	out_conn = io_new_conn(ctx, fds[1], init_out_conn, NULL);

	io_loop(NULL, NULL);
	ok1(strcmp(buf, "12") == 0);
	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
