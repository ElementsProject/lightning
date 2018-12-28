#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>

static struct io_conn *in_conn;

static struct io_plan *in_conn_done(struct io_conn *conn, void *unused)
{
	ok1(!io_plan_in_started(conn));
	return io_close(conn);
}

static struct io_plan *init_in_conn(struct io_conn *conn, char *buf)
{
	ok1(!io_plan_in_started(conn));
	return io_read(conn, buf, 2, in_conn_done, NULL);
}

static int do_nothing(int fd, struct io_plan_arg *arg)
{
	return 1;
}

static struct io_plan *dummy_write(struct io_conn *conn,
				   struct io_plan *(*next)
				   (struct io_conn *, void *),
				   void *next_arg)
{
	io_plan_arg(conn, IO_OUT);
	return io_set_plan(conn, IO_OUT, do_nothing, next, next_arg);
}

static struct io_plan *out_post_write(struct io_conn *conn, void *unused)
{
	/* It might not have started yet: try again. */
	if (!io_plan_in_started(in_conn))
		return dummy_write(conn, out_post_write, NULL);
	ok1(io_plan_in_started(in_conn));

	/* Final write, then close */
	return io_write(conn, "2", 1, io_close_cb, NULL);
}

static struct io_plan *init_out_conn(struct io_conn *conn, void *unused)
{
	ok1(!io_plan_in_started(in_conn));
	return io_write(conn, "1", 1, out_post_write, NULL);
}

int main(void)
{
	int fds[2];
	const tal_t *ctx = tal(NULL, char);
	char *buf = tal_arr(ctx, char, 3);

	/* This is how many tests you plan to run */
	plan_tests(5);

	if (pipe(fds) != 0)
		abort();

	buf[2] = '\0';

	in_conn = io_new_conn(ctx, fds[0], init_in_conn, buf);
	io_new_conn(ctx, fds[1], init_out_conn, NULL);

	io_loop(NULL, NULL);
	ok1(strcmp(buf, "12") == 0);
	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
