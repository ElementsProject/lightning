#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

static size_t bytes_written;

/* Should be called multiple times, since only writes 1 byte. */
static int do_controlled_write(int fd, struct io_plan_arg *arg)
{
	ssize_t ret;

	ret = write(fd, arg->u1.cp, 1);
	if (ret < 0)
		return -1;
	bytes_written += ret;
	arg->u1.cp += ret;
	arg->u2.s -= ret;
	return arg->u2.s == 0;
}

static int do_error(int fd, struct io_plan_arg *arg)
{
	errno = 1001;
	return -1;
}

static struct io_plan *conn_wait(struct io_conn *conn, void *unused)
{
	return io_wait(conn, conn, io_never, NULL);
}

static struct io_plan *init_conn_writer(struct io_conn *conn, const char *str)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_OUT);

	arg->u1.const_vp = str;
	arg->u2.s = strlen(str);

	return io_set_plan(conn, IO_OUT, do_controlled_write, conn_wait, NULL);
}

static struct io_plan *init_conn_reader(struct io_conn *conn, void *dst)
{
	/* Never actually succeeds. */
	return io_read(conn, dst, 1000, io_never, NULL);
}

static struct io_plan *init_conn_error(struct io_conn *conn, void *unused)
{
	io_plan_arg(conn, IO_OUT);
	return io_set_plan(conn, IO_OUT, do_error, io_never, NULL);
}

int main(void)
{
	int fd = open("/dev/null", O_RDWR);
	const tal_t *ctx = tal(NULL, char);
	struct io_conn *conn;

	/* This is how many tests you plan to run */
	plan_tests(9);

	conn = io_new_conn(ctx, fd, init_conn_writer, "hello");
	ok1(bytes_written == 0);

	ok1(io_flush_sync(conn));
	ok1(bytes_written == strlen("hello"));

	/* This won't do anything */
	ok1(io_flush_sync(conn));
	ok1(bytes_written == strlen("hello"));

	/* It's reading, this won't do anything. */
	conn = io_new_conn(ctx, fd, init_conn_reader, ctx);
	ok1(io_flush_sync(conn));
	ok1(bytes_written == strlen("hello"));

	/* Now test error state. */
	conn = io_new_conn(ctx, fd, init_conn_error, ctx);
	ok1(!io_flush_sync(conn));
	ok1(errno == 1001);

	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
