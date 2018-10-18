#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

static size_t len;

static void finished_read(struct io_conn *conn, int *expect)
{
	ok1(errno == *expect);
}

static struct io_plan *init_conn_read(struct io_conn *conn, int *expect)
{
	io_set_finish(conn, finished_read, expect);
	return io_read(conn, &expect, sizeof(expect), io_never, expect);
}

static struct io_plan *init_conn_read_partial(struct io_conn *conn, int *expect)
{
	io_set_finish(conn, finished_read, expect);
	return io_read_partial(conn, &expect, sizeof(expect), &len,
			       io_never, expect);
}

int main(void)
{
	int fd, expect_errno = 0;

	/* This is how many tests you plan to run */
	plan_tests(2);
	fd = open("/dev/null", O_RDONLY);
	io_new_conn(NULL, fd, init_conn_read, &expect_errno);

	fd = open("/dev/null", O_RDONLY);
	io_new_conn(NULL, fd, init_conn_read_partial, &expect_errno);

	io_loop(NULL, NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
