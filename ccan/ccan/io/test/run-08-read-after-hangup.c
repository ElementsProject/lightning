#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>

static char inbuf[8];

static struct io_plan *wake_it(struct io_conn *conn, struct io_conn *reader)
{
	io_wake(inbuf);
	return io_close(conn);
}

static struct io_plan *read_buf(struct io_conn *conn, void *unused)
{
	return io_read(conn, inbuf, 8, io_close_cb, NULL);
}

static struct io_plan *init_writer(struct io_conn *conn, struct io_conn *wakeme)
{
	return io_write(conn, "EASYTEST", 8, wake_it, wakeme);
}

static struct io_plan *init_waiter(struct io_conn *conn, void *unused)
{
	return io_wait(conn, inbuf, read_buf, NULL);
}

int main(void)
{
	int fds[2];
	struct io_conn *conn;

	plan_tests(3);

	ok1(pipe(fds) == 0);
	conn = io_new_conn(NULL, fds[0], init_waiter, NULL);
	io_new_conn(conn, fds[1], init_writer, conn);

	ok1(io_loop(NULL, NULL) == NULL);
	ok1(memcmp(inbuf, "EASYTEST", sizeof(inbuf)) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
