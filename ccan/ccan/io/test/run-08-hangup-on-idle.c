#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

static int fds2[2];

static struct io_plan *read_in(struct io_conn *conn, char *buf)
{
	return io_read(conn, buf, 16, io_close_cb, NULL);
}

static struct io_plan *setup_waiter(struct io_conn *conn, char *buf)
{
	return io_wait(conn, buf, read_in, buf);
}

static struct io_plan *wake_and_close(struct io_conn *conn, char *buf)
{
	io_wake(buf);
	return io_close(conn);
}

static struct io_plan *setup_waker(struct io_conn *conn, char *buf)
{
	return io_read(conn, buf, 1, wake_and_close, buf);
}

int main(void)
{
	int fds[2];
	char buf[16];

	plan_tests(4);

	ok1(pipe(fds) == 0);

	io_new_conn(NULL, fds[0], setup_waiter, buf);
	ok1(pipe(fds2) == 0);
	io_new_conn(NULL, fds2[0], setup_waker, buf);

	if (fork() == 0) {
		write(fds[1], "hello there world", 16);
		close(fds[1]);

		/* Now wake it. */
		sleep(1);
		write(fds2[1], "", 1);
		exit(0);
	}

	ok1(io_loop(NULL, NULL) == NULL);
	ok1(memcmp(buf, "hello there world", 16) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
