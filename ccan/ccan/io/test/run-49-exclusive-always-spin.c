#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Regression test: an exclusive io_conn plus a pending non-exclusive
 * always plan must not make io_loop spin on poll() with timeout 0.
 * The always plan may not run (documented), but the loop should block
 * on the exclusive conn's fd instead of busy-polling. */

static int b_wait, a_wait;
static int armed;
static unsigned int zero_timeout_polls;
static int good, bad;

static int checking_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	if (armed) {
		if (timeout == 0) {
			/* Spinning: always plans pending but none runnable. */
			if (++zero_timeout_polls > 100)
				io_break(&bad);
		} else {
			/* Correct: blocking poll (or finite timer). */
			io_break(&good);
			return 0;
		}
	}
	return poll(fds, nfds, timeout);
}

static struct io_plan *b_woken(struct io_conn *conn, void *unused)
{
	/* Must not run while the other conn is exclusive. */
	return io_close(conn);
}

static struct io_plan *init_b(struct io_conn *conn, void *unused)
{
	return io_wait(conn, &b_wait, b_woken, NULL);
}

static struct io_plan *a_got_data(struct io_conn *conn, char *buf)
{
	io_conn_exclusive(conn, true);
	/* Queue B's always plan (non-exclusive, cannot run). */
	io_wake(&b_wait);
	armed = 1;
	/* Sleep forever. */
	return io_wait(conn, &a_wait, io_never, NULL);
}

static struct io_plan *init_a(struct io_conn *conn, char *buf)
{
	return io_read(conn, buf, 1, a_got_data, buf);
}

int main(void)
{
	int afd[2], bfd[2];
	char buf[16];
	void *ret;

	plan_tests(3);
	alarm(10);

	ok1(pipe(afd) == 0);
	ok1(pipe(bfd) == 0);

	io_poll_override(checking_poll);

	io_new_conn(NULL, afd[0], init_a, buf);
	io_new_conn(NULL, bfd[0], init_b, NULL);

	if (write(afd[1], "x", 1) != 1)
		exit(1);

	ret = io_loop(NULL, NULL);
	ok1(ret == &good);

	return exit_status();
}
