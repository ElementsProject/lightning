/* Test previous issue: in duplex case, we wake reader reader wakes writer. */
#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

static struct io_plan *block_reading(struct io_conn *conn, void *unused)
{
	static char buf[1];
	return io_read(conn, buf, sizeof(buf), io_never, NULL);
}

static struct io_plan *writer_woken(struct io_conn *conn, void *unused)
{
	pass("Writer woken up");
	return io_write(conn, "1", 1, io_close_cb, NULL);
}

static struct io_plan *reader_woken(struct io_conn *conn, void *unused)
{
	pass("Reader woken up");
	/* Wake writer */
	io_wake(conn);
	return block_reading(conn, unused);
}

static struct io_plan *setup_conn(struct io_conn *conn, void *trigger)
{
	return io_duplex(conn,
			 io_wait(conn, trigger, reader_woken, NULL),
			 io_out_wait(conn, conn, writer_woken, NULL));
}

int main(void)
{
	int fds[2];
	
	plan_tests(3);
	ok1(socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) == 0);

	/* We use 'fds' as pointer to wake writer. */
	io_new_conn(NULL, fds[0], setup_conn, fds);

	io_wake(fds);
	io_loop(NULL, NULL);

	close(fds[1]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
