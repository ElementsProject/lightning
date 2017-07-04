#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

#define PORT "65020"

/* Should be looking to read from one fd. */
static int mypoll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	ok1(nfds == 1);
	ok1(fds[0].fd >= 0);
	ok1(fds[0].events & POLLIN);
	ok1(!(fds[0].events & POLLOUT));

	/* Pretend it's readable. */
	fds[0].revents = POLLIN;
	return 1;
}

static int check_cant_read(int fd, struct io_plan_arg *arg)
{
	char c;
	ssize_t ret = read(fd, &c, 1);

	ok1(errno == EAGAIN || errno == EWOULDBLOCK);
	ok1(ret == -1);

	return 1;
}

static struct io_plan *setup_conn(struct io_conn *conn, void *unused)
{
	/* Need to get this to mark it IO_POLLING */
	io_plan_arg(conn, IO_IN);
	return io_set_plan(conn, IO_IN, check_cant_read, io_close_cb, NULL);
}

int main(void)
{
	int fds[2];

	plan_tests(8);

	pipe(fds);
	ok1(io_poll_override(mypoll) == poll);

	io_new_conn(NULL, fds[0], setup_conn, NULL);
	ok1(io_loop(NULL, NULL) == NULL);
	close(fds[1]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
