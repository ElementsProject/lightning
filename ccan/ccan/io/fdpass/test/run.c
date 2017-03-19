#include <ccan/io/fdpass/fdpass.h>
/* Include the C files directly. */
#include <ccan/io/fdpass/fdpass.c>
#include <ccan/tap/tap.h>
#include <sys/types.h>
#include <sys/socket.h>

static struct io_plan *try_reading(struct io_conn *conn, int *fd)
{
	char buf[6];
	ok1(read(*fd, buf, sizeof(buf)) == sizeof(buf));
	ok1(memcmp(buf, "hello!", sizeof(buf)) == 0);
	return io_close(conn);
}

static struct io_plan *get_fd(struct io_conn *conn, void *unused)
{
	int *fd = tal(conn, int);
	return io_recv_fd(conn, fd, try_reading, fd);
}

static struct io_plan *try_writing(struct io_conn *conn, int *pfd)
{
	close(pfd[0]);
	ok1(write(pfd[1], "hello!", 6) == 6);
	return io_close(conn);
}

static struct io_plan *send_fd(struct io_conn *conn, int *pfd)
{
	return io_send_fd(conn, pfd[0], true, try_writing, pfd);
}

int main(void)
{
	int sv[2];
	int pfd[2];

	plan_tests(5);
	ok1(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ok1(pipe(pfd) == 0);

	/* Pass read end of pipe to ourselves, test. */
	io_new_conn(NULL, sv[0], get_fd, NULL);
	io_new_conn(NULL, sv[1], send_fd, pfd);

	io_loop(NULL, NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
