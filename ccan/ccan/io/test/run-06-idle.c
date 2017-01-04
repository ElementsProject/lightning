#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT "65006"

static struct io_conn *idler;

struct data {
	int state;
	char buf[4];
};

static struct io_plan *read_done(struct io_conn *conn, struct data *d)
{
	ok1(d->state == 2 || d->state == 3);
	d->state++;
	return io_close(conn);
}

static void finish_waker(struct io_conn *conn, struct data *d)
{
	io_wake(d);
	ok1(d->state == 1);
	d->state++;
}

static void finish_idle(struct io_conn *conn, struct data *d)
{
	ok1(d->state == 3);
	d->state++;
	io_break(d);
}

static struct io_plan *never(struct io_conn *conn, void *arg)
{
	abort();
}

static struct io_plan *read_buf(struct io_conn *conn, struct data *d)
{
	return io_read(conn, d->buf, sizeof(d->buf), read_done, d);
}

static struct io_plan *init_waker(struct io_conn *conn, void *unused)
{
	/* This is /dev/null, so will never succeed. */
	return io_read(conn, unused, 1, never, NULL);
}

static struct io_plan *init_idle(struct io_conn *conn, struct data *d)
{
	int fd2;

	ok1(d->state == 0);
	d->state++;
	idler = conn;
	io_set_finish(conn, finish_idle, d);

	/* This will wake us up, as read will fail. */
	fd2 = open("/dev/null", O_RDONLY);
	ok1(fd2 >= 0);
	io_set_finish(io_new_conn(NULL, fd2, init_waker, d), finish_waker, d);

	return io_wait(conn, d, read_buf, d);
}

static int make_listen_fd(const char *port, struct addrinfo **info)
{
	int fd, on = 1;
	struct addrinfo *addrinfo, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	if (getaddrinfo(NULL, port, &hints, &addrinfo) != 0)
		return -1;

	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
		    addrinfo->ai_protocol);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0) {
		close(fd);
		return -1;
	}
	if (listen(fd, 1) != 0) {
		close(fd);
		return -1;
	}
	*info = addrinfo;
	return fd;
}

int main(void)
{
	struct data *d = malloc(sizeof(*d));
	struct addrinfo *addrinfo;
	struct io_listener *l;
	int fd, status;

	/* This is how many tests you plan to run */
	plan_tests(13);
	d->state = 0;
	fd = make_listen_fd(PORT, &addrinfo);
	ok1(fd >= 0);
	l = io_new_listener(NULL, fd, init_idle, d);
	ok1(l);
	fflush(stdout);
	if (!fork()) {
		int i;

		io_close_listener(l);
		fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			    addrinfo->ai_protocol);
		if (fd < 0)
			exit(1);
		if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
			exit(2);
		signal(SIGPIPE, SIG_IGN);
		for (i = 0; i < strlen("hellothere"); i++) {
			if (write(fd, "hellothere" + i, 1) != 1)
				break;
		}
		close(fd);
		freeaddrinfo(addrinfo);
		free(d);
		exit(0);
	}
	freeaddrinfo(addrinfo);

	ok1(io_loop(NULL, NULL) == d);
	ok1(d->state == 4);
	ok1(memcmp(d->buf, "hellothere", sizeof(d->buf)) == 0);
	free(d);
	io_close_listener(l);

	ok1(wait(&status));
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
