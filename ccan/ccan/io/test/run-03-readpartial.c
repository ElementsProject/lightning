#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

#define PORT "65003"

struct data {
	int state;
	size_t bytes;
	char buf[4];
};

static void finish_ok(struct io_conn *conn, struct data *d)
{
	ok1(d->state == 1);
	d->state++;
	io_break(d);
}

static struct io_plan *init_conn(struct io_conn *conn, struct data *d)
{
	ok1(d->state == 0);
	d->state++;

	io_set_finish(conn, finish_ok, d);

	return io_read_partial(conn, d->buf, sizeof(d->buf), &d->bytes,
			       io_close_cb, d);
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

static void write_to_socket(const char *str, const struct addrinfo *addrinfo)
{
	int fd, i;

	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
		    addrinfo->ai_protocol);
	if (fd < 0)
		exit(1);
	if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
		exit(2);
	signal(SIGPIPE, SIG_IGN);
	for (i = 0; i < strlen(str); i++) {
		if (write(fd, str + i, 1) != 1)
			break;
	}
	close(fd);
}

int main(void)
{
	struct data *d = malloc(sizeof(*d));
	struct addrinfo *addrinfo;
	struct io_listener *l;
	int fd, status;

	/* This is how many tests you plan to run */
	plan_tests(22);
	d->state = 0;
	fd = make_listen_fd(PORT, &addrinfo);
	ok1(fd >= 0);
	l = io_new_listener(NULL, fd, init_conn, d);
	ok1(l);
	fflush(stdout);
	if (!fork()) {
		io_close_listener(l);
		write_to_socket("hellothere", addrinfo);
		freeaddrinfo(addrinfo);
		free(d);
		exit(0);
	}
	ok1(io_loop(NULL, NULL) == d);
	ok1(d->state == 2);
	ok1(d->bytes > 0);
	ok1(d->bytes <= sizeof(d->buf));
	ok1(memcmp(d->buf, "hellothere", d->bytes) == 0);

	ok1(wait(&status));
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	fflush(stdout);
	if (!fork()) {
		io_close_listener(l);
		write_to_socket("hi", addrinfo);
		freeaddrinfo(addrinfo);
		free(d);
		exit(0);
	}
	d->state = 0;
	ok1(io_loop(NULL, NULL) == d);
	ok1(d->state == 2);
	ok1(d->bytes > 0);
	ok1(d->bytes <= strlen("hi"));
	ok1(memcmp(d->buf, "hi", d->bytes) == 0);

	freeaddrinfo(addrinfo);
	free(d);
	io_close_listener(l);

	ok1(wait(&status));
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
