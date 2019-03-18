#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

#define PORT "65047"

struct data {
	struct io_listener *l;
	char *pattern;
	char buf[30];
	size_t buflen;
};

static struct io_plan *read_more(struct io_conn *conn, struct data *d);
static struct io_plan *write_more(struct io_conn *conn, struct data *d);

static struct io_plan *read_done(struct io_conn *conn, struct data *d)
{
	tal_resize(&d->pattern, tal_count(d->pattern) + 1 + strlen(d->buf));
	strcat(d->pattern, "<");
	strcat(d->pattern, d->buf);
	return read_more(conn, d);
}

static struct io_plan *read_more(struct io_conn *conn, struct data *d)
{
	memset(d->buf, 0, sizeof(d->buf));
	return io_read_partial(conn, d->buf, sizeof(d->buf), &d->buflen,
			       read_done, d);
}

static struct io_plan *write_done(struct io_conn *conn, struct data *d)
{
	tal_resize(&d->pattern, tal_count(d->pattern) + 1);
	strcat(d->pattern, ">");
	return write_more(conn, d);
}

static struct io_plan *write_more(struct io_conn *conn, struct data *d)
{
	return io_write_partial(conn, d->buf, 1, &d->buflen,
				write_done, d);
}

static struct io_plan *read_priority_init(struct io_conn *conn, struct data *d)
{
	/* This should suppress the write */
	ok1(io_conn_exclusive(conn, true));
	return read_more(conn, d);
}

static struct io_plan *init_conn(struct io_conn *conn, struct data *d)
{
	/* Free listener so when conns close we exit io_loop */
	io_close_listener(d->l);

	return io_duplex(conn, read_priority_init(conn, d), write_more(conn, d));
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
	struct addrinfo *addrinfo = NULL;
	int fd, status;
	struct data d;

	/* This is how many tests you plan to run */
	plan_tests(8);
	fd = make_listen_fd(PORT, &addrinfo);
	ok1(fd >= 0);
	d.l = io_new_listener(NULL, fd, init_conn, &d);
	ok1(d.l);
	fflush(stdout);

	if (!fork()) {
		io_close_listener(d.l);
		fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			    addrinfo->ai_protocol);
		if (fd < 0)
			exit(1);
		if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
			exit(2);
		signal(SIGPIPE, SIG_IGN);

		if (write(fd, "1hellothere", strlen("1hellothere")) != strlen("1hellothere"))
			exit(3);
		sleep(1);
		if (write(fd, "1helloagain", strlen("1helloagain")) != strlen("1helloagain"))
			exit(4);
		close(fd);
		freeaddrinfo(addrinfo);
		exit(0);
	}
	freeaddrinfo(addrinfo);

	d.pattern = tal_arrz(NULL, char, 1);
	ok1(io_loop(NULL, NULL) == NULL);
	/* No trace of writes */
	ok1(strcmp(d.pattern, "<1hellothere<1helloagain") == 0);
	tal_free(d.pattern);

	ok1(wait(&status));
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
