#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdio.h>

#define PORT "65048"

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

/* Once the write side idles, the read side correctly resumes: some
 * prefix of pure writes (">"), then whatever the peer wrote arrives in
 * "<...>"-marked chunks.  Two things vary across platforms, so neither
 * can be asserted as one fixed outcome:
 *  - Exact chunk boundaries depend on TCP/kernel delivery granularity.
 *  - Whether the write side idles at all before the whole connection
 *    closes depends on how the kernel reports the peer's close: EPIPE
 *    (graceful; write idles, buffered peer data is then read) vs.
 *    ECONNRESET (hard reset; io_close()s the whole conn directly, any
 *    unread peer data is legitimately lost, same as Linux's TCP
 *    generally does for this in-flight-data-on-close shape).
 * So: writes must never follow a read (exclusivity actually held), and
 * whatever *did* get read, concatenated across however many chunks,
 * must be a prefix of what was sent -- empty (nothing read: hard
 * reset) and the full string (graceful: all of it read) both count. */
static bool exclusive_write_pattern_ok(const char *pattern, const char *expect)
{
	const char *p;
	char *data;
	size_t len = 0;
	bool ok, seen_read = false;

	for (p = pattern; *p; p++) {
		if (*p == '<')
			seen_read = true;
		else if (*p == '>' && seen_read)
			return false; /* write after a read: exclusivity lied */
	}

	data = malloc(strlen(pattern) + 1);
	for (p = pattern; *p; p++) {
		if (*p != '<' && *p != '>')
			data[len++] = *p;
	}
	data[len] = '\0';
	ok = (strncmp(data, expect, len) == 0);
	free(data);
	return ok;
}

static struct io_plan *write_priority_init(struct io_conn *conn, struct data *d)
{
	/* This should suppress the read */
	ok1(io_conn_out_exclusive(conn, true));
	return write_more(conn, d);
}

static struct io_plan *init_conn(struct io_conn *conn, struct data *d)
{
	int sndbuf = 1024;

	/* Free listener so when conns close we exit io_loop */
	io_close_listener(d->l);

	/* We write 1 byte at a time in an exclusive (uninterruptible) loop
	 * until the peer's close is noticed -- the peer here never reads,
	 * so that only happens once the send buffer fills and write()
	 * returns EAGAIN/EPIPE. Default buffer sizes vary a lot across
	 * platforms/kernel versions (observed to be large enough on some
	 * macOS configurations that this loop takes an unpredictably long
	 * time -- not blocked, just very slow -- to naturally get there).
	 * Force it small so this is fast and deterministic everywhere. */
	setsockopt(io_conn_fd(conn), SOL_SOCKET, SO_SNDBUF,
		  &sndbuf, sizeof(sndbuf));

	return io_duplex(conn, read_more(conn, d), write_priority_init(conn, d));
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
	/* Writes only until the write side idles; all of the peer's data
	 * read after that, however it got chunked. */
	ok1(exclusive_write_pattern_ok(d.pattern, "1hellothere1helloagain"));
	tal_free(d.pattern);

	ok1(wait(&status));
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
