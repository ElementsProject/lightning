#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

#define PORT "65018"

static void finish_100(struct io_conn *conn, int *state)
{
	ok1(errno == 100);
	ok1(*state == 1);
	(*state)++;
}

static void finish_EBADF(struct io_conn *conn, int *state)
{
	ok1(errno == EBADF);
	ok1(*state == 3);
	(*state)++;
	io_break(state + 1);
}

static struct io_plan *init_conn(struct io_conn *conn, int *state)
{
	if (*state == 0) {
		(*state)++;
		io_set_finish(conn, finish_100, state);
		errno = 100;
		return io_close(conn);
	} else {
		ok1(*state == 2);
		(*state)++;
		close(io_conn_fd(conn));
		errno = 0;
		io_set_finish(conn, finish_EBADF, state);

		return io_read(conn, state, 1, io_close_cb, NULL);
	}
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
	int state = 0;
	struct addrinfo *addrinfo;
	struct io_listener *l;
	int fd;

	/* This is how many tests you plan to run */
	plan_tests(12);
	fd = make_listen_fd(PORT, &addrinfo);
	ok1(fd >= 0);
	l = io_new_listener(NULL, fd, init_conn, &state);
	ok1(l);
	fflush(stdout);
	if (!fork()) {
		io_close_listener(l);
		fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			    addrinfo->ai_protocol);
		if (fd < 0)
			exit(1);
		if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
			exit(2);
		close(fd);
		fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			    addrinfo->ai_protocol);
		if (fd < 0)
			exit(3);
		if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
			exit(4);
		close(fd);
		freeaddrinfo(addrinfo);
		exit(0);
	}
	freeaddrinfo(addrinfo);
	ok1(io_loop(NULL, NULL) == &state + 1);
	ok1(state == 4);
	io_close_listener(l);
	ok1(wait(&state));
	ok1(WIFEXITED(state));
	ok1(WEXITSTATUS(state) == 0);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
