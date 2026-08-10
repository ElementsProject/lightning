#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>

/* Regression test: io_new_listener() must set the listen fd O_NONBLOCK
 * (like io_new_conn() does for connections).  Otherwise, if the pending
 * connection vanishes between poll() and accept() (peer RSTs after the
 * handshake, or a competing acceptor steals it), accept() blocks and
 * hangs the entire io_loop. */

#define PORT "65150"

static int listen_fd, client_fd;
static int rst_sent, done;

static int rst_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int r;
	nfds_t i;

	if (rst_sent) {
		/* accept() has had its chance; stop here.  Checked before
		 * poll(): nothing more will arrive on the fds, so polling
		 * first would block forever. */
		io_break(&done);
		return 0;
	}
	r = poll(fds, nfds, timeout);
	if (r > 0) {
		for (i = 0; i < nfds; i++) {
			if (fds[i].fd == listen_fd && (fds[i].revents & POLLIN)) {
				/* Peer aborts the pending connection after
				 * poll() reported it, before accept(). */
				struct linger ling = { 1, 0 };
				setsockopt(client_fd, SOL_SOCKET, SO_LINGER,
					   &ling, sizeof(ling));
				close(client_fd);
				rst_sent = 1;
			}
		}
	}
	return r;
}

static struct io_plan *init_conn(struct io_conn *conn, void *unused)
{
	return io_close(conn);
}

static int make_listen_fd(const char *port)
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
	freeaddrinfo(addrinfo);
	return fd;
}

int main(void)
{
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);
	int flags, status;

	plan_tests(4);
	alarm(15);

	listen_fd = make_listen_fd(PORT);
	ok1(listen_fd >= 0);
	io_new_listener(NULL, listen_fd, init_conn, NULL);

	/* The fix: listener must be nonblocking. */
	flags = fcntl(listen_fd, F_GETFL);
	ok1(flags != -1 && (flags & O_NONBLOCK));

	/* Behavioral check in a child: RST the pending connection between
	 * poll() and accept(); a blocking accept() hangs (SIGALRM). */
	fflush(stdout);
	if (fork() == 0) {
		alarm(5);
		client_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (getsockname(listen_fd, (struct sockaddr *)&sa, &salen) != 0)
			exit(1);
		if (connect(client_fd, (struct sockaddr *)&sa, salen) != 0)
			exit(1);
		io_poll_override(rst_poll);
		io_loop(NULL, NULL);
		exit(0);
	}

	ok1(wait(&status) != -1);
	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	return exit_status();
}
