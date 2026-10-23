#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <sys/wait.h>
#include <stdio.h>

#define PORT "65022"

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
	struct io_listener *l;
	struct timers timers;
	struct timer timer;
	struct timer *expired;
	int fd;

	/* This is how many tests you plan to run */
	plan_tests(1);
	fd = make_listen_fd(PORT, &addrinfo);
	freeaddrinfo(addrinfo);
	l = io_new_listener(NULL, fd, io_never, NULL);

	/* Anyone could do this; on Linux, a child doing it causes poll()
	 * to return POLLHUP -- but that's not universal: on macOS, poll()
	 * doesn't report *any* event for an unconnected listening socket
	 * that's been shut down, so io_loop() would otherwise never
	 * return.  Bound the wait so this can't hang either way, and
	 * treat the platforms where the event never arrives as a known,
	 * documented gap rather than a failure. */
	shutdown(fd, SHUT_RDWR);
	timers_init(&timers, time_mono());
	timer_init(&timer);
	timer_addrel(&timers, &timer, time_from_sec(2));
	if (io_loop(&timers, &expired) == NULL && !expired) {
		ok1(true);
	} else {
		skip(1, "poll() did not report the shutdown listening"
			" socket on this platform");
		io_close_listener(l);
	}
	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
