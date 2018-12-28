#include <ccan/io/io.h>
/* Include the C files directly. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <ccan/tap/tap.h>
#include <sys/wait.h>
#include <stdio.h>

#define PORT "65020"

static struct io_plan *init_conn(struct io_conn *conn, void *unused)
{
	return io_close(conn);
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

static struct timemono fake_time;

static struct timemono get_fake_time(void)
{
	return fake_time;
}

int main(void)
{
	struct io_listener *l;
	int fd;
	struct timers timers;
	struct timer timer, *expired;
	struct addrinfo *addrinfo;

	/* This is how many tests you plan to run */
	plan_tests(7);

	fake_time = time_mono();

	timers_init(&timers, fake_time);
	timer_init(&timer);
	timer_addmono(&timers, &timer,
		      timemono_add(fake_time, time_from_sec(1000)));

	fd = make_listen_fd(PORT, &addrinfo);
	freeaddrinfo(addrinfo);
	ok1(fd >= 0);
	l = io_new_listener(NULL, fd, init_conn, NULL);
	ok1(l);

	fake_time.ts.tv_sec += 1000;
	ok1(io_time_override(get_fake_time) == time_mono);
	ok1(io_loop(&timers, &expired) == NULL);

	ok1(expired == &timer);
	ok1(!timers_expire(&timers, fake_time));
	ok1(io_time_override(time_mono) == get_fake_time);
	io_close_listener(l);

	timers_cleanup(&timers);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
