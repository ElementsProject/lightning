#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
/* Include the C files directly to make each readiness delivery observable. */
#include <ccan/io/poll.c>
#include <ccan/io/io.c>
#include <unistd.h>

static int replacement_fd;
static unsigned int poll_calls, actor_events, victim_events,
		    survivor_events, replacement_events;
static char completed;

static void check_ready_fds_cleaned(void)
{
	assert(ready_fds == NULL);
	assert(ready_fds_capacity == 0);
}

static int replacement_event(int fd, struct io_plan_arg *arg)
{
	replacement_events++;
	return 1;
}

static struct io_plan *replacement_ready(struct io_conn *conn, void *unused)
{
	io_break(&completed);
	return io_close(conn);
}

static struct io_plan *replacement_init(struct io_conn *conn, void *unused)
{
	io_plan_arg(conn, IO_IN);
	return io_set_plan(conn, IO_IN, replacement_event,
			   replacement_ready, NULL);
}

static int actor_event(int fd, struct io_plan_arg *arg)
{
	actor_events++;
	return 1;
}

static struct io_plan *actor_ready(struct io_conn *conn, void *unused)
{
	struct io_plan *closed = io_close(conn);

	/* Closing the current fd compacts the table.  Adding its replacement
	 * restores the old table length, but must not make it part of the poll
	 * result currently being dispatched. */
	if (!io_new_conn(NULL, replacement_fd, replacement_init, NULL))
		abort();
	return closed;
}

static struct io_plan *actor_init(struct io_conn *conn, void *unused)
{
	io_plan_arg(conn, IO_IN);
	return io_set_plan(conn, IO_IN, actor_event, actor_ready, NULL);
}

static int victim_event(int fd, struct io_plan_arg *arg)
{
	victim_events++;
	return 1;
}

static struct io_plan *victim_init(struct io_conn *conn, void *unused)
{
	io_plan_arg(conn, IO_IN);
	return io_set_plan(conn, IO_IN, victim_event, io_close_cb, NULL);
}

static int survivor_event(int fd, struct io_plan_arg *arg)
{
	survivor_events++;
	return 1;
}

static struct io_plan *survivor_init(struct io_conn *conn, void *unused)
{
	io_plan_arg(conn, IO_IN);
	return io_set_plan(conn, IO_IN, survivor_event, io_close_cb, NULL);
}

static int fake_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	poll_calls++;
	for (size_t i = 0; i < nfds; i++)
		fds[i].revents = 0;

	if (poll_calls == 1) {
		/* Fairness rotation handles slot 1 first.  That actor replaces
		 * itself while slots 0 and 2 still have readiness pending. */
		assert(nfds == 3);
		for (size_t i = 0; i < nfds; i++)
			fds[i].revents = POLLIN;
		return 3;
	}

	assert(poll_calls == 2);
	for (size_t i = 0; i < nfds; i++) {
		if (fds[i].fd != replacement_fd)
			continue;
		fds[i].revents = POLLIN;
		return 1;
	}
	abort();
}

int main(void)
{
	int actor_pipe[2], victim_pipe[2], survivor_pipe[2], replacement_pipe[2];

	assert(pipe(actor_pipe) == 0);
	assert(pipe(victim_pipe) == 0);
	assert(pipe(survivor_pipe) == 0);
	assert(pipe(replacement_pipe) == 0);
	replacement_fd = replacement_pipe[0];

	assert(io_poll_override(fake_poll) == poll);
	assert(io_new_conn(NULL, victim_pipe[0], victim_init, NULL));
	assert(io_new_conn(NULL, actor_pipe[0], actor_init, NULL));
	assert(io_new_conn(NULL, survivor_pipe[0], survivor_init, NULL));

	/* Registered first so this runs after the backend's LIFO cleanup. */
	assert(atexit(check_ready_fds_cleaned) == 0);
	io_poll_protect_stale_fds();
	assert(io_loop(NULL, NULL) == &completed);
	assert(poll_calls == 2);
	assert(actor_events == 1);
	assert(victim_events == 1);
	assert(survivor_events == 1);
	assert(replacement_events == 1);

	close(actor_pipe[1]);
	close(victim_pipe[1]);
	close(survivor_pipe[1]);
	close(replacement_pipe[1]);
	return 0;
}
