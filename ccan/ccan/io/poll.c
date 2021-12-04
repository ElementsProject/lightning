/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#include "io.h"
#include "backend.h"
#include <assert.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>

static size_t num_fds = 0, max_fds = 0, num_waiting = 0, num_always = 0, max_always = 0, num_exclusive = 0;
static struct pollfd *pollfds = NULL;
static struct fd **fds = NULL;
static struct io_plan **always = NULL;
static struct timemono (*nowfn)(void) = time_mono;
static int (*pollfn)(struct pollfd *fds, nfds_t nfds, int timeout) = poll;

struct timemono (*io_time_override(struct timemono (*now)(void)))(void)
{
	struct timemono (*old)(void) = nowfn;
	nowfn = now;
	return old;
}

int (*io_poll_override(int (*poll)(struct pollfd *fds, nfds_t nfds, int timeout)))(struct pollfd *, nfds_t, int)
{
	int (*old)(struct pollfd *fds, nfds_t nfds, int timeout) = pollfn;
	pollfn = poll;
	return old;
}

static bool add_fd(struct fd *fd, short events)
{
	if (!max_fds) {
		assert(num_fds == 0);
		pollfds = tal_arr(NULL, struct pollfd, 8);
		if (!pollfds)
			return false;
		fds = tal_arr(pollfds, struct fd *, 8);
		if (!fds)
			return false;
		max_fds = 8;
	}

	if (num_fds + 1 > max_fds) {
		size_t num = max_fds * 2;

		if (!tal_resize(&pollfds, num))
			return false;
		if (!tal_resize(&fds, num))
			return false;
		max_fds = num;
	}

	pollfds[num_fds].events = events;
	/* In case it's idle. */
	if (!events)
		pollfds[num_fds].fd = -fd->fd - 1;
	else
		pollfds[num_fds].fd = fd->fd;
	pollfds[num_fds].revents = 0; /* In case we're iterating now */
	fds[num_fds] = fd;
	fd->backend_info = num_fds;
	fd->exclusive[0] = fd->exclusive[1] = false;
	num_fds++;
	if (events)
		num_waiting++;

	return true;
}

static void del_fd(struct fd *fd)
{
	size_t n = fd->backend_info;

	assert(n != -1);
	assert(n < num_fds);
	if (pollfds[n].events)
		num_waiting--;
	if (n != num_fds - 1) {
		/* Move last one over us. */
		pollfds[n] = pollfds[num_fds-1];
		fds[n] = fds[num_fds-1];
		assert(fds[n]->backend_info == num_fds-1);
		fds[n]->backend_info = n;
	} else if (num_fds == 1) {
		/* Free everything when no more fds. */
		pollfds = tal_free(pollfds);
		fds = NULL;
		max_fds = 0;
		if (num_always == 0) {
			always = tal_free(always);
			max_always = 0;
		}
	}
	num_fds--;
	fd->backend_info = -1;

	if (fd->exclusive[IO_IN])
		num_exclusive--;
	if (fd->exclusive[IO_OUT])
		num_exclusive--;
}

static void destroy_listener(struct io_listener *l)
{
	close(l->fd.fd);
	del_fd(&l->fd);
}

bool add_listener(struct io_listener *l)
{
	if (!add_fd(&l->fd, POLLIN))
		return false;
	tal_add_destructor(l, destroy_listener);
	return true;
}

static int find_always(const struct io_plan *plan)
{
	size_t i = 0;

	for (i = 0; i < num_always; i++)
		if (always[i] == plan)
			return i;
	return -1;
}

static void remove_from_always(const struct io_plan *plan)
{
	int pos;

	if (plan->status != IO_ALWAYS)
		return;

	pos = find_always(plan);
	assert(pos >= 0);

	/* Move last one down if we made a hole */
	if (pos != num_always-1)
		always[pos] = always[num_always-1];
	num_always--;

	/* Only free if no fds left either. */
	if (num_always == 0 && max_fds == 0) {
		always = tal_free(always);
		max_always = 0;
	}
}

bool backend_new_always(struct io_plan *plan)
{
	assert(find_always(plan) == -1);

	if (!max_always) {
		assert(num_always == 0);
		always = tal_arr(NULL, struct io_plan *, 8);
		if (!always)
			return false;
		max_always = 8;
	}

	if (num_always + 1 > max_always) {
		size_t num = max_always * 2;

		if (!tal_resize(&always, num))
			return false;
		max_always = num;
	}

	always[num_always++] = plan;
	return true;
}

static void setup_pfd(struct io_conn *conn, struct pollfd *pfd)
{
	assert(pfd == &pollfds[conn->fd.backend_info]);

	pfd->events = 0;
	if (conn->plan[IO_IN].status == IO_POLLING_NOTSTARTED
	    || conn->plan[IO_IN].status == IO_POLLING_STARTED)
		pfd->events |= POLLIN;
	if (conn->plan[IO_OUT].status == IO_POLLING_NOTSTARTED
	    || conn->plan[IO_OUT].status == IO_POLLING_STARTED)
		pfd->events |= POLLOUT;

	if (pfd->events) {
		pfd->fd = conn->fd.fd;
	} else {
		pfd->fd = -conn->fd.fd - 1;
	}
}

void backend_new_plan(struct io_conn *conn)
{
	struct pollfd *pfd = &pollfds[conn->fd.backend_info];

	if (pfd->events)
		num_waiting--;

	setup_pfd(conn, pfd);

	if (pfd->events)
		num_waiting++;
}

void backend_wake(const void *wait)
{
	unsigned int i;

	for (i = 0; i < num_fds; i++) {
		struct io_conn *c;

		/* Ignore listeners */
		if (fds[i]->listener)
			continue;

		c = (void *)fds[i];
		if (c->plan[IO_IN].status == IO_WAITING
		    && c->plan[IO_IN].arg.u1.const_vp == wait)
			io_do_wakeup(c, IO_IN);

		if (c->plan[IO_OUT].status == IO_WAITING
		    && c->plan[IO_OUT].arg.u1.const_vp == wait)
			io_do_wakeup(c, IO_OUT);
	}
}

static void destroy_conn(struct io_conn *conn, bool close_fd)
{
	int saved_errno = errno;

	if (close_fd)
		close(conn->fd.fd);
	del_fd(&conn->fd);

	remove_from_always(&conn->plan[IO_IN]);
	remove_from_always(&conn->plan[IO_OUT]);

	/* errno saved/restored by tal_free itself. */
	if (conn->finish) {
		errno = saved_errno;
		conn->finish(conn, conn->finish_arg);
	}
}

static void destroy_conn_close_fd(struct io_conn *conn)
{
	destroy_conn(conn, true);
}

bool add_conn(struct io_conn *c)
{
	if (!add_fd(&c->fd, 0))
		return false;
	tal_add_destructor(c, destroy_conn_close_fd);
	return true;
}

void cleanup_conn_without_close(struct io_conn *conn)
{
	tal_del_destructor(conn, destroy_conn_close_fd);
	destroy_conn(conn, false);
}

static void accept_conn(struct io_listener *l)
{
	int fd = accept(l->fd.fd, NULL, NULL);

	/* FIXME: What to do here? */
	if (fd < 0)
		return;

	io_new_conn(l->ctx, fd, l->init, l->arg);
}

/* Return pointer to exclusive flag for this plan. */
static bool *exclusive(struct io_plan *plan)
{
	struct io_conn *conn;

	conn = container_of(plan, struct io_conn, plan[plan->dir]);
	return &conn->fd.exclusive[plan->dir];
}

/* For simplicity, we do one always at a time */
static bool handle_always(void)
{
	int i;

	/* Backwards is simple easier to remove entries */
	for (i = num_always - 1; i >= 0; i--) {
		struct io_plan *plan = always[i];

		if (num_exclusive && !*exclusive(plan))
			continue;
		/* Remove first: it might re-add */
		if (i != num_always-1)
			always[i] = always[num_always-1];
		num_always--;
		io_do_always(plan);
		return true;
	}

	return false;
}

bool backend_set_exclusive(struct io_plan *plan, bool excl)
{
	bool *excl_ptr = exclusive(plan);

	if (excl != *excl_ptr) {
		*excl_ptr = excl;
		if (!excl)
			num_exclusive--;
		else
			num_exclusive++;
	}

	return num_exclusive != 0;
}

/* FIXME: We could do this once at set_exclusive time, and catch everywhere
 * else that we manipulate events. */
static void exclude_pollfds(void)
{
	size_t i;

	if (num_exclusive == 0)
		return;

	for (i = 0; i < num_fds; i++) {
		struct pollfd *pfd = &pollfds[fds[i]->backend_info];

		if (!fds[i]->exclusive[IO_IN])
			pfd->events &= ~POLLIN;
		if (!fds[i]->exclusive[IO_OUT])
			pfd->events &= ~POLLOUT;

		/* If we're not listening, we don't want error events
		 * either. */
		if (!pfd->events)
			pfd->fd = -fds[i]->fd - 1;
	}
}

static void restore_pollfds(void)
{
	size_t i;

	if (num_exclusive == 0)
		return;

	for (i = 0; i < num_fds; i++) {
		struct pollfd *pfd = &pollfds[fds[i]->backend_info];

		if (fds[i]->listener) {
			pfd->events = POLLIN;
			pfd->fd = fds[i]->fd;
		} else {
			struct io_conn *conn = (void *)fds[i];
			setup_pfd(conn, pfd);
		}
	}
}

/* This is the main loop. */
void *io_loop(struct timers *timers, struct timer **expired)
{
	void *ret;

	/* if timers is NULL, expired must be.  If not, not. */
	assert(!timers == !expired);

	/* Make sure this is NULL if we exit for some other reason. */
	if (expired)
		*expired = NULL;

	while (!io_loop_return) {
		int i, r, ms_timeout = -1;

		if (handle_always()) {
			/* Could have started/finished more. */
			continue;
		}

		/* Everything closed? */
		if (num_fds == 0)
			break;

		/* You can't tell them all to go to sleep! */
		assert(num_waiting);

		if (timers) {
			struct timemono now, first;

			now = nowfn();

			/* Call functions for expired timers. */
			*expired = timers_expire(timers, now);
			if (*expired)
				break;

			/* Now figure out how long to wait for the next one. */
			if (timer_earliest(timers, &first)) {
				uint64_t next;
				next = time_to_msec(timemono_between(first, now));
				if (next < INT_MAX)
					ms_timeout = next;
				else
					ms_timeout = INT_MAX;
			}
		}

		/* We do this temporarily, assuming exclusive is unusual */
		exclude_pollfds();
		r = pollfn(pollfds, num_fds, ms_timeout);
		restore_pollfds();

		if (r < 0) {
			/* Signals shouldn't break us, unless they set
			 * io_loop_return. */
			if (errno == EINTR)
				continue;
			break;
		}

		for (i = 0; i < num_fds && !io_loop_return; i++) {
			struct io_conn *c = (void *)fds[i];
			int events = pollfds[i].revents;

			/* Clear so we don't get confused if exclusive next time */
			pollfds[i].revents = 0;

			if (r == 0)
				break;

			if (fds[i]->listener) {
				struct io_listener *l = (void *)fds[i];
				if (events & POLLIN) {
					accept_conn(l);
					r--;
				} else if (events & (POLLHUP|POLLNVAL|POLLERR)) {
					r--;
					errno = EBADF;
					io_close_listener(l);
				}
			} else if (events & (POLLIN|POLLOUT)) {
				r--;
				io_ready(c, events);
			} else if (events & (POLLHUP|POLLNVAL|POLLERR)) {
				r--;
				errno = EBADF;
				io_close(c);
			}
		}
	}

	ret = io_loop_return;
	io_loop_return = NULL;

	return ret;
}
