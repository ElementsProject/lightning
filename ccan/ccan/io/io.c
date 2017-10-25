/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#include "io.h"
#include "backend.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <ccan/container_of/container_of.h>

void *io_loop_return;

struct io_plan io_conn_freed;

struct io_listener *io_new_listener_(const tal_t *ctx, int fd,
				     struct io_plan *(*init)(struct io_conn *,
							     void *),
				     void *arg)
{
	struct io_listener *l = tal(ctx, struct io_listener);
	if (!l)
		return NULL;

	l->fd.listener = true;
	l->fd.fd = fd;
	l->init = init;
	l->arg = arg;
	l->ctx = ctx;
	if (!add_listener(l))
		return tal_free(l);
	return l;
}

void io_close_listener(struct io_listener *l)
{
	tal_free(l);
}

static struct io_plan *io_never_called(struct io_conn *conn, void *arg)
{
	abort();
}

/* Returns false if conn was freed. */
static bool next_plan(struct io_conn *conn, struct io_plan *plan)
{
	struct io_plan *(*next)(struct io_conn *, void *arg);

	next = plan->next;

	plan->status = IO_UNSET;
	plan->io = NULL;
	plan->next = io_never_called;

	plan = next(conn, plan->next_arg);

	if (plan == &io_conn_freed)
		return false;

	/* It should have set a plan inside this conn (or duplex) */
	assert(plan == &conn->plan[IO_IN]
	       || plan == &conn->plan[IO_OUT]
	       || plan == &conn->plan[2]);
	assert(conn->plan[IO_IN].status != IO_UNSET
	       || conn->plan[IO_OUT].status != IO_UNSET);

	backend_new_plan(conn);
	return true;
}

bool io_fd_block(int fd, bool block)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags == -1)
		return false;

	if (block)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;

	return fcntl(fd, F_SETFL, flags) != -1;
}

struct io_conn *io_new_conn_(const tal_t *ctx, int fd,
			     struct io_plan *(*init)(struct io_conn *, void *),
			     void *arg)
{
	struct io_conn *conn = tal(ctx, struct io_conn);

	if (!conn)
		return NULL;

	conn->fd.listener = false;
	conn->fd.fd = fd;
	conn->finish = NULL;
	conn->finish_arg = NULL;
	list_node_init(&conn->always);

	if (!add_conn(conn))
		return tal_free(conn);

	/* Keep our I/O async. */
	io_fd_block(fd, false);

	/* We start with out doing nothing, and in doing our init. */
	conn->plan[IO_OUT].status = IO_UNSET;

	conn->plan[IO_IN].next = init;
	conn->plan[IO_IN].next_arg = arg;
	if (!next_plan(conn, &conn->plan[IO_IN]))
		return NULL;

	return conn;
}

void io_set_finish_(struct io_conn *conn,
		    void (*finish)(struct io_conn *, void *),
		    void *arg)
{
	conn->finish = finish;
	conn->finish_arg = arg;
}

struct io_plan_arg *io_plan_arg(struct io_conn *conn, enum io_direction dir)
{
	assert(conn->plan[dir].status == IO_UNSET);

	conn->plan[dir].status = IO_POLLING_NOTSTARTED;
	return &conn->plan[dir].arg;
}

static struct io_plan *set_always(struct io_conn *conn,
				  enum io_direction dir,
				  struct io_plan *(*next)(struct io_conn *,
							  void *),
				  void *arg)
{
	struct io_plan *plan = &conn->plan[dir];

	plan->status = IO_ALWAYS;
	backend_new_always(conn);
	return io_set_plan(conn, dir, NULL, next, arg);
}

static struct io_plan *io_always_dir(struct io_conn *conn,
				     enum io_direction dir,
				     struct io_plan *(*next)(struct io_conn *,
							     void *),
				     void *arg)
{
	return set_always(conn, dir, next, arg);
}

struct io_plan *io_always_(struct io_conn *conn,
			   struct io_plan *(*next)(struct io_conn *, void *),
			   void *arg)
{
	return io_always_dir(conn, IO_IN, next, arg);
}

struct io_plan *io_out_always_(struct io_conn *conn,
			       struct io_plan *(*next)(struct io_conn *,
						       void *),
			       void *arg)
{
	return io_always_dir(conn, IO_OUT, next, arg);
}

static int do_write(int fd, struct io_plan_arg *arg)
{
	ssize_t ret = write(fd, arg->u1.cp, arg->u2.s);
	if (ret < 0)
		return -1;

	arg->u1.cp += ret;
	arg->u2.s -= ret;
	return arg->u2.s == 0;
}

/* Queue some data to be written. */
struct io_plan *io_write_(struct io_conn *conn, const void *data, size_t len,
			  struct io_plan *(*next)(struct io_conn *, void *),
			  void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_OUT);

	if (len == 0)
		return set_always(conn, IO_OUT, next, next_arg);

	arg->u1.const_vp = data;
	arg->u2.s = len;

	return io_set_plan(conn, IO_OUT, do_write, next, next_arg);
}

static int do_read(int fd, struct io_plan_arg *arg)
{
	ssize_t ret = read(fd, arg->u1.cp, arg->u2.s);
	if (ret <= 0)
		return -1;

	arg->u1.cp += ret;
	arg->u2.s -= ret;
	return arg->u2.s == 0;
}

/* Queue a request to read into a buffer. */
struct io_plan *io_read_(struct io_conn *conn,
			 void *data, size_t len,
			 struct io_plan *(*next)(struct io_conn *, void *),
			 void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	if (len == 0)
		return set_always(conn, IO_IN, next, next_arg);

	arg->u1.cp = data;
	arg->u2.s = len;

	return io_set_plan(conn, IO_IN, do_read, next, next_arg);
}

static int do_read_partial(int fd, struct io_plan_arg *arg)
{
	ssize_t ret = read(fd, arg->u1.cp, *(size_t *)arg->u2.vp);
	if (ret <= 0)
		return -1;

	*(size_t *)arg->u2.vp = ret;
	return 1;
}

/* Queue a partial request to read into a buffer. */
struct io_plan *io_read_partial_(struct io_conn *conn,
				 void *data, size_t maxlen, size_t *len,
				 struct io_plan *(*next)(struct io_conn *,
							 void *),
				 void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	if (maxlen == 0)
		return set_always(conn, IO_IN, next, next_arg);

	arg->u1.cp = data;
	/* We store the max len in here temporarily. */
	*len = maxlen;
	arg->u2.vp = len;

	return io_set_plan(conn, IO_IN, do_read_partial, next, next_arg);
}

static int do_write_partial(int fd, struct io_plan_arg *arg)
{
	ssize_t ret = write(fd, arg->u1.cp, *(size_t *)arg->u2.vp);
	if (ret < 0)
		return -1;

	*(size_t *)arg->u2.vp = ret;
	return 1;
}

/* Queue a partial write request. */
struct io_plan *io_write_partial_(struct io_conn *conn,
				  const void *data, size_t maxlen, size_t *len,
				  struct io_plan *(*next)(struct io_conn *,
							  void*),
				  void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_OUT);

	if (maxlen == 0)
		return set_always(conn, IO_OUT, next, next_arg);

	arg->u1.const_vp = data;
	/* We store the max len in here temporarily. */
	*len = maxlen;
	arg->u2.vp = len;

	return io_set_plan(conn, IO_OUT, do_write_partial, next, next_arg);
}

static int do_connect(int fd, struct io_plan_arg *arg)
{
	int err, ret;
	socklen_t len = sizeof(err);

	/* Has async connect finished? */
	ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret < 0)
		return -1;

	if (err == 0) {
		return 1;
	} else if (err == EINPROGRESS)
		return 0;

	errno = err;
	return -1;
}

struct io_plan *io_connect_(struct io_conn *conn, const struct addrinfo *addr,
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *next_arg)
{
	int fd = io_conn_fd(conn);

	/* We don't actually need the arg, but we need it polling. */
	io_plan_arg(conn, IO_OUT);

	/* Note that io_new_conn() will make fd O_NONBLOCK */

	/* Immediate connect can happen. */
	if (connect(fd, addr->ai_addr, addr->ai_addrlen) == 0)
		return set_always(conn, IO_OUT, next, next_arg);

	if (errno != EINPROGRESS)
		return io_close(conn);

	return io_set_plan(conn, IO_OUT, do_connect, next, next_arg);
}

static struct io_plan *io_wait_dir(struct io_conn *conn,
				   const void *wait,
				   enum io_direction dir,
				   struct io_plan *(*next)(struct io_conn *,
							   void *),
				   void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, dir);
	arg->u1.const_vp = wait;

	conn->plan[dir].status = IO_WAITING;

	return io_set_plan(conn, dir, NULL, next, next_arg);
}

struct io_plan *io_wait_(struct io_conn *conn,
			 const void *wait,
			 struct io_plan *(*next)(struct io_conn *, void *),
			 void *next_arg)
{
	return io_wait_dir(conn, wait, IO_IN, next, next_arg);
}

struct io_plan *io_out_wait_(struct io_conn *conn,
			     const void *wait,
			     struct io_plan *(*next)(struct io_conn *, void *),
			     void *next_arg)
{
	return io_wait_dir(conn, wait, IO_OUT, next, next_arg);
}

void io_wake(const void *wait)
{
	backend_wake(wait);
}

/* Returns false if this should not be touched (eg. freed). */
static bool do_plan(struct io_conn *conn, struct io_plan *plan,
		    bool idle_on_epipe)
{
	/* We shouldn't have polled for this event if this wasn't true! */
	assert(plan->status == IO_POLLING_NOTSTARTED
	       || plan->status == IO_POLLING_STARTED);

	switch (plan->io(conn->fd.fd, &plan->arg)) {
	case -1:
		if (errno == EPIPE && idle_on_epipe) {
			plan->status = IO_UNSET;
			backend_new_plan(conn);
			return false;
		}
		io_close(conn);
		return false;
	case 0:
		plan->status = IO_POLLING_STARTED;
		return true;
	case 1:
		return next_plan(conn, plan);
	default:
		/* IO should only return -1, 0 or 1 */
		abort();
	}
}

void io_ready(struct io_conn *conn, int pollflags)
{
	if (pollflags & POLLIN)
		if (!do_plan(conn, &conn->plan[IO_IN], false))
			return;

	if (pollflags & POLLOUT)
		/* If we're writing to a closed pipe, we need to wait for
		 * read to fail if we're duplex: we want to drain it! */
		do_plan(conn, &conn->plan[IO_OUT],
			conn->plan[IO_IN].status == IO_POLLING_NOTSTARTED
			|| conn->plan[IO_IN].status == IO_POLLING_STARTED);
}

void io_do_always(struct io_conn *conn)
{
	/* There's a corner case where the in next_plan wakes up the
	 * out, placing it in IO_ALWAYS and we end up processing it immediately,
	 * only to leave it in the always list.
	 *
	 * Yet we can't just process one, in case they are both supposed
	 * to be done, so grab state beforehand.
	 */
	bool always_out = (conn->plan[IO_OUT].status == IO_ALWAYS);

	if (conn->plan[IO_IN].status == IO_ALWAYS)
		if (!next_plan(conn, &conn->plan[IO_IN]))
			return;

	if (always_out) {
		/* You can't *unalways* a conn (except by freeing, in which
		 * case next_plan() returned false */
		assert(conn->plan[IO_OUT].status == IO_ALWAYS);
		next_plan(conn, &conn->plan[IO_OUT]);
	}
}

void io_do_wakeup(struct io_conn *conn, enum io_direction dir)
{
	struct io_plan *plan = &conn->plan[dir];

	assert(plan->status == IO_WAITING);

	set_always(conn, dir, plan->next, plan->next_arg);
}

/* Close the connection, we're done. */
struct io_plan *io_close(struct io_conn *conn)
{
	tal_free(conn);
	return &io_conn_freed;
}

struct io_plan *io_close_cb(struct io_conn *conn, void *next_arg)
{
	return io_close(conn);
}

struct io_plan *io_close_taken_fd(struct io_conn *conn)
{
	io_fd_block(conn->fd.fd, true);

	cleanup_conn_without_close(conn);
	return io_close(conn);
}

/* Exit the loop, returning this (non-NULL) arg. */
void io_break(const void *ret)
{
	assert(ret);
	io_loop_return = (void *)ret;
}

struct io_plan *io_never(struct io_conn *conn, void *unused)
{
	return io_always(conn, io_never_called, NULL);
}

int io_conn_fd(const struct io_conn *conn)
{
	return conn->fd.fd;
}

struct io_plan *io_duplex(struct io_conn *conn,
			  struct io_plan *in_plan, struct io_plan *out_plan)
{
	assert(conn == container_of(in_plan, struct io_conn, plan[IO_IN]));
	/* in_plan must be conn->plan[IO_IN], out_plan must be [IO_OUT] */
	assert(out_plan == in_plan + 1);
	return out_plan + 1;
}

struct io_plan *io_halfclose(struct io_conn *conn)
{
	/* Both unset?  OK. */
	if (conn->plan[IO_IN].status == IO_UNSET
	    && conn->plan[IO_OUT].status == IO_UNSET)
		return io_close(conn);

	/* We leave this unset then. */
	if (conn->plan[IO_IN].status == IO_UNSET)
		return &conn->plan[IO_IN];
	else
		return &conn->plan[IO_OUT];
}

struct io_plan *io_set_plan(struct io_conn *conn, enum io_direction dir,
			    int (*io)(int fd, struct io_plan_arg *arg),
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *next_arg)
{
	struct io_plan *plan = &conn->plan[dir];

	plan->io = io;
	plan->next = next;
	plan->next_arg = next_arg;
	assert(next != NULL);

	return plan;
}

bool io_plan_in_started(const struct io_conn *conn)
{
	return conn->plan[IO_IN].status == IO_POLLING_STARTED;
}

bool io_plan_out_started(const struct io_conn *conn)
{
	return conn->plan[IO_OUT].status == IO_POLLING_STARTED;
}

bool io_flush_sync(struct io_conn *conn)
{
	struct io_plan *plan = &conn->plan[IO_OUT];
	bool ok;

	/* Not writing?  Nothing to do. */
	if (plan->status != IO_POLLING_STARTED
	    && plan->status != IO_POLLING_NOTSTARTED)
		return true;

	/* Synchronous please. */
	io_fd_block(io_conn_fd(conn), true);

again:
	switch (plan->io(conn->fd.fd, &plan->arg)) {
	case -1:
		ok = false;
		break;
	/* Incomplete, try again. */
	case 0:
		plan->status = IO_POLLING_STARTED;
		goto again;
	case 1:
		ok = true;
		/* In case they come back. */
		set_always(conn, IO_OUT, plan->next, plan->next_arg);
		break;
	default:
		/* IO should only return -1, 0 or 1 */
		abort();
	}

	io_fd_block(io_conn_fd(conn), false);
	return ok;
}
