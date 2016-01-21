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
	close(l->fd.fd);
	del_listener(l);
	tal_free(l);
}

static struct io_plan *io_never_called(struct io_conn *conn, void *arg)
{
	abort();
}

static void next_plan(struct io_conn *conn, struct io_plan *plan)
{
	struct io_plan *(*next)(struct io_conn *, void *arg);

	next = plan->next;

	plan->status = IO_UNSET;
	plan->io = NULL;
	plan->next = io_never_called;

	plan = next(conn, plan->next_arg);

	/* It should have set a plan inside this conn (or duplex) */
	assert(plan == &conn->plan[IO_IN]
	       || plan == &conn->plan[IO_OUT]
	       || plan == &conn->plan[2]);
	assert(conn->plan[IO_IN].status != IO_UNSET
	       || conn->plan[IO_OUT].status != IO_UNSET);

	backend_new_plan(conn);
}

static void set_blocking(int fd, bool block)
{
	int flags = fcntl(fd, F_GETFL);

	if (block)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;

	fcntl(fd, F_SETFL, flags);
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
	list_node_init(&conn->closing);
	conn->debug = false;

	if (!add_conn(conn))
		return tal_free(conn);

	/* Keep our I/O async. */
	set_blocking(fd, false);

	/* We start with out doing nothing, and in doing our init. */
	conn->plan[IO_OUT].status = IO_UNSET;

	conn->plan[IO_IN].next = init;
	conn->plan[IO_IN].next_arg = arg;
	next_plan(conn, &conn->plan[IO_IN]);

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

	conn->plan[dir].status = IO_POLLING;
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

static int do_plan(struct io_conn *conn, struct io_plan *plan)
{
	/* Someone else might have called io_close() on us. */
	if (plan->status == IO_CLOSING)
		return -1;

	/* We shouldn't have polled for this event if this wasn't true! */
	assert(plan->status == IO_POLLING);

	switch (plan->io(conn->fd.fd, &plan->arg)) {
	case -1:
		io_close(conn);
		return -1;
	case 0:
		return 0;
	case 1:
		next_plan(conn, plan);
		return 1;
	default:
		/* IO should only return -1, 0 or 1 */
		abort();
	}
}

void io_ready(struct io_conn *conn, int pollflags)
{
	if (pollflags & POLLIN)
		do_plan(conn, &conn->plan[IO_IN]);

	if (pollflags & POLLOUT)
		do_plan(conn, &conn->plan[IO_OUT]);
}

void io_do_always(struct io_conn *conn)
{
	if (conn->plan[IO_IN].status == IO_ALWAYS)
		next_plan(conn, &conn->plan[IO_IN]);

	if (conn->plan[IO_OUT].status == IO_ALWAYS)
		next_plan(conn, &conn->plan[IO_OUT]);
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
	/* Already closing?  Don't close twice. */
	if (conn->plan[IO_IN].status == IO_CLOSING)
		return &conn->plan[IO_IN];

	conn->plan[IO_IN].status = conn->plan[IO_OUT].status = IO_CLOSING;
	conn->plan[IO_IN].arg.u1.s = errno;
	backend_new_closing(conn);

	return io_set_plan(conn, IO_IN, NULL, NULL, NULL);
}

struct io_plan *io_close_cb(struct io_conn *conn, void *next_arg)
{
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

void io_duplex_prepare(struct io_conn *conn)
{
	assert(conn->plan[IO_IN].status == IO_UNSET);
	assert(conn->plan[IO_OUT].status == IO_UNSET);

	/* We can't sync debug until we've set both: io_wait() and io_always
	 * can't handle it. */
	conn->debug_saved = conn->debug;
	io_set_debug(conn, false);
}

struct io_plan *io_duplex_(struct io_plan *in_plan, struct io_plan *out_plan)
{
	struct io_conn *conn;

	/* in_plan must be conn->plan[IO_IN], out_plan must be [IO_OUT] */
	assert(out_plan == in_plan + 1);

	/* Restore debug. */
	conn = container_of(in_plan, struct io_conn, plan[IO_IN]);
	io_set_debug(conn, conn->debug_saved);

	/* Now set the plans again, to invoke sync debug. */
	io_set_plan(conn, IO_OUT,
		    out_plan->io, out_plan->next, out_plan->next_arg);
	io_set_plan(conn, IO_IN,
		    in_plan->io, in_plan->next, in_plan->next_arg);

	return out_plan + 1;
}

struct io_plan *io_halfclose(struct io_conn *conn)
{
	/* Already closing?  Don't close twice. */
	if (conn->plan[IO_IN].status == IO_CLOSING)
		return &conn->plan[IO_IN];

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
	assert(plan->status == IO_CLOSING || next != NULL);

	if (!conn->debug)
		return plan;

	if (io_loop_return) {
		io_debug_complete(conn);
		return plan;
	}

	switch (plan->status) {
	case IO_POLLING:
		while (do_plan(conn, plan) == 0);
		break;
	/* Shouldn't happen, since you said you did plan! */
	case IO_UNSET:
		abort();
	case IO_ALWAYS:
		/* If other one is ALWAYS, leave in list! */
		if (conn->plan[!dir].status != IO_ALWAYS)
			remove_from_always(conn);
		next_plan(conn, plan);
		break;
	case IO_WAITING:
	case IO_CLOSING:
		io_debug_complete(conn);
	}

	return plan;
}

void io_set_debug(struct io_conn *conn, bool debug)
{
	conn->debug = debug;

	/* Debugging means fds must block. */
	set_blocking(io_conn_fd(conn), debug);
}

void io_debug_complete(struct io_conn *conn)
{
}
