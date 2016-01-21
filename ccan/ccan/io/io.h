/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#ifndef CCAN_IO_H
#define CCAN_IO_H
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>
#include <unistd.h>

struct timers;
struct timer;
struct list_head;

/**
 * struct io_plan - a plan for input or output.
 *
 * Each io_conn has zero to two of these active at any time.
 */
struct io_plan;

/**
 * struct io_conn - a connection associated with an fd.
 */
struct io_conn;

/**
 * io_new_conn - create a new connection.
 * @ctx: the context to tal from (or NULL)
 * @fd: the file descriptor.
 * @init: the function to call for a new connection
 * @arg: the argument to @init.
 *
 * This creates a connection which owns @fd, it then calls
 * @init to initialize the connection, which sets up an io_plan.
 *
 * Returns NULL on error (and sets errno).
 *
 * Example:
 * // Dumb init function to print string and tell conn to close.
 * static struct io_plan *conn_init(struct io_conn *conn, const char *msg)
 * {
 *	printf("Created conn %p: %s", conn, msg);
 *	return io_close(conn);
 * }
 *
 * static void create_self_closing_pipe(void)
 * {
 *	int fd[2];
 *	struct io_conn *conn;
 *
 *	pipe(fd);
 *	conn = io_new_conn(NULL, fd[0], conn_init, (const char *)"hi!");
 *	if (!conn)
 *		exit(1);
 * }
 */
#define io_new_conn(ctx, fd, init, arg)					\
	io_new_conn_((ctx), (fd),					\
		     typesafe_cb_preargs(struct io_plan *, void *,	\
					 (init), (arg),			\
					 struct io_conn *conn),		\
		     (void *)(arg))

struct io_conn *io_new_conn_(const tal_t *ctx, int fd,
			     struct io_plan *(*init)(struct io_conn *, void *),
			     void *arg);

/**
 * io_set_finish - set finish function on a connection.
 * @conn: the connection.
 * @finish: the function to call when it's closed or fails.
 * @arg: the argument to @finish.
 *
 * @finish will be called when an I/O operation fails, or you call
 * io_close() on the connection.  errno will be set to the value
 * after the failed I/O, or at the call to io_close().  The fd
 * will be closed before @finish is called.
 *
 * Example:
 * static void finish(struct io_conn *conn, const char *msg)
 * {
 *	// errno is not 0 after success, so this is a bit useless.
 *	printf("Conn %p closed with errno %i (%s)\n", conn, errno, msg);
 * }
 *
 * // Dumb init function to print string and tell conn to close.
 * static struct io_plan *conn_init(struct io_conn *conn, const char *msg)
 * {
 *	io_set_finish(conn, finish, msg);
 *	return io_close(conn);
 * }
 */
#define io_set_finish(conn, finish, arg)				\
	io_set_finish_((conn),						\
		       typesafe_cb_preargs(void, void *,		\
					   (finish), (arg),		\
					   struct io_conn *),		\
		       (void *)(arg))
void io_set_finish_(struct io_conn *conn,
		    void (*finish)(struct io_conn *, void *),
		    void *arg);


/**
 * io_new_listener - create a new accepting listener.
 * @ctx: the context to tal from (or NULL)
 * @fd: the file descriptor.
 * @init: the function to call for a new connection
 * @arg: the argument to @init.
 *
 * When @fd becomes readable, we accept(), create a new connection,
 * (tal'ocated off @ctx) and pass that to init().
 *
 * Returns NULL on error (and sets errno).
 *
 * Example:
 * #include <sys/types.h>
 * #include <sys/socket.h>
 * #include <netdb.h>
 *
 * ...
 *
 * // Set up a listening socket, return it.
 * static struct io_listener *do_listen(const char *port)
 * {
 *	struct addrinfo *addrinfo, hints;
 *	int fd, on = 1;
 *
 *	memset(&hints, 0, sizeof(hints));
 *	hints.ai_family = AF_UNSPEC;
 *	hints.ai_socktype = SOCK_STREAM;
 *	hints.ai_flags = AI_PASSIVE;
 *	hints.ai_protocol = 0;
 *
 *	if (getaddrinfo(NULL, port, &hints, &addrinfo) != 0)
 *		return NULL;
 *
 *	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
 *		    addrinfo->ai_protocol);
 *	if (fd < 0)
 *		return NULL;
 *
 *	freeaddrinfo(addrinfo);
 *	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
 *	if (bind(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0) {
 *		close(fd);
 *		return NULL;
 *	}
 *	if (listen(fd, 1) != 0) {
 *		close(fd);
 *		return NULL;
 *	}
 *	return io_new_listener(NULL, fd, conn_init, (const char *)"listened!");
 * }
 */
#define io_new_listener(ctx, fd, init, arg)				\
	io_new_listener_((ctx), (fd),					\
			 typesafe_cb_preargs(struct io_plan *, void *,	\
					     (init), (arg),		\
					     struct io_conn *conn),	\
			 (void *)(arg))
struct io_listener *io_new_listener_(const tal_t *ctx, int fd,
				     struct io_plan *(*init)(struct io_conn *,
							     void *),
				     void *arg);

/**
 * io_close_listener - delete a listener.
 * @listener: the listener returned from io_new_listener.
 *
 * This closes the fd and frees @listener.
 *
 * Example:
 * ...
 *	struct io_listener *l = do_listen("8111");
 *	if (l) {
 *		io_loop(NULL, NULL);
 *		io_close_listener(l);
 *	}
 */
void io_close_listener(struct io_listener *listener);

/**
 * io_write - output plan to write data.
 * @conn: the connection that plan is for.
 * @data: the data buffer.
 * @len: the length to write.
 * @next: function to call output is done.
 * @arg: @next argument
 *
 * This updates the output plan, to write out a data buffer.  Once it's all
 * written, the @next function will be called: on an error, the finish
 * function is called instead.
 *
 * Note that the I/O may actually be done immediately.
 *
 * Example:
 * static struct io_plan *write_to_conn(struct io_conn *conn, const char *msg)
 * {
 *	// Write message, then close.
 *	return io_write(conn, msg, strlen(msg), io_close_cb, NULL);
 * }
 */
#define io_write(conn, data, len, next, arg)				\
	io_write_((conn), (data), (len),				\
		  typesafe_cb_preargs(struct io_plan *, void *,		\
				      (next), (arg), struct io_conn *),	\
		  (arg))
struct io_plan *io_write_(struct io_conn *conn,
			  const void *data, size_t len,
			  struct io_plan *(*next)(struct io_conn *, void *),
			  void *arg);

/**
 * io_read - input plan to read data.
 * @conn: the connection that plan is for.
 * @data: the data buffer.
 * @len: the length to read.
 * @next: function to call once input is done.
 * @arg: @next argument
 *
 * This creates a plan to read data into a buffer.  Once it's all
 * read, the @next function will be called: on an error, the finish
 * function is called instead.
 *
 * Note that the I/O may actually be done immediately.
 *
 * Example:
 * static struct io_plan *read_from_conn(struct io_conn *conn, char *buf)
 * {
 *	// Read message, then close.
 *	return io_read(conn, buf, 12, io_close_cb, NULL);
 * }
 */
#define io_read(conn, data, len, next, arg)				\
	io_read_((conn), (data), (len),					\
		 typesafe_cb_preargs(struct io_plan *, void *,		\
				     (next), (arg), struct io_conn *),	\
		 (arg))
struct io_plan *io_read_(struct io_conn *conn,
			 void *data, size_t len,
			 struct io_plan *(*next)(struct io_conn *, void *),
			 void *arg);


/**
 * io_read_partial - input plan to read some data.
 * @conn: the connection that plan is for.
 * @data: the data buffer.
 * @maxlen: the maximum length to read
 * @lenp: set to the length actually read.
 * @next: function to call once input is done.
 * @arg: @next argument
 *
 * This creates a plan to read data into a buffer.  Once any data is
 * read, @len is updated and the @next function will be called: on an
 * error, the finish function is called instead.
 *
 * Note that the I/O may actually be done immediately.
 *
 * Example:
 * struct buf {
 *	size_t len;
 *	char buf[12];
 * };
 *
 * static struct io_plan *dump(struct io_conn *conn, struct buf *b)
 * {
 *	printf("Partial read: '%*s'\n", (int)b->len, b->buf);
 *	free(b);
 *	return io_close(conn);
 * }
 *
 * static struct io_plan *read_part(struct io_conn *conn, struct buf *b)
 * {
 *	// Read message, then dump and close.
 *	return io_read_partial(conn, b->buf, sizeof(b->buf), &b->len, dump, b);
 * }
 */
#define io_read_partial(conn, data, maxlen, lenp, next, arg)		\
	io_read_partial_((conn), (data), (maxlen), (lenp),		\
			 typesafe_cb_preargs(struct io_plan *, void *,	\
					     (next), (arg),		\
					     struct io_conn *),		\
			 (arg))
struct io_plan *io_read_partial_(struct io_conn *conn,
				 void *data, size_t maxlen, size_t *lenp,
				 struct io_plan *(*next)(struct io_conn *,
							 void *),
				 void *arg);

/**
 * io_write_partial - output plan to write some data.
 * @conn: the connection that plan is for.
 * @data: the data buffer.
 * @maxlen: the maximum length to write
 * @lenp: set to the length actually written.
 * @next: function to call once output is done.
 * @arg: @next argument
 *
 * This creates a plan to write data from a buffer.   Once any data is
 * written, @len is updated and the @next function will be called: on an
 * error, the finish function is called instead.
 *
 * Note that the I/O may actually be done immediately.
 *
 * Example:
 * struct buf {
 *	size_t len;
 *	char buf[12];
 * };
 *
 * static struct io_plan *show_partial(struct io_conn *conn, struct buf *b)
 * {
 *	printf("Only wrote: '%*s'\n", (int)b->len, b->buf);
 *	free(b);
 *	return io_close(conn);
 * }
 *
 * static struct io_plan *write_part(struct io_conn *conn, struct buf *b)
 * {
 *	// Write message, then dump and close.
 *	strcpy(b->buf, "Hello world");
 *	return io_write_partial(conn, b->buf, strlen(b->buf),
 *				&b->len, show_partial, b);
 * }
 */
#define io_write_partial(conn, data, maxlen, lenp, next, arg)		\
	io_write_partial_((conn), (data), (maxlen), (lenp),		\
			  typesafe_cb_preargs(struct io_plan *, void *,	\
					      (next), (arg),		\
					      struct io_conn *),	\
			  (arg))
struct io_plan *io_write_partial_(struct io_conn *conn,
				  const void *data, size_t maxlen, size_t *lenp,
				  struct io_plan *(*next)(struct io_conn *,
							  void*),
				  void *arg);

/**
 * io_always - plan to immediately call next callback
 * @conn: the connection that plan is for.
 * @next: function to call.
 * @arg: @next argument
 *
 * Sometimes it's neater to plan a callback rather than call it directly;
 * for example, if you only need to read data for one path and not another.
 *
 * Example:
 * static struct io_plan *init_conn_with_nothing(struct io_conn *conn,
 *						 void *unused)
 * {
 *	// Silly example: close on next time around loop.
 *	return io_always(conn, io_close_cb, NULL);
 * }
 */
#define io_always(conn, next, arg)					\
	io_always_((conn), typesafe_cb_preargs(struct io_plan *, void *, \
					       (next), (arg),		\
					       struct io_conn *),	\
		   (arg))

struct io_plan *io_always_(struct io_conn *conn,
			   struct io_plan *(*next)(struct io_conn *, void *),
			   void *arg);

/**
 * io_out_always - output plan to immediately call next callback
 * @conn: the connection that plan is for.
 * @next: function to call.
 * @arg: @next argument
 *
 * This is a variant of io_always() which uses the output plan; it only
 * matters if you are using io_duplex, and thus have two plans running at
 * once.
 */
#define io_out_always(conn, next, arg)					\
	io_out_always_((conn), typesafe_cb_preargs(struct io_plan *, void *, \
						   (next), (arg),	\
						   struct io_conn *),	\
		       (arg))

struct io_plan *io_out_always_(struct io_conn *conn,
			       struct io_plan *(*next)(struct io_conn *,
						       void *),
			       void *arg);

/**
 * io_connect - create an asynchronous connection to a listening socket.
 * @conn: the connection that plan is for.
 * @addr: where to connect.
 * @init: function to call once it's connected
 * @arg: @init argument
 *
 * This initiates a connection, and creates a plan for
 * (asynchronously) completing it.  Once complete, the @init function
 * will be called.
 *
 * Example:
 * #include <sys/types.h>
 * #include <sys/socket.h>
 * #include <netdb.h>
 *
 * // Write, then close socket.
 * static struct io_plan *init_connect(struct io_conn *conn,
 *				       struct addrinfo *addrinfo)
 * {
 *	return io_connect(conn, addrinfo, io_close_cb, NULL);
 * }
 *
 * ...
 *
 *	int fd;
 *	struct addrinfo *addrinfo;
 *
 *	fd = socket(AF_INET, SOCK_STREAM, 0);
 *	getaddrinfo("localhost", "8111", NULL, &addrinfo);
 *	io_new_conn(NULL, fd, init_connect, addrinfo);
 */
struct addrinfo;
#define io_connect(conn, addr, next, arg)				\
	io_connect_((conn), (addr),					\
		    typesafe_cb_preargs(struct io_plan *, void *,	\
					(next), (arg),			\
					struct io_conn *),		\
		    (arg))

struct io_plan *io_connect_(struct io_conn *conn, const struct addrinfo *addr,
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *arg);

/**
 * io_duplex - set plans for both input and output.
 * @conn: the connection that plan is for.
 * @in: the input plan
 * @out: the output plan
 *
 * Most plans are either for input or output; io_duplex creates a plan
 * which does both.  This is often used in the init function to create
 * two independent streams, though it can be used once on any connection.
 *
 * Note that if either plan closes the connection, it will be closed.
 *
 * Example:
 * struct buf {
 *	char in[100];
 *	char out[100];
 * };
 *
 * static struct io_plan *read_and_write(struct io_conn *conn, struct buf *b)
 * {
 *	return io_duplex(conn,
 *			 io_read(conn, b->in, sizeof(b->in), io_close_cb, b),
 *			 io_write(conn, b->out, sizeof(b->out), io_close_cb,b));
 * }
 */
#define io_duplex(conn, in_plan, out_plan) \
	(io_duplex_prepare(conn), io_duplex_(in_plan, out_plan))

struct io_plan *io_duplex_(struct io_plan *in_plan, struct io_plan *out_plan);
void io_duplex_prepare(struct io_conn *conn);

/**
 * io_halfclose - close half of an io_duplex connection.
 * @conn: the connection that plan is for.
 *
 * It's common to want to close a duplex connection after both input and
 * output plans have completed.  If either calls io_close() the connection
 * closes immediately.  Instead, io_halfclose() needs to be called twice.
 *
 * Example:
 * struct buf {
 *	char in[100];
 *	char out[100];
 * };
 *
 * static struct io_plan *finish(struct io_conn *conn, struct buf *b)
 * {
 *	return io_halfclose(conn);
 * }
 *
 * static struct io_plan *read_and_write(struct io_conn *conn, struct buf *b)
 * {
 *	return io_duplex(conn,
 *			 io_read(conn, b->in, sizeof(b->in), finish, b),
 *			 io_write(conn, b->out, sizeof(b->out), finish, b));
 * }
 */
struct io_plan *io_halfclose(struct io_conn *conn);

/**
 * io_wait - leave a plan idle until something wakes us.
 * @conn: the connection that plan is for.
 * @waitaddr: the address to wait on.
 * @next: function to call after waiting.
 * @arg: @next argument
 *
 * This leaves the input or output idle: io_wake(@waitaddr) will be
 * called later to restart the connection.
 *
 * Example:
 * // Silly example to wait then close.
 * static struct io_plan *wait(struct io_conn *conn, void *b)
 * {
 *	return io_wait(conn, b, io_close_cb, NULL);
 * }
 */
#define io_wait(conn, waitaddr, next, arg)				\
	io_wait_((conn), (waitaddr),					\
		 typesafe_cb_preargs(struct io_plan *, void *,		\
				     (next), (arg),			\
				     struct io_conn *),			\
		 (arg))

struct io_plan *io_wait_(struct io_conn *conn,
			 const void *wait,
			 struct io_plan *(*next)(struct io_conn *, void *),
			 void *arg);


/**
 * io_out_wait - leave the output plan idle until something wakes us.
 * @conn: the connection that plan is for.
 * @waitaddr: the address to wait on.
 * @next: function to call after waiting.
 * @arg: @next argument
 *
 * io_wait() makes the input plan idle: if you're not using io_duplex it
 * doesn't matter which plan is waiting.  Otherwise, you may need to use
 * io_out_wait() instead, to specify explicitly that the output plan is
 * waiting.
 */
#define io_out_wait(conn, waitaddr, next, arg)				\
	io_out_wait_((conn), (waitaddr),				\
		     typesafe_cb_preargs(struct io_plan *, void *,	\
					 (next), (arg),			\
					 struct io_conn *),		\
		     (arg))

struct io_plan *io_out_wait_(struct io_conn *conn,
			     const void *wait,
			     struct io_plan *(*next)(struct io_conn *, void *),
			     void *arg);

/**
 * io_wake - wake up any connections waiting on @wait
 * @waitaddr: the address to trigger.
 *
 * All io_conns who have returned io_wait() on @waitaddr will move on
 * to their next callback.
 *
 * Example:
 * static struct io_plan *wake_it(struct io_conn *conn, void *b)
 * {
 *	io_wake(b);
 *	return io_close(conn);
 * }
 */
void io_wake(const void *wait);

/**
 * io_break - return from io_loop()
 * @ret: non-NULL value to return from io_loop().
 *
 * This breaks out of the io_loop.  As soon as the current function
 * returns, any io_close()'d connections will have their finish
 * callbacks called, then io_loop() with return with @ret.
 *
 * If io_loop() is called again, then @plan will be carried out.
 *
 * Example:
 *	static struct io_plan *fail_on_timeout(struct io_conn *conn, char *msg)
 *	{
 *		io_break(msg);
 *		return io_close(conn);
 *	}
 */
void io_break(const void *ret);

/**
 * io_never - assert if callback is called.
 * @conn: the connection that plan is for.
 * @unused: an unused parameter to make this suitable for use as a callback.
 *
 * Sometimes you want to make it clear that a callback should never happen
 * (eg. for io_break).  This will assert() if called.
 *
 * Example:
 * static struct io_plan *break_out(struct io_conn *conn, void *unused)
 * {
 *	io_break(conn);
 *	// We won't ever return from io_break
 *	return io_never(conn, NULL);
 * }
 */
struct io_plan *io_never(struct io_conn *conn, void *unused);

/* FIXME: io_recvfrom/io_sendto */

/**
 * io_close - plan to close a connection.
 * @conn: the connection to close.
 *
 * On return to io_loop, the connection will be closed.  It doesn't have
 * to be the current connection and it doesn't need to be idle.  No more
 * IO or callbacks will occur.
 *
 * You can close a connection twice without harmful effects.
 *
 * Example:
 * static struct io_plan *close_on_timeout(struct io_conn *conn, const char *msg)
 * {
 *	printf("closing: %s\n", msg);
 *	return io_close(conn);
 * }
 */
struct io_plan *io_close(struct io_conn *conn);

/**
 * io_close_cb - helper callback to close a connection.
 * @conn: the connection.
 *
 * This schedules a connection to be closed; designed to be used as
 * a callback function.
 *
 * Example:
 *	#define close_on_timeout io_close_cb
 */
struct io_plan *io_close_cb(struct io_conn *, void *unused);

/**
 * io_loop - process fds until all closed on io_break.
 * @timers - timers which are waiting to go off (or NULL for none)
 * @expired - an expired timer (can be NULL if @timers is)
 *
 * This is the core loop; it exits with the io_break() arg, or NULL if
 * all connections and listeners are closed, or with @expired set to an
 * expired timer (if @timers isn't NULL).
 *
 * Example:
 *	io_loop(NULL, NULL);
 */
void *io_loop(struct timers *timers, struct timer **expired);

/**
 * io_conn_fd - get the fd from a connection.
 * @conn: the connection.
 *
 * Sometimes useful, eg for getsockname().
 */
int io_conn_fd(const struct io_conn *conn);

/**
 * io_time_override - override the normal call for time.
 * @nowfn: the function to call.
 *
 * io usually uses time_now() internally, but this forces it
 * to use your function (eg. for debugging).  Returns the old
 * one.
 */
struct timeabs (*io_time_override(struct timeabs (*now)(void)))(void);

/**
 * io_set_debug - set synchronous mode on a connection.
 * @conn: the connection.
 * @debug: whether to enable or disable debug.
 *
 * Once @debug is true on a connection, all I/O is done synchronously
 * as soon as it is set, until it is unset or @conn is closed.  This
 * makes it easy to debug what's happening with a connection, but note
 * that other connections are starved while this is being done.
 *
 * See also: io_debug_complete()
 *
 * Example:
 * // Dumb init function to set debug and tell conn to close.
 * static struct io_plan *conn_init(struct io_conn *conn, const char *msg)
 * {
 *	io_set_debug(conn, true);
 *	return io_close(conn);
 * }
 */
void io_set_debug(struct io_conn *conn, bool debug);

/**
 * io_debug_complete - empty function called when conn is closing/waiting.
 * @conn: the connection.
 *
 * This is for putting a breakpoint onto, when debugging.  It is called
 * when a conn with io_set_debug() true can no longer be synchronous:
 * 1) It is io_close()'d
 * 2) It enters io_wait() (sychronous debug will resume after io_wake())
 * 3) io_break() is called (sychronous debug will resume after io_loop())
 */
void io_debug_complete(struct io_conn *conn);
#endif /* CCAN_IO_H */
