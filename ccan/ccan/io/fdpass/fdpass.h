/* GNU LGPL version 2 (or later) - see LICENSE file for details */
#ifndef CCAN_IO_FDPASS_H
#define CCAN_IO_FDPASS_H
#include <ccan/io/io.h>

/**
 * io_send_fd - output plan to send a file descriptor
 * @conn: the connection that plan is for.
 * @fd: the file descriptor to pass.
 * @fdclose: true to close fd after successful sending.
 * @next: function to call output is done.
 * @arg: @next argument
 *
 * This updates the output plan, to write out a file descriptor.  This
 * usually only works over an AF_LOCAL (ie. Unix domain) socket.  Once
 * that's sent, the @next function will be called: on an error, the
 * finish function is called instead.
 *
 * Note that the I/O may actually be done immediately, and the other end
 * of the socket must use io_recv_fd: if it does a normal read, the file
 * descriptor will be lost.
 *
 * Example:
 * static struct io_plan *fd_to_conn(struct io_conn *conn, int fd)
 * {
 *	// Write fd, then close conn.
 *	return io_send_fd(conn, fd, false, io_close_cb, NULL);
 * }
 */
#define io_send_fd(conn, fd, fdclose, next, arg)			\
	io_send_fd_((conn), (fd), (fdclose),				\
		    typesafe_cb_preargs(struct io_plan *, void *,	\
					(next), (arg), struct io_conn *), \
		    (arg))
struct io_plan *io_send_fd_(struct io_conn *conn,
			    int fd, bool fdclose,
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *arg);

/**
 * io_recv_fd - input plan to receive a file descriptor
 * @conn: the connection that plan is for.
 * @fd: a pointer to where to place to file descriptor
 * @next: function to call once input is done.
 * @arg: @next argument
 *
 * This creates a plan to receive a file descriptor, as sent by
 * io_send_fd.  Once it's all read, the @next function will be called:
 * on an error, the finish function is called instead.
 *
 * Note that the I/O may actually be done immediately.
 *
 * Example:
 * static struct io_plan *read_from_conn(struct io_conn *conn, int *fdp)
 * {
 *	// Read message, then close.
 *	return io_recv_fd(conn, fdp, io_close_cb, NULL);
 * }
 */
#define io_recv_fd(conn, fd, next, arg)					\
	io_recv_fd_((conn), (fd),					\
		    typesafe_cb_preargs(struct io_plan *, void *,	\
					(next), (arg), struct io_conn *), \
		    (arg))
struct io_plan *io_recv_fd_(struct io_conn *conn,
			    int *fd,
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *arg);
#endif /* CCAN_IO_FDPASS_H */
