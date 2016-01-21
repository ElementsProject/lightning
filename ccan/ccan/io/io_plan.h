/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#ifndef CCAN_IO_PLAN_H
#define CCAN_IO_PLAN_H
struct io_conn;

/**
 * union io_plan_union - type for struct io_plan read/write fns.
 */
union io_plan_union {
	char *cp;
	void *vp;
	const void *const_vp;
	size_t s;
	char c[sizeof(size_t)];
};

/**
 * struct io_plan_arg - scratch space for struct io_plan read/write fns.
 */
struct io_plan_arg {
	union io_plan_union u1, u2;
};

enum io_direction {
	IO_IN,
	IO_OUT
};

/**
 * io_plan_arg - get a conn's io_plan_arg for a given direction.
 * @conn: the connection.
 * @dir: IO_IN or IO_OUT.
 *
 * This is how an io helper gets scratch space to store into; you must call
 * io_set_plan() when you've initialized it.
 *
 * Example:
 * #include <ccan/io/io_plan.h>
 *
 * // Simple helper to read a single char.
 * static int do_readchar(int fd, struct io_plan_arg *arg)
 * {
 *	return read(fd, arg->u1.cp, 1) <= 0 ? -1 : 1;
 * }
 *
 * static struct io_plan *io_read_char_(struct io_conn *conn, char *in,
 *				 struct io_plan *(*next)(struct io_conn*,void*),
 *				 void *next_arg)
 * {
 *	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);
 *
 *	// Store information we need in the plan unions u1 and u2.
 *	arg->u1.cp = in;
 *
 *	return io_set_plan(conn, IO_IN, do_readchar, next, next_arg);
 * }
 */
struct io_plan_arg *io_plan_arg(struct io_conn *conn, enum io_direction dir);

/**
 * io_set_plan - set a conn's io_plan.
 * @conn: the connection.
 * @dir: IO_IN or IO_OUT.
 * @io: the IO function to call when the fd is ready.
 * @next: the next callback when @io returns 1.
 * @next_arg: the argument to @next.
 *
 * If @conn has debug set, the io function will be called immediately,
 * so it's important that this be the last thing in your function!
 *
 * See also:
 *	io_get_plan_arg()
 */
struct io_plan *io_set_plan(struct io_conn *conn, enum io_direction dir,
			    int (*io)(int fd, struct io_plan_arg *arg),
			    struct io_plan *(*next)(struct io_conn *, void *),
			    void *next_arg);
#endif /* CCAN_IO_PLAN_H */
