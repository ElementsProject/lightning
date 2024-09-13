#include "config.h"
/* FIXME: io_plan needs size_t */
 #include <unistd.h>
#include <ccan/io/io_plan.h>
#include <ccan/mem/mem.h>
#include <common/utils.h>
#include <errno.h>
#include <wire/wire_io.h>

/*
 * OK, this is a little tricky.  ccan/io lets you create your own plans,
 * beyond the standard io_read/io_write etc.  It provides a union to place
 * scratch data, and it's almost enough for our purposes.
 */

/* 4 bytes for the length header. */
#define HEADER_LEN (sizeof(wire_len_t))

/* We carefully never allow sizes > 64M, so this is an impossible value. */
#define INSIDE_HEADER_BIT WIRE_LEN_LIMIT

/* arg->u2.s contains length we've read, arg->u1.vp contains u8 **data. */
static int do_read_wire_header(int fd, struct io_plan_arg *arg)
{
	ssize_t ret;
	size_t len = arg->u2.s & ~INSIDE_HEADER_BIT;
	u8 *p = *(u8 **)arg->u1.vp;

	ret = read(fd, p + len, HEADER_LEN - len);
	if (ret <= 0) {
		/* Errno isn't set if we hit EOF, so set it to distinct value */
		if (ret == 0)
			errno = 0;
		return -1;
	}
	arg->u2.s += ret;

	/* Length bytes read?  Set up for normal read of data. */
	if (arg->u2.s == INSIDE_HEADER_BIT + HEADER_LEN) {
		arg->u2.s = wirelen_to_cpu(*(wire_len_t *)p);
		if (arg->u2.s >= INSIDE_HEADER_BIT) {
			errno = E2BIG;
			return -1;
		}
		/* A type-only message is not unheard of, so optimize a little */
		if (arg->u2.s != HEADER_LEN)
			tal_resize((u8 **)arg->u1.vp, arg->u2.s);
		arg->u1.vp = *(u8 **)arg->u1.vp;
	}

	return arg->u2.s == 0;
}

static int do_read_wire(int fd, struct io_plan_arg *arg)
{
	ssize_t ret;

	/* Still reading header? */
	if (arg->u2.s & INSIDE_HEADER_BIT) {
		ret = do_read_wire_header(fd, arg);
		/* If this is OK, and finished header, we continue below. */
		if (ret != 0 || (arg->u2.s & INSIDE_HEADER_BIT))
			return ret;
	}

	/* Normal read */
	ret = read(fd, arg->u1.cp, arg->u2.s);
	if (ret <= 0) {
		/* Errno isn't set if we hit EOF, so set it to distinct value */
		if (ret == 0)
			errno = 0;
		return -1;
	}

	arg->u1.cp += ret;
	arg->u2.s -= ret;
	return arg->u2.s == 0;
}

struct io_plan *io_read_wire_(struct io_conn *conn,
			      const tal_t *ctx,
			      u8 **data,
			      struct io_plan *(*next)(struct io_conn *, void *),
			      void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	/* We allocate data now; saves storing ctx, and lets us read in len. */
	arg->u1.vp = data;
	*data = tal_arr(ctx, u8, HEADER_LEN);

	/* We use u2 to store the length we've read. */
	arg->u2.s = INSIDE_HEADER_BIT;
	return io_set_plan(conn, IO_IN, do_read_wire, next, next_arg);
}

/* arg->u2.s contains length we've written, arg->u1 contains u8 *data. */
static int do_write_wire_header(int fd, struct io_plan_arg *arg)
{
	ssize_t ret;
	size_t len = arg->u2.s & ~INSIDE_HEADER_BIT;
	wire_len_t hdr = cpu_to_wirelen(tal_count(arg->u1.const_vp));

	ret = write(fd, (char *)&hdr + len, HEADER_LEN - len);
	if (ret <= 0)
		return -1;
	arg->u2.s += ret;

	/* Both bytes written?  Set up for normal write of data. */
	if (arg->u2.s == INSIDE_HEADER_BIT + HEADER_LEN)
		arg->u2.s = 0;

	return 0;
}

static int do_write_wire(int fd, struct io_plan_arg *arg)
{
	ssize_t ret;
	size_t totlen = tal_bytelen(arg->u1.cp);

	/* Still writing header? */
	if (arg->u2.s & INSIDE_HEADER_BIT) {
		ret = do_write_wire_header(fd, arg);
		/* If this is OK, and finished header, we continue below. */
		if (ret != 0 || (arg->u2.s & INSIDE_HEADER_BIT))
			return ret;
	}

	/* Normal write */
	ret = write(fd, arg->u1.cp + arg->u2.s, totlen - arg->u2.s);
	if (ret < 0)
		return -1;

	arg->u2.s += ret;
	if (arg->u2.s != totlen)
		return 0;

	tal_free(arg->u1.cp);
	return 1;
}

/* Write message from data (tal_count(data) gives length). */
struct io_plan *io_write_wire_(struct io_conn *conn,
			       const u8 *data,
			       struct io_plan *(*next)(struct io_conn *, void *),
			       void *next_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_OUT);

	if (tal_bytelen(data) >= INSIDE_HEADER_BIT) {
		errno = E2BIG;
		return io_close(conn);
	}

	arg->u1.const_vp = tal_dup_talarr(conn, u8,
					  memcheck(data, tal_bytelen(data)));

	/* We use u2 to store the length we've written. */
	arg->u2.s = INSIDE_HEADER_BIT;
	return io_set_plan(conn, IO_OUT, do_write_wire, next, next_arg);
}
