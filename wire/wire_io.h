#ifndef LIGHTNING_WIRE_WIRE_IO_H
#define LIGHTNING_WIRE_WIRE_IO_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>

/* We don't allow > 128M msgs: enough for more than 1M channels in gossip_getchannels_entry. */
#define WIRE_LEN_LIMIT (1 << 27)

typedef be32 wire_len_t;
#define wirelen_to_cpu be32_to_cpu
#define cpu_to_wirelen cpu_to_be32

/* Read message into *data, allocating off ctx. */
struct io_plan *io_read_wire_(struct io_conn *conn,
			      const tal_t *ctx,
			      u8 **data,
			      struct io_plan *(*next)(struct io_conn *, void *),
			      void *next_arg);

#define io_read_wire(conn, ctx, data, next, arg)			\
	io_read_wire_((conn), (ctx), (data),				\
		      typesafe_cb_preargs(struct io_plan *, void *,	\
					  (next), (arg), struct io_conn *), \
		      (arg))

/* Write message from data (tal_count(data) gives length).  data can be take() */
struct io_plan *io_write_wire_(struct io_conn *conn,
			       const u8 *data TAKES,
			       struct io_plan *(*next)(struct io_conn *, void *),
			       void *next_arg);

#define io_write_wire(conn, data, next, arg)				\
	io_write_wire_((conn), (data),					\
		       typesafe_cb_preargs(struct io_plan *, void *,	\
					   (next), (arg), struct io_conn *), \
		       (arg))
#endif /* LIGHTNING_WIRE_WIRE_IO_H */
