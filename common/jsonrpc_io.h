/* Low-level helper library for C plugins using ccan/io and jsonrpc socket. */
#ifndef LIGHTNING_COMMON_JSONRPC_IO_H
#define LIGHTNING_COMMON_JSONRPC_IO_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/json_parse_simple.h>

struct io_conn;
struct plugin;

/**
 * jsonrpc_io_new: allocate a fresh jsonrpc_io
 */
struct jsonrpc_io *jsonrpc_io_new(const tal_t *ctx);


/**
 * jsonrpc_io_read: set io_plan for reading more into buffer.
 * @conn: the io_conn to read.
 * @json_in: the jsonrpc_io.
 * @next: the callback once a read is done.
 * @arg: the argument for @next (typesafe).
 */
struct io_plan *jsonrpc_io_read_(struct io_conn *conn,
				 struct jsonrpc_io *json_in,
				 struct io_plan *(*next)(struct io_conn *,
							 void *),
				 void *arg);
#define jsonrpc_io_read(ctx, json_in, next, arg)			\
	jsonrpc_io_read_((ctx), (json_in),				\
			 typesafe_cb_preargs(struct io_plan *, void *,	\
					     (next), (arg),		\
					     struct io_conn *),		\
			 (arg))

/**
 * jsonrpc_newly_read: how much did we read into the buffer?
 *
 * Returns the buffer and sets *len to the bytes just read.  After
 * that it will return *len == 0.
 */
const char *jsonrpc_newly_read(struct jsonrpc_io *json_in,
			       size_t *len);

/**
 * jsonrpc_io_parse: try to parse more of the buffer.
 * @ctx: context to allocate error message off.
 * @json_in: json_in after jsonrpc_io_read.
 * @toks: returned non-NULL if there's a whole valid json object.
 * @buf: returned non-NULL as above.
 *
 * On error, a message is returned.  On incomplete, *@toks and *@buf
 * are NULL.  Usually you call this, the use the result and call
 * jsonrpc_io_parse_done(), then call it again.
 */
const char *jsonrpc_io_parse(const tal_t *ctx,
			     struct jsonrpc_io *json_in,
			     const jsmntok_t **toks,
			     const char **buf);

/**
 * jsonrpc_io_parse_done: call aftr using toks from jsonrpc_io_parse.
 * @json_in: json_in after jsonrpc_io_parse.
 *
 * You must call this if jsonrpc_io_parse() sets *toks non-NULL
 * (i.e. complete, and no error).
 */
void jsonrpc_io_parse_done(struct jsonrpc_io *json_in);

#endif /* LIGHTNING_COMMON_JSONRPC_IO_H */
