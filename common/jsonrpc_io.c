#include "config.h"

#include <ccan/io/io.h>
#include <ccan/membuf/membuf.h>
#include <ccan/tal/str/str.h>
#include <common/jsonrpc_io.h>
#include <common/utils.h>

#define READ_CHUNKSIZE 64

struct jsonrpc_io {
	MEMBUF(char) membuf;
	jsmn_parser parser;
	jsmntok_t *toks;

	/* Amount just read by io_read_partial */
	size_t bytes_read;
};

struct jsonrpc_io *jsonrpc_io_new(const tal_t *ctx)
{
	struct jsonrpc_io *json_in;

	json_in = tal(ctx, struct jsonrpc_io);
	json_in->bytes_read = 0;

	membuf_init(&json_in->membuf,
		    tal_arr(json_in, char, READ_CHUNKSIZE),
		    READ_CHUNKSIZE, membuf_tal_resize);
	json_in->toks = toks_alloc(json_in);
	jsmn_init(&json_in->parser);

	return json_in;
}

/* Empty new bytes read into our unparsed buffer */
static void add_newly_read(struct jsonrpc_io *json_in)
{
	/* Now added it to our unparsed buffer */
	assert(json_in->bytes_read <= membuf_num_space(&json_in->membuf));
	membuf_added(&json_in->membuf, json_in->bytes_read);
	json_in->bytes_read = 0;
}

const char *jsonrpc_newly_read(struct jsonrpc_io *json_in,
			       size_t *len)
{
	*len = json_in->bytes_read;

	add_newly_read(json_in);

	return membuf_space(&json_in->membuf) - *len;
}

const char *jsonrpc_io_parse(const tal_t *ctx,
			     struct jsonrpc_io *json_in,
			     const jsmntok_t **toks,
			     const char **buf)
{
	bool complete;

	/* If we're read any more, add that */
	add_newly_read(json_in);
	*toks = NULL;
	*buf = NULL;

	if (!json_parse_input(&json_in->parser, &json_in->toks,
			      membuf_elems(&json_in->membuf),
			      membuf_num_elems(&json_in->membuf),
			      &complete)) {
		return tal_fmt(ctx, "Failed to parse RPC JSON response '%.*s'",
			       (int)membuf_num_elems(&json_in->membuf),
			       membuf_elems(&json_in->membuf));
	}

	if (!complete)
		return NULL;

	/* Must have jsonrpc to be valid! */
	if (!json_get_member(membuf_elems(&json_in->membuf),
			     json_in->toks,
			     "jsonrpc")) {
		return tal_fmt(ctx,
			       "JSON-RPC message does not contain \"jsonrpc\" field: '%.*s'",
			       (int)membuf_num_elems(&json_in->membuf),
			       membuf_elems(&json_in->membuf));
	}

	*toks = json_in->toks;
	*buf = membuf_elems(&json_in->membuf);
	return NULL;
}

void jsonrpc_io_parse_done(struct jsonrpc_io *json_in)
{
	size_t bytes_parsed = json_in->toks[0].end;
	membuf_consume(&json_in->membuf, bytes_parsed);

	jsmn_init(&json_in->parser);
	toks_reset(json_in->toks);
}

struct io_plan *jsonrpc_io_read_(struct io_conn *conn,
				 struct jsonrpc_io *json_in,
				 struct io_plan *(*next)(struct io_conn *,
							 void *),
				 void *arg)
{
	/* Make sure there's more room */
	membuf_prepare_space(&json_in->membuf, READ_CHUNKSIZE);

	/* Try to read more. */
	json_in->bytes_read = 0;
	return io_read_partial(conn,
			       membuf_space(&json_in->membuf),
			       membuf_num_space(&json_in->membuf),
			       &json_in->bytes_read,
			       next, arg);
}
