/* lightningd/json_stream.h
 * Helpers for outputting JSON results into a membuf.
 */
#ifndef LIGHTNING_COMMON_JSON_STREAM_H
#define LIGHTNING_COMMON_JSON_STREAM_H
#include "config.h"

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/jsonrpc_errors.h>
#include <common/utils.h>

struct command;
struct io_conn;
struct logger;
struct json_escape;
struct pubkey;
struct bip340sig;
struct secret;
struct node_id;
struct channel_id;
struct channel_type;
struct bitcoin_txid;
struct bitcoin_outpoint;
struct short_channel_id;
struct sha256;
struct preimage;
struct bitcoin_tx;
struct wally_psbt;
struct lease_rates;
struct wireaddr;
struct wireaddr_internal;
struct onionmsg_hop;
struct blinded_path;

struct json_stream {
	struct json_out *jout;

	/* Who is writing to this buffer now; NULL if nobody is. */
	struct command *writer;

	/* Who is io_writing from this buffer now: NULL if nobody is. */
	struct io_conn *reader;
	struct io_plan *(*reader_cb)(struct io_conn *conn,
				     struct json_stream *js,
				     void *arg);
	void *reader_arg;
	size_t len_read;

	/* If non-NULL, reflects the current filter position */
	struct json_filter *filter;

	/* Where to log I/O */
	struct logger *log;
};


/**
 * new_json_stream - create a new JSON stream.
 * @ctx: tal context for allocation.
 * @writer: object responsible for writing to this stream.
 * @log: where to log the IO
 */
struct json_stream *new_json_stream(const tal_t *ctx, struct command *writer,
				    struct logger *log);

/**
 * Duplicate an existing stream.
 *
 * Mostly useful when we want to send copies of a given stream to
 * multiple recipients, that might read at different speeds from the
 * stream. For example this is used when construcing a single
 * notification and then duplicating it for the fanout.
 *
 * @ctx: tal context for allocation.
 * @original: the stream to duplicate.
 * @log: log for new stream.
 */
struct json_stream *json_stream_dup(const tal_t *ctx,
				    struct json_stream *original,
				    struct logger *log);

/* Attach a filter.  Usually this works at the result level: you don't
 * want to filter out id, etc! */
void json_stream_attach_filter(struct json_stream *js,
			       struct json_filter *filter STEALS);

/* Detach the filter: returns non-NULL string if it was misused. */
const char *json_stream_detach_filter(const tal_t *ctx, struct json_stream *js);

/**
 * json_stream_close - finished writing to a JSON stream.
 * @js: the json_stream.
 * @writer: object responsible for writing to this stream.
 */
void json_stream_close(struct json_stream *js, struct command *writer);

/* '"fieldname" : [ ' or '[ ' if fieldname is NULL */
void json_array_start(struct json_stream *js, const char *fieldname);
/* '"fieldname" : { ' or '{ ' if fieldname is NULL */
void json_object_start(struct json_stream *ks, const char *fieldname);
/* '],' */
void json_array_end(struct json_stream *js);
/* '},' */
void json_object_end(struct json_stream *js);

/**
 * json_stream_append - literally insert this string into the json_stream.
 * @js: the json_stream.
 * @str: the string.
 * @len: the length to append (<= strlen(str)).
 */
void json_stream_append(struct json_stream *js, const char *str, size_t len);

/**
 * json_add_primitive_fmt - add an unquoted literal member.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @fmt...: the printf-style format
 */
void json_add_primitive_fmt(struct json_stream *js,
			    const char *fieldname,
			    const char *fmt, ...) PRINTF_FMT(3,4);

/**
 * json_add_primitive - add an unquoted literal member.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @val: the primitive
 */
void json_add_primitive(struct json_stream *js,
			const char *fieldname,
			const char *val TAKES);

/**
 * json_add_str_fmt - add a string member (printf-style).
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @fmt...: the printf-style format
 */
void json_add_str_fmt(struct json_stream *js,
		      const char *fieldname,
		      const char *fmt, ...) PRINTF_FMT(3,4);

/**
 * json_add_string - add a string member.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @str: the string
 */
void json_add_string(struct json_stream *js,
		     const char *fieldname,
		     const char *str TAKES);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  String must
 * already be JSON escaped as necessary. */
void json_add_escaped_string(struct json_stream *result,
			     const char *fieldname,
			     const struct json_escape *esc TAKES);

/**
 * json_add_jsonstr - add a JSON entity in a string that is already
 * JSON-formatted.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @jsonstr: the JSON entity
 * @jsonstrlen: the length of @jsonstr
 */
void json_add_jsonstr(struct json_stream *js,
		      const char *fieldname,
		      const char *jsonstr,
		      size_t jsonstrlen);

/**
 * json_stream_output - start writing out a json_stream to this conn.
 * @js: the json_stream
 * @conn: the io_conn to write out to.
 * @cb: the callback to call once it's all written.
 * @arg: the argument to @cb
 */
#define json_stream_output(js, conn, cb, arg)				\
	json_stream_output_((js), (conn),				\
			    typesafe_cb_preargs(struct io_plan *,	\
						void *,			\
						(cb), (arg),		\
						struct io_conn *,	\
						struct json_stream *), \
			    (arg))

struct io_plan *json_stream_output_(struct json_stream *js,
				    struct io_conn *conn,
				    struct io_plan *(*cb)(struct io_conn *conn,
							  struct json_stream *js,
							  void *arg),
				    void *arg);

/* Ensure there's a double \n after a JSON response. */
void json_stream_double_cr(struct json_stream *js);
void json_stream_flush(struct json_stream *js);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  Turns
 * any non-printable chars into JSON escapes, but leaves existing escapes alone.
 */
void json_add_string(struct json_stream *result, const char *fieldname, const char *value);

/* '"fieldname" : "value[:value_len]"' or '"value[:value_len]"' if
 * fieldname is NULL.  Turns any non-printable chars into JSON
 * escapes, but leaves existing escapes alone.
 */
void json_add_stringn(struct json_stream *result, const char *fieldname,
		      const char *value TAKES, size_t value_len);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  String must
 * already be JSON escaped as necessary. */
void json_add_escaped_string(struct json_stream *result,
			     const char *fieldname,
			     const struct json_escape *esc TAKES);

/* '"fieldname" : literal' or 'literal' if fieldname is NULL*/
void json_add_literal(struct json_stream *result, const char *fieldname,
		      const char *literal, int len);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_num(struct json_stream *result, const char *fieldname,
		  unsigned int value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_u64(struct json_stream *result, const char *fieldname,
		  uint64_t value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_s64(struct json_stream *result, const char *fieldname,
		  int64_t value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_u32(struct json_stream *result, const char *fieldname,
		  uint32_t value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_s32(struct json_stream *result, const char *fieldname,
		  int32_t value);
/* '"fieldname" : true|false' or 'true|false' if fieldname is NULL */
void json_add_bool(struct json_stream *result, const char *fieldname,
		   bool value);

/* '"fieldname" : null' or 'null' if fieldname is NULL */
void json_add_null(struct json_stream *stream, const char *fieldname);

/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex(struct json_stream *result, const char *fieldname,
		  const void *data, size_t len);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data);

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t);

/* used in log.c and notification.c*/
void json_add_timestr(struct json_stream *result, const char *fieldname,
			  struct timespec ts);

/* Add ISO_8601 timestamp string, i.e. "2019-09-07T15:50+01:00" */
void json_add_timeiso(struct json_stream *result,
		      const char *fieldname,
		      struct timeabs time);

/* Add any json token */
void json_add_tok(struct json_stream *result, const char *fieldname,
                  const jsmntok_t *tok, const char *buffer);

/* Add an error code */
void json_add_jsonrpc_errcode(struct json_stream *result, const char *fieldname,
			      enum jsonrpc_errcode code);

/* Add "bolt11" or "bolt12" field, depending on invstring. */
void json_add_invstring(struct json_stream *result, const char *invstring);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key);

/* '"fieldname" : "89abcdef..."' or "89abcdef..." if fieldname is NULL */
void json_add_bip340sig(struct json_stream *response,
			const char *fieldname,
			const struct bip340sig *sig);

/* '"fieldname" : "89abcdef..."' or "89abcdef..." if fieldname is NULL */
void json_add_secret(struct json_stream *response,
		     const char *fieldname,
		     const struct secret *secret);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_node_id(struct json_stream *response,
				const char *fieldname,
				const struct node_id *id);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_channel_id(struct json_stream *response,
			 const char *fieldname,
			 const struct channel_id *cid);

/* '"fieldname" : <hexrev>' or "<hexrev>" if fieldname is NULL */
void json_add_txid(struct json_stream *result, const char *fieldname,
		   const struct bitcoin_txid *txid);

/* '"fieldname" : "txid:n" */
void json_add_outpoint(struct json_stream *result, const char *fieldname,
		       const struct bitcoin_outpoint *out);

/* '"fieldname" : "1234:5:6"' */
void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       struct short_channel_id id);

/* JSON serialize a network address for a node */
void json_add_address(struct json_stream *response, const char *fieldname,
		      const struct wireaddr *addr);

/* JSON serialize a network address for a node. */
void json_add_address_internal(struct json_stream *response,
			       const char *fieldname,
			       const struct wireaddr_internal *addr);

/* Adds an 'msat' field */
void json_add_amount_msat(struct json_stream *result,
			  const char *msatfieldname,
			  struct amount_msat msat)
	NO_NULL_ARGS;

/* Adds an 'msat' field */
void json_add_amount_sat_msat(struct json_stream *result,
			      const char *msatfieldname,
			      struct amount_sat sat)
	NO_NULL_ARGS;

/* This is used to create requests, *never* for output (output is always
 * msat!) */
void json_add_sats(struct json_stream *result,
		   const char *fieldname,
		   struct amount_sat sat)
	NO_NULL_ARGS;

void json_add_sha256(struct json_stream *result, const char *fieldname,
		     const struct sha256 *hash);

void json_add_preimage(struct json_stream *result, const char *fieldname,
		     const struct preimage *preimage);

/* '"fieldname" : "010000000001..."' or "010000000001..." if fieldname is NULL */
void json_add_tx(struct json_stream *result,
		 const char *fieldname,
		 const struct bitcoin_tx *tx);

/* '"fieldname" : "cHNidP8BAJoCAAAAAljo..." or "cHNidP8BAJoCAAAAAljo..." if fieldname is NULL */
void json_add_psbt(struct json_stream *stream,
		   const char *fieldname,
		   const struct wally_psbt *psbt);

/* Add fields from the lease_rates to a json stream.
 * Note that field names are set */
void json_add_lease_rates(struct json_stream *result,
			  const struct lease_rates *rates);

/* Add an id field literally (i.e. it's already a JSON primitive or string!) */
void json_add_id(struct json_stream *result, const char *id);

/* Add a blinded_path hop serialization. */
void json_add_onionmsg_path(struct json_stream *js, const char *fieldname,
			    const struct onionmsg_hop *hop);

/* Add a blinded_path structure serialization. */
void json_add_blinded_path(struct json_stream *js, const char *fieldname,
			   const struct blinded_path *blinded_path);

#endif /* LIGHTNING_COMMON_JSON_STREAM_H */
