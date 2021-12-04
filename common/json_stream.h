/* lightningd/json_stream.h
 * Helpers for outputting JSON results into a membuf.
 */
#ifndef LIGHTNING_COMMON_JSON_STREAM_H
#define LIGHTNING_COMMON_JSON_STREAM_H
#include "config.h"
#include <ccan/tal/tal.h>

struct command;
struct io_conn;
struct log;

struct json_stream {
	/* NULL if we ran OOM! */
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

	/* Where to log I/O */
	struct log *log;
};


/**
 * new_json_stream - create a new JSON stream.
 * @ctx: tal context for allocation.
 * @writer: object responsible for writing to this stream.
 * @log: where to log the IO
 */
struct json_stream *new_json_stream(const tal_t *ctx, struct command *writer,
				    struct log *log);

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
				    struct log *log);

/**
 * json_stream_close - finished writing to a JSON stream.
 * @js: the json_stream.
 * @writer: object responsible for writing to this stream.
 */
void json_stream_close(struct json_stream *js, struct command *writer);

/* For low-level JSON stream access: */
void json_stream_log_suppress(struct json_stream *js, const char *cmd_name);

/* '"fieldname" : [ ' or '[ ' if fieldname is NULL */
void json_array_start(struct json_stream *js, const char *fieldname);
/* '"fieldname" : { ' or '{ ' if fieldname is NULL */
void json_object_start(struct json_stream *ks, const char *fieldname);
/* '],' */
void json_array_end(struct json_stream *js);
/* '},' */
void json_object_end(struct json_stream *js);
/* ' },' */
void json_object_compat_end(struct json_stream *js);

/**
 * json_stream_append - literally insert this string into the json_stream.
 * @js: the json_stream.
 * @str: the string.
 * @len: the length to append (<= strlen(str)).
 */
void json_stream_append(struct json_stream *js, const char *str, size_t len);

/**
 * json_add_member - add a generic member.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @quote: true if should be escaped and wrapped in "".
 * @fmt...: the printf-style format
 *
 * The resulting string from @fmt is escaped if quote is true:
 * see json_member_direct to avoid quoting.
 */
void json_add_member(struct json_stream *js,
		     const char *fieldname,
		     bool quote,
		     const char *fmt, ...) PRINTF_FMT(4,5);

/**
 * json_add_jsonstr - add a JSON entity in a string that is already
 * JSON-formatted.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @jsonstr: the JSON entity, must be non-NULL, a null-terminated
 * string that is already formatted in JSON.
 */
void json_add_jsonstr(struct json_stream *js,
		      const char *fieldname,
		      const char *jsonstr);

/**
 * json_member_direct - start a generic member.
 * @js: the json_stream.
 * @fieldname: fieldname (if in object), otherwise must be NULL.
 * @extra: the space to reserve.
 *
 * Returns NULL if oom, otherwise returns a ptr to @extra bytes.
 */
char *json_member_direct(struct json_stream *js,
			 const char *fieldname, size_t extra);

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

#endif /* LIGHTNING_COMMON_JSON_STREAM_H */
