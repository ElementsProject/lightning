/* lightningd/json_stream.h
 * Helpers for outputting JSON results into a membuf.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSON_STREAM_H
#define LIGHTNING_LIGHTNINGD_JSON_STREAM_H
#include "config.h"
#include <ccan/membuf/membuf.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct command;
struct io_conn;
struct json_stream;

/**
 * new_json_stream - create a new JSON stream.
 * @ctx: tal context for allocation.
 * @writer: object responsible for writing to this stream.
 */
struct json_stream *new_json_stream(const tal_t *ctx, struct command *writer);

/**
 * json_stream_close - finished writing to a JSON stream.
 * @js: the json_stream.
 * @writer: object responsible for writing to this stream.
 */
void json_stream_close(struct json_stream *js, struct command *writer);

/**
 * json_stream_still_writing - is someone currently writing to this stream?
 * @js: the json_stream.
 *
 * Has this json_stream not been closed yet?
 */
bool json_stream_still_writing(const struct json_stream *js);


/* '"fieldname" : [ ' or '[ ' if fieldname is NULL */
void json_array_start(struct json_stream *js, const char *fieldname);
/* '"fieldname" : { ' or '{ ' if fieldname is NULL */
void json_object_start(struct json_stream *ks, const char *fieldname);
/* ' ], ' */
void json_array_end(struct json_stream *js);
/* ' }, ' */
void json_object_end(struct json_stream *js);

/**
 * json_stream_append - literally insert this string into the json_stream.
 * @js: the json_stream.
 * @str: the string.
 */
void json_stream_append(struct json_stream *js, const char *str);

/**
 * json_stream_append_fmt - insert formatted string into the json_stream.
 * @js: the json_stream.
 * @fmt...: the printf-style format
 */
void PRINTF_FMT(2,3)
json_stream_append_fmt(struct json_stream *js, const char *fmt, ...);

/**
 * json_add_member - add a generic member.
 * @js: the json_stream.
 * @fieldname: optional fieldname.
 * @fmt...: the printf-style format
 */
void PRINTF_FMT(3,4)
json_add_member(struct json_stream *js, const char *fieldname,
		const char *fmt, ...);

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

#endif /* LIGHTNING_LIGHTNINGD_JSON_STREAM_H */
