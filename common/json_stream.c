#include "config.h"
#include <ccan/io/io.h>
  /* To reach into io_plan: not a public header! */
  #include <ccan/io/backend.h>
#include <ccan/json_out/json_out.h>
#include <common/json_stream.h>


static void adjust_io_write(struct json_out *jout,
			    ptrdiff_t delta,
			    struct json_stream *js)
{
	/* If io_write is in progress, we shift it to point to new buffer pos */
	if (js->reader)
	/* FIXME: This, or something prettier (io_replan?) belong in ccan/io! */
		js->reader->plan[IO_OUT].arg.u1.cp += delta;
}

struct json_stream *new_json_stream(const tal_t *ctx,
				    struct command *writer,
				    struct log *log)
{
	struct json_stream *js = tal(ctx, struct json_stream);

	/* FIXME: Add magic so tal_resize can fail! */
	js->jout = json_out_new(js);
	json_out_call_on_move(js->jout, adjust_io_write, js);
	js->writer = writer;
	js->reader = NULL;
	js->log = log;
	return js;
}

struct json_stream *json_stream_dup(const tal_t *ctx,
				    struct json_stream *original,
				    struct log *log)
{
	struct json_stream *js = tal_dup(ctx, struct json_stream, original);

	if (original->jout)
		js->jout = json_out_dup(js, original->jout);
	js->log = log;
	return js;
}

/**
 * json_stream_still_writing - is someone currently writing to this stream?
 * @js: the json_stream.
 *
 * Has this json_stream not been closed yet?
 */
static bool json_stream_still_writing(const struct json_stream *js)
{
	return js->writer != NULL;
}

void json_stream_log_suppress(struct json_stream *js, const char *cmd_name)
{
	/* Really shouldn't be used for anything else */
	assert(streq(cmd_name, "getlog"));
	js->log = NULL;
}

/* If we have an allocation failure. */
static void COLD js_oom(struct json_stream *js)
{
	js->jout = tal_free(js->jout);
}

void json_stream_append(struct json_stream *js,
			const char *str, size_t len)
{
	char *dest;

	if (!js->jout)
		return;
	dest = json_out_direct(js->jout, len);
	if (!dest) {
		js_oom(js);
		return;
	}
	memcpy(dest, str, len);
}

/* We promise it will end in '\n\n' */
void json_stream_double_cr(struct json_stream *js)
{
	const char *contents;
	size_t len, cr_needed;

	if (!js->jout)
		return;

	/* Must be well-formed at this point! */
	json_out_finished(js->jout);

	contents = json_out_contents(js->jout, &len);
	/* It's an object (with an id!): definitely can't be less that "{}" */
	assert(len >= 2);
	if (contents[len-1] == '\n') {
		if (contents[len-2] == '\n')
			return;
		cr_needed = 1;
	} else
		cr_needed = 2;

	json_stream_append(js, "\n\n", cr_needed);
}

void json_stream_close(struct json_stream *js, struct command *writer)
{
	/* FIXME: We use writer == NULL for malformed: make writer a void *?
	 * I used to assert(writer); here. */
	assert(js->writer == writer);

	/* Should be well-formed at this point! */
	json_stream_double_cr(js);
	json_stream_flush(js);
	js->writer = NULL;
}

/* Also called when we're oom, so it will kill reader. */
void json_stream_flush(struct json_stream *js)
{
	/* Wake the stream reader. FIXME:  Could have a flag here to optimize */
	io_wake(js);
}

char *json_member_direct(struct json_stream *js,
			 const char *fieldname, size_t extra)
{
	char *dest;

	if (!js->jout)
		return NULL;

	dest = json_out_member_direct(js->jout, fieldname, extra);
	if (!dest)
		js_oom(js);
	return dest;
}

void json_array_start(struct json_stream *js, const char *fieldname)
{
	if (js->jout && !json_out_start(js->jout, fieldname, '['))
		js_oom(js);
}

void json_array_end(struct json_stream *js)
{
	if (js->jout && !json_out_end(js->jout, ']'))
		js_oom(js);
}

void json_object_start(struct json_stream *js, const char *fieldname)
{
	if (js->jout && !json_out_start(js->jout, fieldname, '{'))
		js_oom(js);
}

void json_object_end(struct json_stream *js)
{
	if (js->jout && !json_out_end(js->jout, '}'))
		js_oom(js);
}

void json_object_compat_end(struct json_stream *js)
{
	/* In 0.7.1 we upgraded pylightning to no longer need this. */
#ifdef COMPAT_V070
	json_stream_append(js, " ", 1);
#endif
	json_object_end(js);
}

void json_add_member(struct json_stream *js,
		     const char *fieldname,
		     bool quote,
		     const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (js->jout && !json_out_addv(js->jout, fieldname, quote, fmt, ap))
		js_oom(js);
	va_end(ap);
}

void json_add_jsonstr(struct json_stream *js,
		      const char *fieldname,
		      const char *jsonstr)
{
	char *p;
	size_t len = strlen(jsonstr);

	p = json_member_direct(js, fieldname, len);
	/* Could be OOM! */
	if (p)
		memcpy(p, jsonstr, len);
}

/* This is where we read the json_stream and write it to conn */
static struct io_plan *json_stream_output_write(struct io_conn *conn,
						struct json_stream *js)
{
	const char *p;

	/* Out of memory?  Nothing we can do but close conn */
	if (!js->jout)
		return io_close(conn);

	/* For when we've just done some output */
	json_out_consume(js->jout, js->len_read);

	/* Get how much we can write out from js */
	p = json_out_contents(js->jout, &js->len_read);

	/* Nothing in buffer? */
	if (!p) {
		/* We're not doing io_write now, unset. */
		js->reader = NULL;
		if (!json_stream_still_writing(js))
			return js->reader_cb(conn, js, js->reader_arg);
		return io_out_wait(conn, js, json_stream_output_write, js);
	}

	js->reader = conn;
	return io_write(conn,
			p, js->len_read,
			json_stream_output_write, js);
}

struct io_plan *json_stream_output_(struct json_stream *js,
				    struct io_conn *conn,
				    struct io_plan *(*cb)(struct io_conn *conn,
							  struct json_stream *js,
							  void *arg),
				    void *arg)
{
	assert(!js->reader);

	js->reader_cb = cb;
	js->reader_arg = arg;

	js->len_read = 0;
	return json_stream_output_write(conn, js);
}
