#include <ccan/io/io.h>
  /* To reach into io_plan: not a public header! */
  #include <ccan/io/backend.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/utils.h>
#include <lightningd/json.h>
#include <lightningd/json_stream.h>
#include <lightningd/log.h>
#include <stdarg.h>
#include <stdio.h>

struct json_stream {
#if DEVELOPER
	/* tal_arr of types (JSMN_OBJECT/JSMN_ARRAY) we're enclosed in. */
	jsmntype_t *wrapping;
#endif
	/* True if we haven't yet put an element in current wrapping */
	bool empty;

	/* True if we ran out of memory: don't touch outbuf! */
	bool oom;

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

	/* Current command's output. */
	MEMBUF(char) outbuf;
};

static void free_json_stream_membuf(struct json_stream *js)
{
	free(membuf_cleanup(&js->outbuf));
}

struct json_stream *new_json_stream(const tal_t *ctx,
				    struct command *writer,
				    struct log *log)
{
	struct json_stream *js = tal(ctx, struct json_stream);

	js->writer = writer;
	js->reader = NULL;
	/* We don't use tal here, because we handle failure externally (tal
	 * helpfully aborts with a msg, which is usually right) */
	membuf_init(&js->outbuf, malloc(64), 64, membuf_realloc);
	tal_add_destructor(js, free_json_stream_membuf);
#if DEVELOPER
	js->wrapping = tal_arr(js, jsmntype_t, 0);
#endif
	js->empty = true;
	js->oom = false;
	js->log = log;
	return js;
}

struct json_stream *json_stream_dup(const tal_t *ctx,
				    struct json_stream *original,
				    struct log *log)
{
	size_t num_elems = membuf_num_elems(&original->outbuf);
	char *elems = membuf_elems(&original->outbuf);
	struct json_stream *js = tal_dup(ctx, struct json_stream, original);

	if (!js->oom) {
		char *newelems = malloc(sizeof(*elems) * num_elems);
		if (!newelems)
			js->oom = true;
		else {
			memcpy(newelems, elems, sizeof(*elems) * num_elems);
			tal_add_destructor(js, free_json_stream_membuf);
			membuf_init(&js->outbuf, newelems, num_elems,
				    membuf_realloc);
			membuf_added(&js->outbuf, num_elems);
		}
	}
	js->log = log;
	return js;
}

bool json_stream_still_writing(const struct json_stream *js)
{
	return js->writer != NULL;
}

void json_stream_log_suppress(struct json_stream *js, const char *cmd_name)
{
	/* Really shouldn't be used for anything else */
	assert(streq(cmd_name, "getlog"));
	js->log = NULL;
}

/* FIXME: This, or something prettier (io_replan?) belong in ccan/io! */
static void adjust_io_write(struct io_conn *conn, ptrdiff_t delta)
{
	conn->plan[IO_OUT].arg.u1.cp += delta;
}

/* Make sure js->outbuf has room for len: return pointer, or NULL on OOM. */
static char *mkroom(struct json_stream *js, size_t len)
{
	ptrdiff_t delta;
	assert(!js->oom);

	delta = membuf_prepare_space(&js->outbuf, len);
	if (membuf_num_space(&js->outbuf) < len) {
		char msg[100];

		/* Be a little paranoid: avoid allocations here */
		snprintf(msg, sizeof(msg),
			 "Out of memory allocating JSON membuf len %zu+%zu",
			 membuf_num_elems(&js->outbuf), len);

		/* Clean it up immediately, in case we need the mem. */
		js->oom = true;
		free_json_stream_membuf(js);
		tal_del_destructor(js, free_json_stream_membuf);
		send_backtrace(msg);
		return NULL;
	}

	/* If io_write is in progress, we shift it to point to new buffer pos */
	if (js->reader)
		adjust_io_write(js->reader, delta);

	return membuf_space(&js->outbuf);
}

void json_stream_append(struct json_stream *js,
			const char *str, size_t len)
{
	if (js->oom || !mkroom(js, len))
		return;
	memcpy(membuf_add(&js->outbuf, len), str, len);
}

void json_stream_close(struct json_stream *js, struct command *writer)
{
	/* FIXME: We use writer == NULL for malformed: make writer a void *?
	 * I used to assert(writer); here. */
	assert(js->writer == writer);

	json_stream_append(js, "\n\n", strlen("\n\n"));
	json_stream_flush(js);
	js->writer = NULL;
}

/* Also called when we're oom, so it will kill reader. */
void json_stream_flush(struct json_stream *js)
{
	/* Wake the stream reader. FIXME:  Could have a flag here to optimize */
	io_wake(js);
}

static void check_fieldname(const struct json_stream *js,
			    const char *fieldname)
{
#if DEVELOPER
	size_t n = tal_count(js->wrapping);
	if (n == 0)
		/* Can't have a fieldname if not in anything! */
		assert(!fieldname);
	else if (js->wrapping[n-1] == JSMN_ARRAY)
		/* No fieldnames in arrays. */
		assert(!fieldname);
	else
		/* Must have fieldnames in objects. */
		assert(fieldname);
#endif
}

char *json_member_direct(struct json_stream *js,
			 const char *fieldname, size_t extra)
{
	char *dest;

	if (js->oom)
		return NULL;

	/* Prepend comma if required. */
	if (!js->empty)
		extra++;

	check_fieldname(js, fieldname);
	if (fieldname)
		extra += 1 + strlen(fieldname) + 2;

	if (!extra) {
		dest = NULL;
		goto out;
	}

	dest = mkroom(js, extra);
	if (!dest)
		goto out;

	if (!js->empty)
		*(dest++) = ',';
	if (fieldname) {
		*(dest++) = '"';
		memcpy(dest, fieldname, strlen(fieldname));
		dest += strlen(fieldname);
		*(dest++) = '"';
		*(dest++) = ':';
	}
	membuf_added(&js->outbuf, extra);

out:
	js->empty = false;
	return dest;
}

static void js_indent(struct json_stream *js, jsmntype_t type)
{
#if DEVELOPER
	tal_arr_expand(&js->wrapping, type);
#endif
	js->empty = true;
}

static void js_unindent(struct json_stream *js, jsmntype_t type)
{
#if DEVELOPER
	size_t indent = tal_count(js->wrapping);
	assert(indent > 0);
	assert(js->wrapping[indent-1] == type);
	tal_resize(&js->wrapping, indent-1);
#endif
	js->empty = false;
}

void json_array_start(struct json_stream *js, const char *fieldname)
{
	char *dest = json_member_direct(js, fieldname, 1);
	if (dest)
		dest[0] = '[';
	js_indent(js, JSMN_ARRAY);
}

void json_array_end(struct json_stream *js)
{
	js_unindent(js, JSMN_ARRAY);
	json_stream_append(js, "]", 1);
}

void json_object_start(struct json_stream *js, const char *fieldname)
{
	char *dest = json_member_direct(js, fieldname, 1);
	if (dest)
		dest[0] = '{';
	js_indent(js, JSMN_OBJECT);
}

void json_object_end(struct json_stream *js)
{
	js_unindent(js, JSMN_OBJECT);
	json_stream_append(js, "}", 1);
}

void json_add_member(struct json_stream *js,
		     const char *fieldname,
		     bool quote,
		     const char *fmt, ...)
{
	va_list ap;
	char *str, *p;

	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	if (quote) {
		struct json_escape *e = json_escape(NULL, take(str));

		p = json_member_direct(js, fieldname, strlen(e->s) + 2);
		if (!p)
			return;
		p[0] = p[1 + strlen(e->s)] = '"';
		memcpy(p+1, e->s, strlen(e->s));
		tal_free(e);
	} else {
		p = json_member_direct(js, fieldname, strlen(str));
		if (!p)
			return;
		memcpy(p, str, strlen(str));
		tal_free(str);
	}
}

/* This is where we read the json_stream and write it to conn */
static struct io_plan *json_stream_output_write(struct io_conn *conn,
						struct json_stream *js)
{
	/* Out of memory?  Nothing we can do but close conn */
	if (js->oom)
		return io_close(conn);

	/* For when we've just done some output */
	membuf_consume(&js->outbuf, js->len_read);

	/* Get how much we can write out from js */
	js->len_read = membuf_num_elems(&js->outbuf);

	/* Nothing in buffer? */
	if (js->len_read == 0) {
		/* We're not doing io_write now, unset. */
		js->reader = NULL;
		if (!json_stream_still_writing(js))
			return js->reader_cb(conn, js, js->reader_arg);
		return io_out_wait(conn, js, json_stream_output_write, js);
	}

	js->reader = conn;
	if (js->log)
		log_io(js->log, LOG_IO_OUT, "",
		       membuf_elems(&js->outbuf), js->len_read);
	return io_write(conn,
			membuf_elems(&js->outbuf), js->len_read,
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
