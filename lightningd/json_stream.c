#include <ccan/io/io.h>
  /* To reach into io_plan: not a public header! */
  #include <ccan/io/backend.h>
#include <common/utils.h>
#include <lightningd/json.h>
#include <lightningd/json_stream.h>
#include <stdarg.h>
#include <stdio.h>

struct json_stream {
#if DEVELOPER
	/* tal_arr of types (JSMN_OBJECT/JSMN_ARRAY) we're enclosed in. */
	jsmntype_t *wrapping;
#endif
	/* How far to indent. */
	size_t indent;

	/* True if we haven't yet put an element in current wrapping */
	bool empty;

	/* Who is writing to this buffer now; NULL if nobody is. */
	struct command *writer;

	/* Who is io_writing from this buffer now: NULL if nobody is. */
	struct io_conn *reader;
	struct io_plan *(*reader_cb)(struct io_conn *conn,
				     struct json_stream *js,
				     void *arg);
	void *reader_arg;
	size_t len_read;

	/* Current command's output. */
	MEMBUF(char) outbuf;
};

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb,
				void *rawelems, size_t newsize)
{
	char *p = rawelems;

	tal_resize(&p, newsize);
	return p;
}

struct json_stream *new_json_stream(const tal_t *ctx, struct command *writer)
{
	struct json_stream *js = tal(ctx, struct json_stream);

	js->writer = writer;
	js->reader = NULL;
	membuf_init(&js->outbuf,
		    tal_arr(js, char, 64), 64, membuf_tal_realloc);
#if DEVELOPER
	js->wrapping = tal_arr(js, jsmntype_t, 0);
#endif
	js->indent = 0;
	js->empty = true;
	return js;
}

bool json_stream_still_writing(const struct json_stream *js)
{
	return js->writer != NULL;
}

void json_stream_close(struct json_stream *js, struct command *writer)
{
	/* FIXME: We use writer == NULL for malformed: make writer a void *?
	 * I used to assert(writer); here. */
	assert(js->writer == writer);

	js->writer = NULL;
}

/* FIXME: This, or something prettier (io_replan?) belong in ccan/io! */
static void adjust_io_write(struct io_conn *conn, ptrdiff_t delta)
{
	conn->plan[IO_OUT].arg.u1.cp += delta;
}

/* Make sure js->outbuf has room for len */
static void mkroom(struct json_stream *js, size_t len)
{
	ptrdiff_t delta = membuf_prepare_space(&js->outbuf, len);

	/* If io_write is in progress, we shift it to point to new buffer pos */
	if (js->reader)
		adjust_io_write(js->reader, delta);
}

static void js_written_some(struct json_stream *js)
{
	/* Wake the stream reader. FIXME:  Could have a flag here to optimize */
	io_wake(js);
}

void json_stream_append(struct json_stream *js, const char *str)
{
	size_t len = strlen(str);

	mkroom(js, len);
	memcpy(membuf_add(&js->outbuf, len), str, len);
	js_written_some(js);
}

static void json_stream_append_vfmt(struct json_stream *js,
				    const char *fmt, va_list ap)
{
	size_t fmtlen;
	va_list ap2;

	/* Make a copy in case we need it below. */
	va_copy(ap2, ap);

	/* Try printing in place first. */
	fmtlen = vsnprintf(membuf_space(&js->outbuf),
			   membuf_num_space(&js->outbuf), fmt, ap);

	/* Horrible subtlety: vsnprintf *will* NUL terminate, even if it means
	 * chopping off the last character.  So if fmtlen ==
	 * membuf_num_space(&jcon->outbuf), the result was truncated! */
	if (fmtlen >= membuf_num_space(&js->outbuf)) {
		/* Make room for NUL terminator, even though we don't want it */
		mkroom(js, fmtlen + 1);
		vsprintf(membuf_space(&js->outbuf), fmt, ap2);
	}
	membuf_added(&js->outbuf, fmtlen);
	js_written_some(js);
	va_end(ap2);
}

void PRINTF_FMT(2,3)
json_stream_append_fmt(struct json_stream *js, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	json_stream_append_vfmt(js, fmt, ap);
	va_end(ap);
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

static void js_append_indent(struct json_stream *js)
{
	static const char indent_buf[] = "                                ";
	size_t len;

	for (size_t i = 0; i < js->indent * 2; i += len) {
		len = js->indent * 2;
		if (len > sizeof(indent_buf)-1)
			len = sizeof(indent_buf)-1;
		/* Use tail of indent_buf string. */
		json_stream_append(js, indent_buf + sizeof(indent_buf) - 1 - len);
	}
}

static void json_start_member(struct json_stream *js, const char *fieldname)
{
	/* Prepend comma if required. */
	if (!js->empty)
		json_stream_append(js, ", \n");
	else
		json_stream_append(js, "\n");

	js_append_indent(js);

	check_fieldname(js, fieldname);
	if (fieldname)
		json_stream_append_fmt(js, "\"%s\": ", fieldname);
	js->empty = false;
}

static void js_indent(struct json_stream *js, jsmntype_t type)
{
#if DEVELOPER
	*tal_arr_expand(&js->wrapping) = type;
#endif
	js->empty = true;
	js->indent++;
}

static void js_unindent(struct json_stream *js, jsmntype_t type)
{
	assert(js->indent);
#if DEVELOPER
	assert(tal_count(js->wrapping) == js->indent);
	assert(js->wrapping[js->indent-1] == type);
	tal_resize(&js->wrapping, js->indent-1);
#endif
	js->empty = false;
	js->indent--;
}

void json_array_start(struct json_stream *js, const char *fieldname)
{
	json_start_member(js, fieldname);
	json_stream_append(js, "[");
	js_indent(js, JSMN_ARRAY);
}

void json_array_end(struct json_stream *js)
{
	json_stream_append(js, "\n");
	js_unindent(js, JSMN_ARRAY);
	js_append_indent(js);
	json_stream_append(js, "]");
}

void json_object_start(struct json_stream *js, const char *fieldname)
{
	json_start_member(js, fieldname);
	json_stream_append(js, "{");
	js_indent(js, JSMN_OBJECT);
}

void json_object_end(struct json_stream *js)
{
	json_stream_append(js, "\n");
	js_unindent(js, JSMN_OBJECT);
	js_append_indent(js);
	json_stream_append(js, "}");
}

void PRINTF_FMT(3,4)
json_add_member(struct json_stream *js, const char *fieldname,
		const char *fmt, ...)
{
	va_list ap;

	json_start_member(js, fieldname);
	va_start(ap, fmt);
	json_stream_append_vfmt(js, fmt, ap);
	va_end(ap);
}

/* This is where we read the json_stream and write it to conn */
static struct io_plan *json_stream_output_write(struct io_conn *conn,
						struct json_stream *js)
{
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
