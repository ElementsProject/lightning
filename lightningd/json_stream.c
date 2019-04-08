#include <ccan/io/io.h>
  /* To reach into io_plan: not a public header! */
  #include <ccan/io/backend.h>
#include <ccan/str/hex/hex.h>
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

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb,
				void *rawelems, size_t newsize)
{
	char *p = rawelems;

	tal_resize(&p, newsize);
	return p;
}

struct json_stream *new_json_stream(const tal_t *ctx,
				    struct command *writer,
				    struct log *log)
{
	struct json_stream *js = tal(ctx, struct json_stream);

	js->writer = writer;
	js->reader = NULL;
	membuf_init(&js->outbuf,
		    tal_arr(js, char, 64), 64, membuf_tal_realloc);
#if DEVELOPER
	js->wrapping = tal_arr(js, jsmntype_t, 0);
#endif
	js->empty = true;
	js->log = log;
	return js;
}

struct json_stream *json_stream_dup(const tal_t *ctx, struct json_stream *original)
{
	size_t num_elems = membuf_num_elems(&original->outbuf);
	char *elems = membuf_elems(&original->outbuf);
	struct json_stream *js = tal_dup(ctx, struct json_stream, original);
	membuf_init(&js->outbuf, tal_dup_arr(js, char, elems, num_elems, 0),
		    num_elems, membuf_tal_realloc);
	membuf_added(&js->outbuf, num_elems);
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

/* Make sure js->outbuf has room for len: return pointer */
static char *mkroom(struct json_stream *js, size_t len)
{
	ptrdiff_t delta = membuf_prepare_space(&js->outbuf, len);

	/* If io_write is in progress, we shift it to point to new buffer pos */
	if (js->reader)
		adjust_io_write(js->reader, delta);

	return membuf_space(&js->outbuf);
}

static void js_written_some(struct json_stream *js)
{
	/* Wake the stream reader. FIXME:  Could have a flag here to optimize */
	io_wake(js);
}

void json_stream_append_part(struct json_stream *js, const char *str, size_t len)
{
	mkroom(js, len);
	memcpy(membuf_add(&js->outbuf, len), str, len);
	js_written_some(js);
}

void json_stream_append(struct json_stream *js, const char *str)
{
	json_stream_append_part(js, str, strlen(str));
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
		vsprintf(mkroom(js, fmtlen + 1), fmt, ap2);
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

/* Caller must call js_written_some() if this returns non-NULL!
 * Will never return NULL if extra is nonzero.
 */
static char *json_start_member(struct json_stream *js,
			       const char *fieldname, size_t extra)
{
	char *dest;

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
	json_start_member(js, fieldname, 1)[0] = '[';
	js_written_some(js);
	js_indent(js, JSMN_ARRAY);
}

void json_array_end(struct json_stream *js)
{
	js_unindent(js, JSMN_ARRAY);
	json_stream_append(js, "]");
}

void json_object_start(struct json_stream *js, const char *fieldname)
{
	json_start_member(js, fieldname, 1)[0] = '{';
	js_written_some(js);
	js_indent(js, JSMN_OBJECT);
}

void json_object_end(struct json_stream *js)
{
	js_unindent(js, JSMN_OBJECT);
	json_stream_append(js, "}");
}

void PRINTF_FMT(3,4)
json_add_member(struct json_stream *js, const char *fieldname,
		const char *fmt, ...)
{
	va_list ap;

	json_start_member(js, fieldname, 0);
	va_start(ap, fmt);
	json_stream_append_vfmt(js, fmt, ap);
	va_end(ap);
}

void json_add_hex(struct json_stream *js, const char *fieldname,
		  const void *data, size_t len)
{
	/* Size without NUL term */
	size_t hexlen = hex_str_size(len) - 1;
	char *dest;

	dest = json_start_member(js, fieldname, 1 + hexlen + 1);
	dest[0] = '"';
	if (!hex_encode(data, len, dest + 1, hexlen + 1))
		abort();
	dest[1+hexlen] = '"';
	js_written_some(js);
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
