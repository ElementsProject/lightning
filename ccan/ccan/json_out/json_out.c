/* MIT (BSD) license - see LICENSE file for details */
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
#include <ccan/membuf/membuf.h>
#include <stdarg.h>
#include <stdio.h>

struct json_out {
	/* Callback if we reallocate. */
	void (*move_cb)(struct json_out *jout, ptrdiff_t delta, void *arg);
	void *cb_arg;
	
#ifdef CCAN_JSON_OUT_DEBUG
	/* tal_arr of types ( or [ we're enclosed in.  NULL if oom. */
	char *wrapping;
#endif
	/* True if we haven't yet put an element in current wrapping */
	bool empty;

	/* Output. */
	MEMBUF(char) outbuf;
};

/* Realloc helper for tal membufs */
static void *membuf_tal_realloc(struct membuf *mb,
				void *rawelems, size_t newsize)
{
	char *p = rawelems;

	if (!tal_resize(&p, newsize))
		return NULL;
	return p;
}

struct json_out *json_out_new(const tal_t *ctx)
{
	struct json_out *jout = tal(ctx, struct json_out);
	char *pool;

	if (!jout)
		return NULL;
	pool = tal_arr(jout, char, 64);
	if (!pool)
		return tal_free(jout);

	membuf_init(&jout->outbuf, pool, tal_count(pool), membuf_tal_realloc);
#ifdef CCAN_JSON_OUT_DEBUG
	jout->wrapping = tal_arr(jout, char, 0);
#endif
	jout->empty = true;
	jout->move_cb = NULL;
	return jout;
}

void json_out_call_on_move_(struct json_out *jout,
			    void (*cb)(struct json_out *jout, ptrdiff_t delta,
				       void *arg),
			    void *arg)
{
	if (cb)
		assert(!jout->move_cb);
	jout->move_cb = cb;
	jout->cb_arg = arg;
}

struct json_out *json_out_dup(const tal_t *ctx, const struct json_out *src)
{
	size_t num_elems = membuf_num_elems(&src->outbuf);
	char *elems = membuf_elems(&src->outbuf);
	struct json_out *jout = tal_dup(ctx, struct json_out, src);
	char *pool;

	if (!jout)
		return NULL;
	pool = tal_dup_arr(jout, char, elems, num_elems, 0);
	if (!pool)
		return tal_free(jout);
	membuf_init(&jout->outbuf, pool, num_elems, membuf_tal_realloc);
	membuf_added(&jout->outbuf, num_elems);
#ifdef CCAN_JSON_OUT_DEBUG
	jout->wrapping = tal_dup_arr(jout, char,
				     jout->wrapping, tal_count(jout->wrapping),
				     0);
#endif
	return jout;
}

static void indent(struct json_out *jout, char type)
{
#ifdef CCAN_JSON_OUT_DEBUG
	/* Can't check if we ran out of memory. */
	if (jout->wrapping) {
		size_t n = tal_count(jout->wrapping);
		if (!tal_resize(&jout->wrapping, n+1))
			jout->wrapping = tal_free(jout->wrapping);
		else
			jout->wrapping[n] = type;
	}
#endif
	jout->empty = true;
}

static void unindent(struct json_out *jout, char type)
{
#ifdef CCAN_JSON_OUT_DEBUG
	/* Can't check if we ran out of memory. */
	if (jout->wrapping) {
		size_t indent = tal_count(jout->wrapping);
		assert(indent > 0);
		/* Both [ and ] and { and } are two apart in ASCII */
		assert(jout->wrapping[indent-1] == type - 2);
		tal_resize(&jout->wrapping, indent-1);
	}
#endif
	jout->empty = false;
}

/* Make sure jout->outbuf has room for len: return pointer */
static char *mkroom(struct json_out *jout, size_t len)
{
	ptrdiff_t delta = membuf_prepare_space(&jout->outbuf, len);

	if (delta && jout->move_cb)
		jout->move_cb(jout, delta, jout->cb_arg);

	return membuf_space(&jout->outbuf);
}

static void check_fieldname(const struct json_out *jout,
			    const char *fieldname)
{
#ifdef CCAN_JSON_OUT_DEBUG
	/* We don't escape this for you */
	assert(!fieldname || !json_escape_needed(fieldname, strlen(fieldname)));

	/* Can't check anything else if we ran out of memory. */
	if (jout->wrapping) {
		size_t n = tal_count(jout->wrapping);
		if (n == 0)
			/* Can't have a fieldname if not in anything! */
			assert(!fieldname);
		else if (jout->wrapping[n-1] == '[')
			/* No fieldnames in arrays. */
			assert(!fieldname);
		else {
			/* Must have fieldnames in objects. */
			assert(fieldname);
		}
	}
#endif
}

char *json_out_member_direct(struct json_out *jout,
			     const char *fieldname, size_t extra)
{
	char *dest;

	/* Prepend comma if required. */
	if (!jout->empty)
		extra++;

	check_fieldname(jout, fieldname);
	if (fieldname)
		extra += 1 + strlen(fieldname) + 2;

	dest = mkroom(jout, extra);
	if (!dest)
		goto out;

	if (!jout->empty)
		*(dest++) = ',';
	if (fieldname) {
		*(dest++) = '"';
		memcpy(dest, fieldname, strlen(fieldname));
		dest += strlen(fieldname);
		*(dest++) = '"';
		*(dest++) = ':';
	}
	membuf_added(&jout->outbuf, extra);

out:
	jout->empty = false;
	return dest;
}

bool json_out_start(struct json_out *jout, const char *fieldname, char type)
{
	char *p;

	assert(type == '[' || type == '{');
	p = json_out_member_direct(jout, fieldname, 1);
	if (p)
		p[0] = type;
	indent(jout, type);

	return p != NULL;
}

bool json_out_end(struct json_out *jout, char type)
{
	char *p;

	assert(type == '}' || type == ']');
	p = json_out_direct(jout, 1);
	if (p)
		p[0] = type;
	unindent(jout, type);

	return p != NULL;
}

bool json_out_addv(struct json_out *jout,
		   const char *fieldname,
		   bool quote,
		   const char *fmt,
		   va_list ap)
{
	size_t fmtlen, avail;
	va_list ap2;
	char *dst;

	if (!json_out_member_direct(jout, fieldname, 0))
		return false;

	/* Make a copy in case we need it below. */
	va_copy(ap2, ap);

	/* We can use any additional space, but need room for ". */
	avail = membuf_num_space(&jout->outbuf);
	if (quote) {
		if (avail < 2)
			avail = 0;
		else
			avail -= 2;
	}

	/* Try printing in place first. */
	dst = membuf_space(&jout->outbuf);
	fmtlen = vsnprintf(dst + quote, avail, fmt, ap);

	/* Horrible subtlety: vsnprintf *will* NUL terminate, even if it means
	 * chopping off the last character.  So if fmtlen ==
	 * membuf_num_space(&jout->outbuf), the result was truncated! */
	if (fmtlen + (int)quote*2 >= membuf_num_space(&jout->outbuf)) {
		/* Make room for NUL terminator, even though we don't want it */
		dst = mkroom(jout, fmtlen + 1 + (int)quote*2);
		if (!dst)
			goto out;
		vsprintf(dst + quote, fmt, ap2);
	}

#ifdef CCAN_JSON_OUT_DEBUG
	/* You're not inserting junk here, are you? */
	assert(quote || !json_escape_needed(dst, fmtlen));
#endif

	/* Of course, if we need to escape it, we have to redo it all. */
	if (quote) {
		if (json_escape_needed(dst + quote, fmtlen)) {
			struct json_escape *e;
			e = json_escape_len(NULL, dst + quote, fmtlen);
			fmtlen = strlen(e->s);
			dst = mkroom(jout, fmtlen + (int)quote*2);
			if (!dst)
				goto out;
			memcpy(dst + quote, e, fmtlen);
			tal_free(e);
		}
		dst[0] = '"';
		dst[fmtlen+1] = '"';
	}
	membuf_added(&jout->outbuf, fmtlen + (int)quote*2);

out:
	va_end(ap2);
	return dst != NULL;
}

bool json_out_add(struct json_out *jout,
		  const char *fieldname,
		  bool quote,
		  const char *fmt, ...)
{
	va_list ap;
	bool ret;

	va_start(ap, fmt);
	ret = json_out_addv(jout, fieldname, quote, fmt, ap);
	va_end(ap);
	return ret;
}

bool json_out_addstr(struct json_out *jout,
		     const char *fieldname,
		     const char *str)
{
	size_t len = strlen(str);
	char *p;
	struct json_escape *e;

	if (json_escape_needed(str, len)) {
		e = json_escape(NULL, str);
		str = e->s;
		len = strlen(str);
	} else
		e = NULL;

	p = json_out_member_direct(jout, fieldname, len + 2);
	if (p) {
		p[0] = p[1+len] = '"';
		memcpy(p+1, str, len);
	}
	tal_free(e);

	return p != NULL;
}

bool json_out_add_splice(struct json_out *jout,
			 const char *fieldname,
			 const struct json_out *src)
{
	const char *p;
	size_t len;

	p = json_out_contents(src, &len);
	if (!p)
		return false;
	memcpy(json_out_member_direct(jout, fieldname, len), p, len);
	return true;
}

char *json_out_direct(struct json_out *jout, size_t len)
{
	char *p = mkroom(jout, len);
	if (p)
		membuf_added(&jout->outbuf, len);
	return p;
}

void json_out_finished(struct json_out *jout)
{
#ifdef CCAN_JSON_OUT_DEBUG
	assert(tal_count(jout->wrapping) == 0);
#endif
	jout->empty = true;
}

const char *json_out_contents(const struct json_out *jout, size_t *len)
{
	*len = membuf_num_elems(&jout->outbuf);
	return *len ? membuf_elems(&jout->outbuf) : NULL;
}

void json_out_consume(struct json_out *jout, size_t len)
{
	membuf_consume(&jout->outbuf, len);
}
