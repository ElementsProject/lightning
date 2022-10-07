/*	$Id$ */
/*
 * Copyright (c) 2008, Natacha Porté
 * Copyright (c) 2011, Vicent Martí
 * Copyright (c) 2014, Xavier Mendez, Devin Torres and the Hoedown authors
 * Copyright (c) 2016, 2021, Kristaps Dzonsons
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#if HAVE_SYS_QUEUE
# include <sys/queue.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

static void
hbuf_init(struct lowdown_buf *buf, size_t unit, int buffer_free)
{

	assert(buf != NULL);
	buf->data = NULL;
	buf->size = buf->maxsize = 0;
	buf->unit = unit;
	buf->buffer_free = buffer_free;
}

/*
 * Return a buffer that deep-copies "buf".  Returns the pointer of NULL
 * on memory allocation failure.
 */
struct lowdown_buf *
hbuf_dup(const struct lowdown_buf *buf)
{
	struct lowdown_buf	*v;

	v = calloc(1, sizeof(struct lowdown_buf));
	if (v != NULL && hbuf_clone(buf, v))
		return v;
	free(v);
	return NULL;
}

/*
 * Deep-copies "buf" into "v", wiping its contents.  Returns TRUE on
 * success or FALSE on memory allocation failure.
 */
int
hbuf_clone(const struct lowdown_buf *buf, struct lowdown_buf *v)
{

	*v = *buf;
	if (buf->size) {
		if ((v->data = malloc(buf->size)) == NULL)
			return 0;
		memcpy(v->data, buf->data, buf->size);
	} else
		v->data = NULL;

	return 1;
}

void
hbuf_truncate(struct lowdown_buf *buf)
{

	buf->size = 0;
}

int
hbuf_streq(const struct lowdown_buf *buf1, const char *buf2)
{
	size_t	 sz;

	sz = strlen(buf2);
	return buf1->size == sz &&
	       memcmp(buf1->data, buf2, sz) == 0;
}

int
hbuf_strprefix(const struct lowdown_buf *buf1, const char *buf2)
{
	size_t	 sz;

	sz = strlen(buf2);
	return buf1->size >= sz &&
	       memcmp(buf1->data, buf2, sz) == 0;
}

int
hbuf_eq(const struct lowdown_buf *buf1, const struct lowdown_buf *buf2)
{

	return buf1->size == buf2->size &&
	       memcmp(buf1->data, buf2->data, buf1->size) == 0;
}

struct lowdown_buf *
hbuf_new(size_t unit)
{
	struct lowdown_buf	*ret;

	if ((ret = malloc(sizeof(struct lowdown_buf))) == NULL)
		return NULL;
	hbuf_init(ret, unit, 1);
	return ret;
}

struct lowdown_buf *
lowdown_buf_new(size_t unit)
{

	return hbuf_new(unit);
}

void
hbuf_free(struct lowdown_buf *buf)
{

	if (buf == NULL) 
		return;
	free(buf->data);
	if (buf->buffer_free)
		free(buf);
}

void
lowdown_buf_free(struct lowdown_buf *buf)
{

	hbuf_free(buf);
}

int
hbuf_grow(struct lowdown_buf *buf, size_t neosz)
{
	size_t	 neoasz;
	void	*pp;

	if (buf->maxsize >= neosz)
		return 1;

	neoasz = (neosz/buf->unit + (neosz%buf->unit > 0)) * buf->unit;

	if ((pp = realloc(buf->data, neoasz)) == NULL)
		return 0;
	buf->data = pp;
	buf->maxsize = neoasz;
	return 1;
}

int
hbuf_putb(struct lowdown_buf *buf, const struct lowdown_buf *b)
{

	assert(buf != NULL && b != NULL);
	return hbuf_put(buf, b->data, b->size);
}

int
hbuf_put(struct lowdown_buf *buf, const char *data, size_t size)
{
	assert(buf != NULL && buf->unit);

	if (data == NULL || size == 0)
		return 1;

	if (buf->size + size > buf->maxsize &&
	    !hbuf_grow(buf, buf->size + size))
		return 0;

	memcpy(buf->data + buf->size, data, size);
	buf->size += size;
	return 1;
}

int
hbuf_puts(struct lowdown_buf *buf, const char *str)
{

	assert(buf != NULL && str != NULL);
	return hbuf_put(buf, str, strlen(str));
}

int
hbuf_putc(struct lowdown_buf *buf, char c)
{
	assert(buf && buf->unit);

	if (buf->size >= buf->maxsize &&
	    !hbuf_grow(buf, buf->size + 1))
		return 0;

	buf->data[buf->size] = c;
	buf->size += 1;
	return 1;
}

int
hbuf_putf(struct lowdown_buf *buf, FILE *file)
{

	assert(buf != NULL && buf->unit);
	while (!(feof(file) || ferror(file))) {
		if (!hbuf_grow(buf, buf->size + buf->unit))
			return 0;
		buf->size += fread(buf->data + buf->size, 
			1, buf->unit, file);
	}

	return ferror(file) == 0;
}

int
hbuf_printf(struct lowdown_buf *buf, const char *fmt, ...)
{
	va_list	 ap;
	int	 n;

	assert(buf != NULL && buf->unit);

	if (buf->size >= buf->maxsize &&
	    !hbuf_grow(buf, buf->size + 1))
		return 0;

	va_start(ap, fmt);
	n = vsnprintf(buf->data + buf->size,
		buf->maxsize - buf->size, fmt, ap);
	va_end(ap);

	if (n < 0)
		return 0;

	if ((size_t)n >= buf->maxsize - buf->size) {
		if (!hbuf_grow(buf, buf->size + n + 1))
			return 0;
		va_start(ap, fmt);
		n = vsnprintf(buf->data + buf->size,
			buf->maxsize - buf->size, fmt, ap);
		va_end(ap);
	}

	if (n < 0)
		return 0;

	buf->size += n;
	return 1;
}

/*
 * Link shortener.
 * This only shows the domain name and last path/filename.
 * It uses the following algorithm:
 *   (1) strip schema (if none, print in full)
 *   (2) print domain following
 *   (3) if no path, return
 *   (4) if path, look for final path component
 *   (5) print final path component with /.../ if shortened
 * Return zero on failure (memory), non-zero on success.
 */
int
hbuf_shortlink(struct lowdown_buf *out, const struct lowdown_buf *link)
{
	size_t		 start = 0, sz;
	const char	*cp, *rcp;

	/* 
	 * Skip the leading protocol.
	 * If we don't find a protocol, leave it be.
	 */

	if (link->size > 7 && strncmp(link->data, "http://", 7) == 0)
		start = 7;
	else if (link->size > 8 && strncmp(link->data, "https://", 8) == 0)
		start = 8;
	else if (link->size > 7 && strncmp(link->data, "file://", 7) == 0)
		start = 7;
	else if (link->size > 7 && strncmp(link->data, "mailto:", 7) == 0)
		start = 7;
	else if (link->size > 6 && strncmp(link->data, "ftp://", 6) == 0)
		start = 6;

	if (start == 0)
		return hbuf_putb(out, link);

	sz = link->size;
	if (link->data[link->size - 1] == '/')
		sz--;

	/* 
	 * Look for the end of the domain name. 
	 * If we don't have an end, then print the whole thing.
	 */

	cp = memchr(link->data + start, '/', sz - start);
	if (cp == NULL)
		return hbuf_put(out, link->data + start, sz - start);

	if (!hbuf_put(out, 
	    link->data + start, cp - (link->data + start)))
		return 0;

	/* 
	 * Look for the filename.
	 * If it's the same as the end of the domain, then print the
	 * whole thing.
	 * Otherwise, use a "..." between.
	 */

	rcp = memrchr(link->data + start, '/', sz - start);

	if (rcp == cp)
		return hbuf_put(out, cp, sz - (cp - link->data));

	return HBUF_PUTSL(out, "/...") &&
		hbuf_put(out, rcp, sz - (rcp - link->data));
}

/**
 * Convert the buffer into an identifier.  These are used in various
 * front-ends for linking to a section identifier.  Use pandoc's format
 * for these identifiers: lowercase, no specials except some, and
 * collapsing whitespace into a dash.
 */
struct lowdown_buf *
hbuf_dupname(const struct lowdown_buf *buf)
{
	struct lowdown_buf	*nbuf;
	size_t			 i;
	int			 last_space = 1;
	char			 c;

	if ((nbuf = hbuf_new(32)) == NULL)
		goto err;

	for (i = 0; i < buf->size; i++) {
		if (isalnum((unsigned char)buf->data[i]) ||
		    buf->data[i] == '-' ||
		    buf->data[i] == '.' ||
		    buf->data[i] == '_') {
			c = tolower((unsigned char)buf->data[i]);
			if (!hbuf_putc(nbuf, c))
				goto err;
			last_space = 0;
		} else if (isspace((unsigned char)buf->data[i])) {
			if (!last_space) {
				if (!HBUF_PUTSL(nbuf, "-"))
					goto err;
				last_space = 1;
			}
		}
	}

	if (nbuf->size == 0 && !HBUF_PUTSL(nbuf, "section"))
		goto err;

	return nbuf;
err:
	hbuf_free(nbuf);
	return NULL;
}

/*
 * Format the raw string used for creating header identifiers.  This
 * recursively drops through the header contents extracting text along
 * the way.
 */
int
hbuf_extract_text(struct lowdown_buf *ob, const struct lowdown_node *n)
{
	const struct lowdown_node	*child;

	if (n->type == LOWDOWN_NORMAL_TEXT)
		if (!hbuf_putb(ob, &n->rndr_normal_text.text))
			return 0;
	if (n->type == LOWDOWN_IMAGE)
		if (!hbuf_putb(ob, &n->rndr_image.alt))
			return 0;
	if (n->type == LOWDOWN_LINK_AUTO)
		if (!hbuf_putb(ob, &n->rndr_autolink.link))
			return 0;
	TAILQ_FOREACH(child, &n->children, entries)
		if (!hbuf_extract_text(ob, child))
			return 0;

	return 1;
}

/*
 * Return a unique header identifier for "header".  Return zero on
 * failure (memory), non-zero on success.  The new value is appended to
 * the queue, which must be freed with hentryq_clear at some point.
 */
const struct lowdown_buf *
hbuf_id(const struct lowdown_buf *header, const struct lowdown_node *n,
	struct hentryq *q)
{
	struct lowdown_buf		*buf = NULL, *nbuf = NULL;
	const struct lowdown_node	*child;
	size_t				 count;
	struct hentry			*he = NULL, *entry;

	if (header == NULL) {
		if ((nbuf = hbuf_new(32)) == NULL)
			goto out;
		TAILQ_FOREACH(child, &n->children, entries)
			if (!hbuf_extract_text(nbuf, child))
				goto out;
		if ((buf = hbuf_dupname(nbuf)) == NULL)
			goto out;
		hbuf_free(nbuf);
		nbuf = NULL;
	} else
		if ((buf = hbuf_dupname(header)) == NULL)
			goto out;

	TAILQ_FOREACH(entry, q, entries)
		if (hbuf_eq(entry->buf, buf))
			break;

	if (entry == NULL) {
		he = calloc(1, sizeof(struct hentry));
		if (he == NULL)
			goto out;
		TAILQ_INSERT_TAIL(q, he, entries);
		he->buf = buf;
		return buf;
	}

	if ((nbuf = hbuf_new(32)) == NULL)
		goto out;

	for (count = 1;; count++) {
		hbuf_truncate(nbuf);
		if (!hbuf_putb(nbuf, buf))
			goto out;
		if (!hbuf_printf(nbuf, "-%zu", count))
			goto out;
		TAILQ_FOREACH(entry, q, entries)
			if (hbuf_eq(entry->buf, nbuf))
				break;
		if (entry == NULL) {
			he = calloc(1, sizeof(struct hentry));
			if (he == NULL)
				goto out;
			TAILQ_INSERT_TAIL(q, he, entries);
			he->buf = nbuf;
			hbuf_free(buf);
			return nbuf;
		}
	}
out:
	hbuf_free(buf);
	hbuf_free(nbuf);
	free(he);
	return NULL;
}

void
hentryq_clear(struct hentryq *q)
{
	struct hentry	*he;

	if (q == NULL)
		return;

	while ((he = TAILQ_FIRST(q)) != NULL) {
		TAILQ_REMOVE(q, he, entries);
		hbuf_free(he->buf);
		free(he);
	}
}

