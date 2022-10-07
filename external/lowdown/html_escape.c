/*	$Id$ */
/*
 * Copyright (c) 2008, Natacha Porté
 * Copyright (c) 2011, Vicent Martí
 * Copyright (c) 2014, Xavier Mendez, Devin Torres and the Hoedown authors
 * Copyright (c) 2016--2017, 2020 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

/*
 * The following characters will not be escaped:
 *
 *    -_.+!*'(),%#@?=;:/,+&$~ alphanum
 *
 * Note that this character set is the addition of:
 *
 * - The characters which are safe to be in an URL
 * - The characters which are *not* safe to be in an URL because they
 *   are RESERVED characters.
 *
 * We assume (lazily) that any RESERVED char that appears inside an URL
 * is actually meant to have its native function (i.e. as an URL
 * component/separator) and hence needs no escaping.
 *
 * There are two exceptions: the chacters & (amp) and ' (single quote)
 * do not appear in the table.  They are meant to appear in the URL as
 * components, yet they require special HTML-entity escaping to generate
 * valid HTML markup.
 *
 * All other characters will be escaped to %XX.
 */
static const int href_tbl[UINT8_MAX + 1] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * For each 8-bit character, if non-zero, the HTML entity we need to
 * substitute for safe output.  According to the OWASP rules:
 *   & --> &amp;
 *   < --> &lt;
 *   > --> &gt;      optional
 *   " --> &quot;    optional
 *   ' --> &#x27;    optional: &apos; is not recommended
 *   / --> &#x2F;    optional: end an HTML entity
 */
static const int esc_tbl[UINT8_MAX + 1] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 6, 2, 0, 0, 0, 0, 0, 0, 0, 3,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * Maximum value of optional entity subsititute.
 * Above this (>ESC_TBL_OWASP_MAX) is mandatory.
 */
#define	ESC_TBL_OWASP_MAX 3

/*
 * For literal contexts, maximum value of optional entity subsititute.
 * Above this is mandatory.
 */
#define	ESC_TBL_LITERAL_MAX 3

/*
 * Named entities (mostly).
 */
static const char *esc_name[] = {
        "",
        "", /* oops */
        "&#39;",
        "&#47;",
        "&gt;",
        "&lt;",
        "&amp;",
};

/*
 * Numeric entities.
 */
static const char *esc_num[] = {
        "",
        "", /* oops */
        "&#39;",
        "&#47;",
        "&#62;",
        "&#60;",
        "&#38;",
};

/* 
 * Escape general HTML attributes.
 * This is modelled after the main Markdown parser.
 */
int
hesc_attr(struct lowdown_buf *ob, const char *data, size_t size)
{
	size_t	 	 i, mark;
	int		 rc;

	if (size == 0)
		return 1;

	for (i = 0; i < size; i++) {
		mark = i;
		while (i < size && data[i] != '"' && data[i] != '&') 
			i++;

		if (mark == 0 && i >= size)
			return hbuf_put(ob, data, size);

		if (i > mark &&
		    !hbuf_put(ob, data + mark, i - mark))
			return 0;

		if (i >= size)
			break;

		rc = 1;
		if (data[i] == '"')
			rc = HBUF_PUTSL(ob, "&quot;");
		else if (data[i] == '&')
			rc = HBUF_PUTSL(ob, "&amp;");
		if (!rc)
			return 0;
	}

	return 1;
}

/* 
 * Escape (part of) a URL inside HTML.
 * Return zero on failure (memory), non-zero otherwise.
 */
int
hesc_href(struct lowdown_buf *ob, const char *data, size_t size)
{
	static const char 	hex_chars[] = "0123456789ABCDEF";
	size_t  		i, mark;
	char 		 	hex_str[3];
	int			rc;

	if (size == 0)
		return 1;

	hex_str[0] = '%';

	for (i = 0; i < size; i++) {
		mark = i;
		while (i < size && href_tbl[(unsigned char)data[i]])
			i++;

		/* 
		 * Optimization for cases where there's nothing to
		 * escape.
		*/

		if (mark == 0 && i >= size)
			return hbuf_put(ob, data, size);

		if (i > mark &&
		    !hbuf_put(ob, data + mark, i - mark))
			return 0;

		/* Escaping... */

		if (i >= size)
			break;

		switch (data[i]) {
		case '&':
			/* 
			 * Amp appears all the time in URLs, but needs
			 * HTML-entity escaping to be inside an href.
			*/
			rc = HBUF_PUTSL(ob, "&amp;");
			break;
		case '\'':
			/* 
			 * The single quote is a valid URL character
			 * according to the standard; it needs HTML
			 * entity escaping too.
			*/
			rc = HBUF_PUTSL(ob, "&#x27;");
			break;
		default:
			/* 
			 * Every other character goes with a %XX
			 * escaping.
			*/
			hex_str[1] = hex_chars[(data[i] >> 4) & 0xF];
			hex_str[2] = hex_chars[data[i] & 0xF];
			rc = hbuf_put(ob, hex_str, 3);
			break;
		}
		if (!rc)
			return 0;
	}

	return 1;
}

/* 
 * Escape HTML.
 * If "literal", we also want to escape some extra characters.
 * If "secure", also escape characters as suggested by OWASP rules.
 * If "num", use only numeric escapes.
 * Does nothing if "size" is zero.
 * Return zero on failure (memory), non-zero otherwise.
 */
int
hesc_html(struct lowdown_buf *ob, const char *data,
	size_t size, int secure, int literal, int num)
{
	size_t 		i, mark;
	int		max = 0, rc;
	unsigned char	ch;

	if (size == 0)
		return 1;

	if (!literal && !secure)
		max = ESC_TBL_OWASP_MAX;
	else if (literal && !secure)
		max = ESC_TBL_LITERAL_MAX;

	for (i = 0; ; i++) {
		mark = i;
		while (i < size && 
		       esc_tbl[(unsigned char)data[i]] == 0) 
			i++;

		/* Case where there's nothing to escape. */

		if (mark == 0 && i >= size)
			return hbuf_put(ob, data, size);

		if (i > mark &&
		    !hbuf_put(ob, data + mark, i - mark))
			return 0;

		if (i >= size) 
			break;

		ch = (unsigned char)data[i];

		if (esc_tbl[ch] <= max)
			rc = hbuf_putc(ob, data[i]);
		else
			rc = hbuf_puts(ob, num ?
				esc_num[esc_tbl[ch]] :
				esc_name[esc_tbl[ch]]);
		if (!rc)
			return 0;
	}

	return 1;
}
