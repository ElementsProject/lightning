/*	$Id$ */
/*
 * Copyright (c) 2017--2021 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

/*
 * Starting size for input and output buffers.
 */
#define HBUF_START_BIG 4096

/*
 * Starting size for metadata buffers.
 */
#define HBUF_START_SMALL 128

/*
 * Return FALSE on failure, TRUE on success.
 */
static int
lowdown_render(const struct lowdown_opts *opts,
	struct lowdown_buf *ob, const struct lowdown_node *n)
{
	void	*rndr;
	int	 c = 0;

	switch (opts == NULL ? LOWDOWN_HTML : opts->type) {
	case LOWDOWN_GEMINI:
		if ((rndr = lowdown_gemini_new(opts)) == NULL)
			return 0;
		c = lowdown_gemini_rndr(ob, rndr, n);
		lowdown_gemini_free(rndr);
		break;
	case LOWDOWN_HTML:
		if ((rndr = lowdown_html_new(opts)) == NULL)
			return 0;
		c = lowdown_html_rndr(ob, rndr, n);
		lowdown_html_free(rndr);
		break;
	case LOWDOWN_LATEX:
		if ((rndr = lowdown_latex_new(opts)) == NULL)
			return 0;
		c = lowdown_latex_rndr(ob, rndr, n);
		lowdown_latex_free(rndr);
		break;
	case LOWDOWN_MAN:
	case LOWDOWN_NROFF:
		if ((rndr = lowdown_nroff_new(opts)) == NULL)
			return 0;
		c = lowdown_nroff_rndr(ob, rndr, n);
		lowdown_nroff_free(rndr);
		break;
	case LOWDOWN_FODT:
		if ((rndr = lowdown_odt_new(opts)) == NULL)
			return 0;
		c = lowdown_odt_rndr(ob, rndr, n);
		lowdown_odt_free(rndr);
		break;
	case LOWDOWN_TERM:
		if ((rndr = lowdown_term_new(opts)) == NULL)
			return 0;
		c = lowdown_term_rndr(ob, rndr, n);
		lowdown_term_free(rndr);
		break;
	case LOWDOWN_TREE:
		c = lowdown_tree_rndr(ob, n);
		break;
	default:
		c = 1;
		break;
	}

	return c;
}

int
lowdown_buf(const struct lowdown_opts *opts,
	const char *data, size_t datasz,
	char **res, size_t *rsz,
	struct lowdown_metaq *metaq)
{
	struct lowdown_buf	*ob = NULL;
	struct lowdown_doc	*doc;
	size_t			 maxn;
	enum lowdown_type	 t;
	struct lowdown_node	*n = NULL;
	int			 rc = 0;

	t = opts == NULL ? LOWDOWN_HTML : opts->type;

	if ((doc = lowdown_doc_new(opts)) == NULL)
		goto err;

	n = lowdown_doc_parse(doc, &maxn, data, datasz, metaq);
	if (n == NULL)
		goto err;
	assert(n->type == LOWDOWN_ROOT);

    	if (opts != NULL && (opts->oflags & LOWDOWN_SMARTY)) 
		if (!smarty(n, maxn, t))
			goto err;

	if ((ob = lowdown_buf_new(HBUF_START_BIG)) == NULL)
		goto err;

	if (!lowdown_render(opts, ob, n))
		goto err;

	*res = ob->data;
	*rsz = ob->size;
	ob->data = NULL;
	rc = 1;
err:
	lowdown_buf_free(ob);
	lowdown_node_free(n);
	lowdown_doc_free(doc);
	return rc;
}

int
lowdown_buf_diff(const struct lowdown_opts *opts,
	const char *new, size_t newsz,
	const char *old, size_t oldsz,
	char **res, size_t *rsz)
{
	struct lowdown_buf 	*ob = NULL;
	struct lowdown_doc 	*doc = NULL;
	enum lowdown_type 	 t;
	struct lowdown_node 	*nnew = NULL, *nold = NULL, 
				*ndiff = NULL;
	size_t			 maxn;
	int			 rc = 0;

	t = opts == NULL ? LOWDOWN_HTML : opts->type;

	if ((doc = lowdown_doc_new(opts)) == NULL)
		goto err;

	nnew = lowdown_doc_parse(doc, NULL, new, newsz, NULL);
	if (nnew == NULL)
		goto err;
	nold = lowdown_doc_parse(doc, NULL, old, oldsz, NULL);
	if (nold == NULL)
		goto err;

	ndiff = lowdown_diff(nold, nnew, &maxn);

    	if (opts != NULL && (opts->oflags & LOWDOWN_SMARTY)) 
		if (!smarty(ndiff, maxn, t))
			goto err;

	if ((ob = lowdown_buf_new(HBUF_START_BIG)) == NULL)
		goto err;

	if (!lowdown_render(opts, ob, ndiff))
		goto err;

	*res = ob->data;
	*rsz = ob->size;
	ob->data = NULL;
	rc = 1;
err:
	lowdown_buf_free(ob);
	lowdown_node_free(ndiff);
	lowdown_node_free(nnew);
	lowdown_node_free(nold);
	lowdown_doc_free(doc);
	return rc;
}

int
lowdown_file(const struct lowdown_opts *opts, FILE *fin,
	char **res, size_t *rsz, struct lowdown_metaq *metaq)
{
	struct lowdown_buf	*bin = NULL;
	int	 		 rc = 0;

	if ((bin = lowdown_buf_new(HBUF_START_BIG)) == NULL)
		goto out;
	if (!hbuf_putf(bin, fin))
		goto out;

	if (!lowdown_buf(opts,
	    bin->data, bin->size, res, rsz, metaq))
		goto out;
	rc = 1;
out:
	lowdown_buf_free(bin);
	return rc;
}

int
lowdown_file_diff(const struct lowdown_opts *opts,
	FILE *fnew, FILE *fold, char **res, size_t *rsz)
{
	struct lowdown_buf	*bnew = NULL, *bold = NULL;
	int	 		 rc = 0;

	if ((bnew = lowdown_buf_new(HBUF_START_BIG)) == NULL)
		goto out;
	if ((bold = lowdown_buf_new(HBUF_START_BIG)) == NULL)
		goto out;
	if (!hbuf_putf(bold, fold))
		goto out;
	if (!hbuf_putf(bnew, fnew))
		goto out;

	if (!lowdown_buf_diff(opts, 
	    bnew->data, bnew->size, 
	    bold->data, bold->size, 
	    res, rsz))
		goto out;
	rc = 1;
out:
	lowdown_buf_free(bnew);
	lowdown_buf_free(bold);
	return rc;
}

