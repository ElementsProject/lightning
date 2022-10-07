/*	$Id$ */
/*
 * Copyright (c) 2020 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

enum entity {
	ENT_COPY,
	ENT_REG,
	ENT_TMARK,
	ENT_SMARK,
	ENT_ELLIP,
	ENT_MDASH,
	ENT_NDASH,
	ENT_LDQUO,
	ENT_RDQUO,
	ENT_LSQUO,
	ENT_RSQUO,
	ENT_FRAC14,
	ENT_FRAC12,
	ENT_FRAC34,
	ENT__MAX
};

enum type {
	TYPE_ROOT, /* root (LOWDOWN_ROOT) */
	TYPE_BLOCK, /* block-level */
	TYPE_SPAN, /* span-level */
	TYPE_OPAQUE, /* skip */
	TYPE_TEXT /* text (LOWDOWN_NORMAL_TEXT) */
};

struct sym {
	const char	*key; /* input in markdown */
	enum entity	 ent; /* output entity */
};

struct smarty {
	int	 left_wb; /* left wordbreak */
};

static const char *ents[ENT__MAX] = {
	"&copy;", /* ENT_COPY */
	"&reg;", /* ENT_REG */
	"&trade;", /* ENT_TMARK */
	"&#8480;", /* ENT_SMARK */
	"&hellip;", /* ENT_ELLIP */
	"&mdash;", /* ENT_MDASH */
	"&ndash;", /* ENT_NDASH */
	"&ldquo;", /* ENT_LDQUO */
	"&rdquo;", /* ENT_RDQUO */
	"&lsquo;", /* ENT_LSQUO */
	"&rsquo;", /* ENT_RSQUO */
	"&frac14;", /* ENT_FRAC14 */
	"&frac12;", /* ENT_FRAC12 */
	"&frac34;", /* ENT_FRAC34 */
};

/*
 * Order is important: check the longest subset first.
 * (So basically "---" comes before "--".)
 */
static const struct sym syms[] = {
	{ "(c)",	ENT_COPY },
	{ "(C)",	ENT_COPY },
	{ "(r)",	ENT_REG },
	{ "(R)",	ENT_REG },
	{ "(tm)",	ENT_TMARK },
	{ "(TM)",	ENT_TMARK },
	{ "(sm)",	ENT_SMARK },
	{ "(SM)",	ENT_SMARK },
	{ "...",	ENT_ELLIP },
	{ ". . .",	ENT_ELLIP },
	{ "---",	ENT_MDASH },
	{ "--",		ENT_NDASH },
	{ NULL,		ENT__MAX }
};

/*
 * Symbols that require word-break on both sides.
 * Again, order is important: longest-first.
 */
static const struct sym syms2[] = {
	{ "1/4th",	ENT_FRAC14 },
	{ "1/4",	ENT_FRAC14 },
	{ "3/4ths",	ENT_FRAC34 },
	{ "3/4th",	ENT_FRAC34 },
	{ "3/4",	ENT_FRAC34 },
	{ "1/2",	ENT_FRAC12 },
	{ NULL,		ENT__MAX }
};

static const enum type types[LOWDOWN__MAX] = {
	TYPE_ROOT, /* LOWDOWN_ROOT */
	TYPE_OPAQUE, /* LOWDOWN_BLOCKCODE */
	TYPE_BLOCK, /* LOWDOWN_BLOCKQUOTE */
	TYPE_BLOCK, /* LOWDOWN_DEFINITION */
	TYPE_BLOCK, /* LOWDOWN_DEFINITION_TITLE */
	TYPE_BLOCK, /* LOWDOWN_DEFINITION_DATA */
	TYPE_BLOCK, /* LOWDOWN_HEADER */
	TYPE_BLOCK, /* LOWDOWN_HRULE */
	TYPE_BLOCK, /* LOWDOWN_LIST */
	TYPE_BLOCK, /* LOWDOWN_LISTITEM */
	TYPE_BLOCK, /* LOWDOWN_PARAGRAPH */
	TYPE_BLOCK, /* LOWDOWN_TABLE_BLOCK */
	TYPE_BLOCK, /* LOWDOWN_TABLE_HEADER */
	TYPE_BLOCK, /* LOWDOWN_TABLE_BODY */
	TYPE_BLOCK, /* LOWDOWN_TABLE_ROW */
	TYPE_BLOCK, /* LOWDOWN_TABLE_CELL */
	TYPE_OPAQUE, /* LOWDOWN_BLOCKHTML */
	TYPE_OPAQUE, /* LOWDOWN_LINK_AUTO */
	TYPE_OPAQUE, /* LOWDOWN_CODESPAN */
	TYPE_SPAN, /* LOWDOWN_DOUBLE_EMPHASIS */
	TYPE_SPAN, /* LOWDOWN_EMPHASIS */
	TYPE_SPAN, /* LOWDOWN_HIGHLIGHT */
	TYPE_SPAN, /* LOWDOWN_IMAGE */
	TYPE_SPAN, /* LOWDOWN_LINEBREAK */
	TYPE_SPAN, /* LOWDOWN_LINK */
	TYPE_SPAN, /* LOWDOWN_TRIPLE_EMPHASIS */
	TYPE_SPAN, /* LOWDOWN_STRIKETHROUGH */
	TYPE_SPAN, /* LOWDOWN_SUPERSCRIPT */
	TYPE_BLOCK, /* LOWDOWN_FOOTNOTE */
	TYPE_OPAQUE, /* LOWDOWN_MATH_BLOCK */
	TYPE_OPAQUE, /* LOWDOWN_RAW_HTML */
	TYPE_OPAQUE, /* LOWDOWN_ENTITY */
	TYPE_TEXT, /* LOWDOWN_NORMAL_TEXT */
	TYPE_BLOCK, /* LOWDOWN_DOC_HEADER */
	TYPE_BLOCK, /* LOWDOWN_META */
};

/*
 * Given the sequence in "n" starting at "start" and ending at "end",
 * split "n" around the sequence and replace it with "entity".
 * This behaves properly if the leading or trailing sequence is
 * zero-length.
 * It may modify the subtree rooted at the parent of "n".
 * Return zero on failure (memory), non-zero on success.
 */
static int
smarty_entity(struct lowdown_node *n, size_t *maxn,
	size_t start, size_t end, enum entity entity)
{
	struct lowdown_node	*nn, *nent;

	assert(n->type == LOWDOWN_NORMAL_TEXT);

	/* Allocate the subsequent entity. */

	nent = calloc(1, sizeof(struct lowdown_node));
	if (nent == NULL)
		return 0;
	TAILQ_INSERT_AFTER(&n->parent->children, n, nent, entries);

	nent->id = (*maxn)++;
	nent->type = LOWDOWN_ENTITY;
	nent->parent = n->parent;
	TAILQ_INIT(&nent->children);
	nent->rndr_entity.text.data = strdup(ents[entity]);
	if (nent->rndr_entity.text.data == NULL)
		return 0;
	nent->rndr_entity.text.size = strlen(ents[entity]);

	/* Allocate the remaining bits, if applicable. */

	if (n->rndr_normal_text.text.size - end > 0) {
		nn = calloc(1, sizeof(struct lowdown_node));
		if (nn == NULL)
			return 0;
		TAILQ_INSERT_AFTER(&n->parent->children, 
			nent, nn, entries);

		nn->id = (*maxn)++;
		nn->type = LOWDOWN_NORMAL_TEXT;
		nn->parent = n->parent;
		TAILQ_INIT(&nn->children);
		nn->rndr_normal_text.text.size = 
			n->rndr_normal_text.text.size - end;
		nn->rndr_normal_text.text.data = 
			malloc(nn->rndr_normal_text.text.size);
		if (nn->rndr_normal_text.text.data == NULL)
			return 0;
		memcpy(nn->rndr_normal_text.text.data,
			n->rndr_normal_text.text.data + end,
			nn->rndr_normal_text.text.size);
	}

	n->rndr_normal_text.text.size = start;
	return 1;
}

/*
 * Whether the character to the left of a word constitutes a word break
 * on its left side.
 * This is any space or opening punctuation.
 */
static int
smarty_is_wb_l(char c)
{

	return isspace((unsigned char)c) || 
		'(' == c || '[' == c;
}

/*
 * Whether the character to the right of a word constitutes a word
 * break.
 * This is any space or punctuation.
 */
static int
smarty_is_wb_r(char c)
{

	return isspace((unsigned char)c) ||
		ispunct((unsigned char)c);
}

/*
 * Recursive scan for next white-space.
 * If "skip" is set, we're on the starting node and shouldn't do a check
 * for white-space in ourselves.
 */
static int
smarty_right_wb_r(const struct lowdown_node *n, int skip)
{
	const struct lowdown_buf	*b;
	const struct lowdown_node	*nn;

	/* Check type of node. */

	if (types[n->type] == TYPE_BLOCK)
		return 1;
	if (types[n->type] == TYPE_OPAQUE)
		return 0;

	if (!skip &&
	    types[n->type] == TYPE_TEXT &&
	    n->rndr_normal_text.text.size) {
		assert(n->type == LOWDOWN_NORMAL_TEXT);
		b = &n->rndr_normal_text.text;
		return smarty_is_wb_r(b->data[0]);
	}

	/* First scan down. */

	if ((nn = TAILQ_FIRST(&n->children)) != NULL)
		return smarty_right_wb_r(nn, 0);

	/* Now scan back up. */

	do {
		/* FIXME: don't go up to block. */
		if ((nn = TAILQ_NEXT(n, entries)) != NULL)
			return smarty_right_wb_r(nn, 0);
	} while ((n = n->parent) != NULL);

	return 1;
}

/*
 * See if the character to the right of position "pos" in node "n" marks
 * the end of a word.
 * This may require us to traverse the node graph if we're on a node
 * boundary as well.
 */
static int
smarty_right_wb(const struct lowdown_node *n, size_t pos)
{
	const struct lowdown_buf	*b;

	assert(n->type == LOWDOWN_NORMAL_TEXT);
	b = &n->rndr_normal_text.text;

	if (pos + 1 <= b->size)
		return smarty_is_wb_r(b->data[pos]);

	return smarty_right_wb_r(n, 1);
}

/*
 * FIXME: this can be faster with a table-based lookup instead of the
 * switch statement.
 * Returns >1 if a left-quote entity was inserted as the next node
 * of the parse tree, <0 on failure, otherwise return zero.
 */
static int
smarty_hbuf(struct lowdown_node *n, size_t *maxn,
	struct lowdown_buf *b, struct smarty *s)
{
	size_t	 i = 0, j, sz;

	assert(n->type == LOWDOWN_NORMAL_TEXT);

	for (i = 0; i < b->size; i++) {
		switch (b->data[i]) {
		case '.':
		case '(':
		case '-':
			/* Symbols that don't need wordbreak. */

			for (j = 0; syms[j].key != NULL; j++) {
				sz = strlen(syms[j].key);
				if (i + sz - 1 >= b->size)
					continue;
				if (memcmp(syms[j].key, 
				    &b->data[i], sz))
					continue;
				if (!smarty_entity(n, maxn, 
				    i, i + sz, syms[j].ent))
					return -1;
				return 0;
			}
			break;
		case '"':
			/* Left-wb and right-wb differ. */

			if (!s->left_wb) {
				if (!smarty_right_wb(n, i + 1)) 
					break;
				if (!smarty_entity(n, maxn, 
				    i, i + 1, ENT_RDQUO))
					return -1;
				return 0;
			}
			if (!smarty_entity
			    (n, maxn, i, i + 1, ENT_LDQUO))
				return -1;
			return 1;
		case '\'':
			/* Left-wb and right-wb differ. */

			if (!s->left_wb) {
				if (!smarty_entity(n, maxn, 
				    i, i + 1, ENT_RSQUO))
					return -1;
				return 0;
			}
			if (!smarty_entity
			    (n, maxn, i, i + 1, ENT_LSQUO))
				return -1;
			return 1;
		case '1':
		case '3':
			/* Symbols that require wb. */

			if (!s->left_wb)
				break;
			for (j = 0; syms2[j].key != NULL; j++) {
				sz = strlen(syms2[j].key);
				if (i + sz - 1 >= b->size)
					continue;
				if (memcmp(syms2[j].key, 
				    &b->data[i], sz))
					continue;
				if (!smarty_right_wb(n, i + sz)) 
					continue;
				if (!smarty_entity(n, maxn, i, 
				    i + sz, syms2[j].ent))
					return -1;
				return 0;
			}
			break;
		default:
			break;
		}

		s->left_wb = smarty_is_wb_l(b->data[i]);
	}

	return 0;
}

static int
smarty_block(struct lowdown_node *, size_t *, enum lowdown_type);

static int
smarty_span(struct lowdown_node *root, size_t *maxn,
	struct smarty *s, enum lowdown_type type)
{
	struct lowdown_node	*n;
	int			 c;

	TAILQ_FOREACH(n, &root->children, entries)
		switch (types[n->type]) {
		case TYPE_TEXT:
			assert(n->type == LOWDOWN_NORMAL_TEXT);
			c = smarty_hbuf(n, maxn, 
				&n->rndr_normal_text.text, s);
			if (c < 0)
				return 0;
			if (c > 0)
				n = TAILQ_NEXT(n, entries);
			break;
		case TYPE_SPAN:
			if (!smarty_span(n, maxn, s, type))
				return 0;
			break;
		case TYPE_OPAQUE:
			s->left_wb = 0;
			break;
		case TYPE_BLOCK:
			if (!smarty_block(n, maxn, type))
				return 0;
			break;
		case TYPE_ROOT:
			abort();
		}

	return 1;
}

static int
smarty_block(struct lowdown_node *root,
	size_t *maxn, enum lowdown_type type)
{
	struct smarty		 s;
	struct lowdown_node	*n;
	int			 c;

	s.left_wb = 1;

	TAILQ_FOREACH(n, &root->children, entries)
		switch (types[n->type]) {
		case TYPE_ROOT:
		case TYPE_BLOCK:
			if (!smarty_block(n, maxn, type))
				return 0;
			break;
		case TYPE_TEXT:
			assert(n->type == LOWDOWN_NORMAL_TEXT);
			c = smarty_hbuf(n, maxn, 
				&n->rndr_normal_text.text, &s);
			if (c < 0)
				return 0;
			if (c > 0)
				n = TAILQ_NEXT(n, entries);
			break;
		case TYPE_SPAN:
			if (!smarty_span(n, maxn, &s, type))
				return 0;
			break;
		case TYPE_OPAQUE:
			s.left_wb = 0;
			break;
		default:
			break;
		}

	s.left_wb = 1;
	return 1;
}

int
smarty(struct lowdown_node *n, size_t maxn, enum lowdown_type type)
{

	if (n == NULL)
		return 1;
	assert(types[n->type] == TYPE_ROOT);
	return smarty_block(n, &maxn, type);
}
