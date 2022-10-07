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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

static	const char *const names[LOWDOWN__MAX] = {
	"LOWDOWN_ROOT",			/* LOWDOWN_ROOT */
	"LOWDOWN_BLOCKCODE",            /* LOWDOWN_BLOCKCODE */
	"LOWDOWN_BLOCKQUOTE",           /* LOWDOWN_BLOCKQUOTE */
	"LOWDOWN_DEFINITION",		/* LOWDOWN_DEFINITION */
	"LOWDOWN_DEFINITION_TITLE",	/* LOWDOWN_DEFINITION_TITLE */
	"LOWDOWN_DEFINITION_DATA",	/* LOWDOWN_DEFINITION_DATA */
	"LOWDOWN_HEADER",               /* LOWDOWN_HEADER */
	"LOWDOWN_HRULE",                /* LOWDOWN_HRULE */
	"LOWDOWN_LIST",                 /* LOWDOWN_LIST */
	"LOWDOWN_LISTITEM",             /* LOWDOWN_LISTITEM */
	"LOWDOWN_PARAGRAPH",            /* LOWDOWN_PARAGRAPH */
	"LOWDOWN_TABLE_BLOCK",          /* LOWDOWN_TABLE_BLOCK */
	"LOWDOWN_TABLE_HEADER",         /* LOWDOWN_TABLE_HEADER */
	"LOWDOWN_TABLE_BODY",           /* LOWDOWN_TABLE_BODY */
	"LOWDOWN_TABLE_ROW",            /* LOWDOWN_TABLE_ROW */
	"LOWDOWN_TABLE_CELL",           /* LOWDOWN_TABLE_CELL */
	"LOWDOWN_BLOCKHTML",            /* LOWDOWN_BLOCKHTML */
	"LOWDOWN_LINK_AUTO",            /* LOWDOWN_LINK_AUTO */
	"LOWDOWN_CODESPAN",             /* LOWDOWN_CODESPAN */
	"LOWDOWN_DOUBLE_EMPHASIS",      /* LOWDOWN_DOUBLE_EMPHASIS */
	"LOWDOWN_EMPHASIS",             /* LOWDOWN_EMPHASIS */
	"LOWDOWN_HIGHLIGHT",            /* LOWDOWN_HIGHLIGHT */
	"LOWDOWN_IMAGE",                /* LOWDOWN_IMAGE */
	"LOWDOWN_LINEBREAK",            /* LOWDOWN_LINEBREAK */
	"LOWDOWN_LINK",                 /* LOWDOWN_LINK */
	"LOWDOWN_TRIPLE_EMPHASIS",      /* LOWDOWN_TRIPLE_EMPHASIS */
	"LOWDOWN_STRIKETHROUGH",        /* LOWDOWN_STRIKETHROUGH */
	"LOWDOWN_SUPERSCRIPT",          /* LOWDOWN_SUPERSCRIPT */
	"LOWDOWN_FOOTNOTE",		/* LOWDOWN_FOOTNOTE */
	"LOWDOWN_MATH_BLOCK",           /* LOWDOWN_MATH_BLOCK */
	"LOWDOWN_RAW_HTML",             /* LOWDOWN_RAW_HTML */
	"LOWDOWN_ENTITY",               /* LOWDOWN_ENTITY */
	"LOWDOWN_NORMAL_TEXT",          /* LOWDOWN_NORMAL_TEXT */
	"LOWDOWN_DOC_HEADER",           /* LOWDOWN_DOC_HEADER */
	"LOWDOWN_META",			/* LOWDOWN_META */
};

static int
rndr_indent(struct lowdown_buf *ob, size_t indent)
{
	size_t	 i;

	for (i = 0; i < indent; i++)
		if (!HBUF_PUTSL(ob, "  "))
			return 0;
	return 1;
}

static int
rndr_short(struct lowdown_buf *ob, const struct lowdown_buf *b)
{
	size_t	 i;

	for (i = 0; i < 20 && i < b->size; i++)
		if (b->data[i] == '\n') {
			if (!HBUF_PUTSL(ob, "\\n"))
				return 0;
		} else if (b->data[i] == '\t') {
			if (!HBUF_PUTSL(ob, "\\t"))
				return 0;
		} else if (iscntrl((unsigned char)b->data[i])) {
			if (!hbuf_putc(ob, '?'))
				return 0;
		} else {
			if (!hbuf_putc(ob, b->data[i]))
				return 0;
		}

	if (i < b->size && !HBUF_PUTSL(ob, "..."))
		return 0;
	return 1;
}

static int
rndr(struct lowdown_buf *ob,
	const struct lowdown_node *root, size_t indent)
{
	const struct lowdown_node	*n;
	struct lowdown_buf		*tmp;

	if (!rndr_indent(ob, indent))
		return 0;
	if (root->chng == LOWDOWN_CHNG_INSERT && 
	    !HBUF_PUTSL(ob, "INSERT: "))
		return 0;
	if (root->chng == LOWDOWN_CHNG_DELETE && 
	    !HBUF_PUTSL(ob, "DELETE: "))
		return 0;
	if (!hbuf_printf(ob, "%s (%zu)", names[root->type], root->id))
		return 0;
	if (!hbuf_putc(ob, '\n'))
		return 0;

	switch (root->type) {
	case LOWDOWN_PARAGRAPH:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "lines: %zu, blank-after: %d\n", 
		    root->rndr_paragraph.lines,
		    root->rndr_paragraph.beoln))
			return 0;
		break;
	case LOWDOWN_IMAGE:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "source: "))
			return 0;
		if (!rndr_short(ob, &root->rndr_image.link))
			return 0;
		if (root->rndr_image.dims.size) {
			if (!HBUF_PUTSL(ob, "("))
				return 0;
			if (!rndr_short(ob, &root->rndr_image.dims))
				return 0;
			if (!HBUF_PUTSL(ob, ")"))
				return 0;
		}
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		if (root->rndr_image.title.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!hbuf_printf(ob, "title: "))
				return 0;
			if (!rndr_short(ob, &root->rndr_image.title))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_image.alt.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!hbuf_printf(ob, "alt: "))
				return 0;
			if (!rndr_short(ob, &root->rndr_image.alt))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_image.dims.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!hbuf_printf(ob, "dims: "))
				return 0;
			if (!rndr_short(ob, &root->rndr_image.dims))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_image.attr_width.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!hbuf_printf(ob, "width (extended): "))
				return 0;
			if (!rndr_short(ob, &root->rndr_image.attr_width))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_image.attr_height.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!hbuf_printf(ob, "height (extended): "))
				return 0;
			if (!rndr_short(ob, &root->rndr_image.attr_height))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_image.attr_cls.size > 0) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "class: "))
				return 0;
			if (!hbuf_putb(ob, &root->rndr_image.attr_cls))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_image.attr_id.size > 0) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "id: "))
				return 0;
			if (!hbuf_putb(ob, &root->rndr_image.attr_id))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		break;
	case LOWDOWN_HEADER:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "level: %zu\n",
		    root->rndr_header.level))
			return 0;
		if (root->rndr_header.attr_cls.size > 0) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "class: "))
				return 0;
			if (!hbuf_putb(ob, &root->rndr_header.attr_cls))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_header.attr_id.size > 0) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "id: "))
				return 0;
			if (!hbuf_putb(ob, &root->rndr_header.attr_id))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		break;
	case LOWDOWN_RAW_HTML:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "data: %zu Bytes: ",
		    root->rndr_raw_html.text.size))
			return 0;
		if (!rndr_short(ob, &root->rndr_raw_html.text))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	case LOWDOWN_BLOCKHTML:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "data: %zu Bytes: ",
		    root->rndr_blockhtml.text.size))
			return 0;
		if (!rndr_short(ob, &root->rndr_blockhtml.text))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	case LOWDOWN_BLOCKCODE:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "data: %zu Bytes: ",
		    root->rndr_blockcode.text.size))
			return 0;
		if (!rndr_short(ob, &root->rndr_blockcode.text))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	case LOWDOWN_DEFINITION:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "scope: %s\n",
		    HLIST_FL_BLOCK & root->rndr_definition.flags ? 
		    "block" : "span"))
			return 0;
		break;
	case LOWDOWN_TABLE_BLOCK:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "columns: %zu\n", 
		    root->rndr_table.columns))
			return 0;
		break;
	case LOWDOWN_TABLE_CELL:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "current: %zu\n", 
		    root->rndr_table_cell.col))
			return 0;
		break;
	case LOWDOWN_LISTITEM:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "scope: %s\n",
		    (root->rndr_listitem.flags & HLIST_FL_BLOCK) ?
		    "block" : "span"))
			return 0;
		if (!(root->rndr_listitem.flags &
		     (HLIST_FL_CHECKED | HLIST_FL_UNCHECKED)))
			break;
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "check status: %s\n",
		    (root->rndr_listitem.flags & HLIST_FL_CHECKED) ?
		    "checked" : "unchecked"))
			return 0;
		break;
	case LOWDOWN_LIST:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "list type: %s\n",
		    HLIST_FL_ORDERED & root->rndr_list.flags ? 
		    "ordered" : "unordered"))
			return 0;
		break;
	case LOWDOWN_META:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "key: "))
			return 0;
		if (!rndr_short(ob, &root->rndr_meta.key))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	case LOWDOWN_MATH_BLOCK:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "blockmode: %s\n",
		    root->rndr_math.blockmode ?
		    "block" : "inline"))
			return 0;
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "data: %zu Bytes: ",
		    root->rndr_math.text.size))
			return 0;
		if (!rndr_short(ob, &root->rndr_math.text))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	case LOWDOWN_ENTITY:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "value: "))
			return 0;
		if (!rndr_short(ob, &root->rndr_entity.text))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	case LOWDOWN_LINK_AUTO:
		if (root->rndr_autolink.link.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "link: "))
				return 0;
			if (!rndr_short(ob, &root->rndr_autolink.link))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		break;
	case LOWDOWN_LINK:
		if (root->rndr_link.title.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "title: "))
				return 0;
			if (!rndr_short(ob, &root->rndr_link.title))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_link.link.size) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "link: "))
				return 0;
			if (!rndr_short(ob, &root->rndr_link.link))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_link.attr_cls.size > 0) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "class: "))
				return 0;
			if (!hbuf_putb(ob, &root->rndr_link.attr_cls))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		if (root->rndr_link.attr_id.size > 0) {
			if (!rndr_indent(ob, indent + 1))
				return 0;
			if (!HBUF_PUTSL(ob, "id: "))
				return 0;
			if (!hbuf_putb(ob, &root->rndr_link.attr_id))
				return 0;
			if (!HBUF_PUTSL(ob, "\n"))
				return 0;
		}
		break;
	case LOWDOWN_NORMAL_TEXT:
		if (!rndr_indent(ob, indent + 1))
			return 0;
		if (!hbuf_printf(ob, "data: %zu Bytes: ",
		    root->rndr_normal_text.text.size))
			return 0;
		if (!rndr_short(ob, &root->rndr_normal_text.text))
			return 0;
		if (!HBUF_PUTSL(ob, "\n"))
			return 0;
		break;
	default:
		break;
	}

	if ((tmp = hbuf_new(64)) == NULL)
		return 0;

	TAILQ_FOREACH(n, &root->children, entries)
		if (!rndr(tmp, n, indent + 1)) {
			hbuf_free(tmp);
			return 0;
		}

	hbuf_putb(ob, tmp);
	hbuf_free(tmp);
	return 1;
}

int
lowdown_tree_rndr(struct lowdown_buf *ob,
	const struct lowdown_node *root)
{

	return rndr(ob, root, 0);
}

