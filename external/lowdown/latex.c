/*	$Id$ */
/*
 * Copyright (c) 2020--2021 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lowdown.h"
#include "extern.h"

struct latex {
	unsigned int	oflags; /* same as in lowdown_opts */
	struct hentryq	headers_used; /* headers we've seen */
	ssize_t		headers_offs; /* header offset */
	size_t		footsz; /* current footnote */
};

/*
 * Return zero on failure, non-zero on success.
 */
static int
rndr_escape_text(struct lowdown_buf *ob, const char *data, size_t sz)
{
	size_t	 i;

	for (i = 0; i < sz; i++)
		switch (data[i]) {
		case '&':
		case '%':
		case '$':
		case '#':
		case '_':
		case '{':
		case '}':
			if (!hbuf_putc(ob, '\\'))
				return 0;
			if (!hbuf_putc(ob, data[i]))
				return 0;
			break;
		case '~':
			if (!HBUF_PUTSL(ob, "\\textasciitilde{}"))
				return 0;
			break;
		case '^':
			if (!HBUF_PUTSL(ob, "\\textasciicircum{}"))
				return 0;
			break;
		case '\\':
			if (!HBUF_PUTSL(ob, "\\textbackslash{}"))
				return 0;
			break;
		default:
			if (!hbuf_putc(ob, data[i]))
				return 0;
			break;
		}

	return 1;
}

/*
 * Return zero on failure, non-zero on success.
 */
static int
rndr_escape(struct lowdown_buf *ob, const struct lowdown_buf *dat)
{
	
	return rndr_escape_text(ob, dat->data, dat->size);
}

static int
rndr_autolink(struct lowdown_buf *ob,
	const struct rndr_autolink *param)
{

	if (param->link.size == 0)
		return 1;
	if (!HBUF_PUTSL(ob, "\\url{"))
		return 0;
	if (param->type == HALINK_EMAIL && !HBUF_PUTSL(ob, "mailto:"))
		return 0;
	if (!rndr_escape(ob, &param->link))
		return 0;
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_entity(struct lowdown_buf *ob,
	const struct rndr_entity *param)
{
	const char	*tex;
	unsigned char	 texflags;

	tex = entity_find_tex(&param->text, &texflags);
	if (tex == NULL)
		return rndr_escape(ob, &param->text);

	if ((texflags & TEX_ENT_MATH) && (texflags & TEX_ENT_ASCII))
		return hbuf_printf(ob, "$\\mathrm{%s}$", tex);
	if (texflags & TEX_ENT_ASCII)
		return hbuf_puts(ob, tex);
	if (texflags & TEX_ENT_MATH)
		return hbuf_printf(ob, "$\\mathrm{\\%s}$", tex);
	return hbuf_printf(ob, "\\%s", tex);
}

static int
rndr_blockcode(struct lowdown_buf *ob,
	const struct rndr_blockcode *param)
{

	if (ob->size && !HBUF_PUTSL(ob, "\n"))
		return 0;

#if 0
	HBUF_PUTSL(ob, "\\begin{lstlisting}");
	if (lang->size) {
		HBUF_PUTSL(ob, "[language=");
		rndr_escape(ob, lang);
		HBUF_PUTSL(ob, "]\n\n");
	} else
		HBUF_PUTSL(ob, "\n");
#else
	HBUF_PUTSL(ob, "\\begin{verbatim}\n");
#endif
	if (!hbuf_putb(ob, &param->text))
		return 0;
#if 0
	HBUF_PUTSL(ob, "\\end{lstlisting}\n");
#else
	return HBUF_PUTSL(ob, "\\end{verbatim}\n");
#endif
}

static int
rndr_definition_title(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\item ["))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "] ");
}

static int
rndr_definition(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\begin{description}\n"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "\\end{description}\n");
}

static int
rndr_blockquote(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (ob->size && !HBUF_PUTSL(ob, "\n"))
		return 0;
	if (!HBUF_PUTSL(ob, "\\begin{quotation}\n"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "\\end{quotation}\n");
}

static int
rndr_codespan(struct lowdown_buf *ob,
	const struct rndr_codespan *param)
{
#if 0
	HBUF_PUTSL(ob, "\\lstinline{");
	hbuf_putb(ob, text);
#else
	if (!HBUF_PUTSL(ob, "\\texttt{"))
		return 0;
	if (!rndr_escape(ob, &param->text))
		return 0;
#endif
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_triple_emphasis(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\textbf{\\emph{"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "}}");
}

static int
rndr_double_emphasis(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\textbf{"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_emphasis(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\emph{"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_highlight(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\underline{"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_linebreak(struct lowdown_buf *ob)
{

	return HBUF_PUTSL(ob, "\\linebreak\n");
}

static int
rndr_header(struct lowdown_buf *ob, const struct lowdown_buf *content,
	const struct lowdown_node *n, struct latex *st)
{
	const char			*type;
	ssize_t				 level;
	struct lowdown_buf		*buf = NULL;
	const struct lowdown_buf	*id;
	int				 rc = 0;

	if (n->rndr_header.attr_id.size) {
		if ((buf = hbuf_new(32)) == NULL)
			goto out;
		if (!rndr_escape(buf, &n->rndr_header.attr_id))
			goto out;
		id = buf;
	} else {
		id = hbuf_id(NULL, n, &st->headers_used);
		if (id == NULL)
			goto out;
	}

	if (ob->size && !HBUF_PUTSL(ob, "\n"))
		goto out;

	if (!HBUF_PUTSL(ob, "\\hypertarget{"))
		goto out;
	if (!hbuf_putb(ob, id))
		goto out;
	if (!HBUF_PUTSL(ob, "}{%\n"))
		goto out;

	level = (ssize_t)n->rndr_header.level + st->headers_offs;
	if (level < 1)
		level = 1;

	switch (level) {
	case 1:
		type = "\\section";
		break;
	case 2:
		type = "\\subsection";
		break;
	case 3:
		type = "\\subsubsection";
		break;
	case 4:
		type = "\\paragraph";
		break;
	default:
		type = "\\subparagraph";
		break;
	}

	if (!hbuf_puts(ob, type))
		goto out;
	if (!(st->oflags & LOWDOWN_LATEX_NUMBERED) &&
  	    !HBUF_PUTSL(ob, "*"))
		goto out;
	if (!HBUF_PUTSL(ob, "{"))
		goto out;
	if (!hbuf_putb(ob, content))
		goto out;
	if (!HBUF_PUTSL(ob, "}\\label{"))
		goto out;
	if (!hbuf_putb(ob, id))
		goto out;
	if (!HBUF_PUTSL(ob, "}}\n"))
		goto out;
	rc = 1;
out:
	hbuf_free(buf);
	return rc;
}

static int
rndr_link(struct lowdown_buf *ob,
	const struct lowdown_buf *content,
	const struct rndr_link *param)
{
	int	loc;

	loc = param->link.size > 0 &&
		param->link.data[0] == '#';

	if (param->attr_id.size > 0) {
		if (!HBUF_PUTSL(ob, "\\hypertarget{"))
			return 0;
		if (!hbuf_putb(ob, &param->attr_id))
			return 0;
		if (!HBUF_PUTSL(ob, "}{%\n"))
			return 0;
	}

	if (loc && !HBUF_PUTSL(ob, "\\hyperlink{"))
		return 0;
	else if (!loc && !HBUF_PUTSL(ob, "\\href{"))
		return 0;

	if (loc && !rndr_escape_text
	    (ob, &param->link.data[1], param->link.size - 1))
		return 0;
	else if (!loc && !rndr_escape(ob, &param->link))
		return 0;
	if (!HBUF_PUTSL(ob, "}{"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	if (param->attr_id.size > 0 && !HBUF_PUTSL(ob, "}"))
		return 0;
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_list(struct lowdown_buf *ob,
	const struct lowdown_buf *content,
	const struct rndr_list *param)
{
	const char	*type;

	if (ob->size && !hbuf_putc(ob, '\n'))
		return 0;

	/* TODO: HLIST_FL_ORDERED and param->start */

	type = (param->flags & HLIST_FL_ORDERED) ?
		"enumerate" : "itemize";

	if (!hbuf_printf(ob, "\\begin{%s}\n", type))
		return 0;
	if (!(param->flags & HLIST_FL_BLOCK) &&
	    !HBUF_PUTSL(ob, "\\itemsep -0.2em\n"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return hbuf_printf(ob, "\\end{%s}\n", type);
}

static int
rndr_listitem(struct lowdown_buf *ob,
	const struct lowdown_buf *content,
	const struct rndr_listitem *param)
{
	size_t	 size;

	/* Only emit <li> if we're not a <dl> list. */

	if (!(param->flags & HLIST_FL_DEF)) {
		if (!HBUF_PUTSL(ob, "\\item"))
			return 0;
		if ((param->flags & HLIST_FL_CHECKED) &&
		    !HBUF_PUTSL(ob, "[$\\rlap{$\\checkmark$}\\square$]"))
			return 0;
		if ((param->flags & HLIST_FL_UNCHECKED) &&
		    !HBUF_PUTSL(ob, "[$\\square$]"))
			return 0;
		if (!HBUF_PUTSL(ob, " "))
			return 0;
	}

	/* Cut off any trailing space. */

	if ((size = content->size) > 0) {
		while (size && content->data[size - 1] == '\n')
			size--;
		if (!hbuf_put(ob, content->data, size))
			return 0;
	}

	return HBUF_PUTSL(ob, "\n");
}

static int
rndr_paragraph(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{
	size_t	i = 0;

	if (content->size == 0)
		return 1;
	while (i < content->size &&
	       isspace((unsigned char)content->data[i])) 
		i++;
	if (i == content->size)
		return 1;

	if (!HBUF_PUTSL(ob, "\n"))
		return 0;
	if (!hbuf_put(ob, content->data + i, content->size - i))
		return 0;
	return HBUF_PUTSL(ob, "\n");
}

static int
rndr_raw_block(struct lowdown_buf *ob,
	const struct rndr_blockhtml *param,
	const struct latex *st)
{
	size_t	org = 0, sz = param->text.size;

	if (st->oflags & LOWDOWN_LATEX_SKIP_HTML)
		return 1;
	while (sz > 0 && param->text.data[sz - 1] == '\n')
		sz--;
	while (org < sz && param->text.data[org] == '\n')
		org++;
	if (org >= sz)
		return 1;

	if (ob->size && !HBUF_PUTSL(ob, "\n"))
		return 0;
	if (!HBUF_PUTSL(ob, "\\begin{verbatim}\n"))
		return 0;
	if (!hbuf_put(ob, param->text.data + org, sz - org))
		return 0;
	return HBUF_PUTSL(ob, "\\end{verbatim}\n");
}

static int
rndr_hrule(struct lowdown_buf *ob)
{

	if (ob->size && !hbuf_putc(ob, '\n'))
		return 0;
	return HBUF_PUTSL(ob, "\\noindent\\hrulefill\n");
}

static int
rndr_image(struct lowdown_buf *ob,
	const struct rndr_image *param)
{
	const char	*cp;
	char		 dimbuf[32];
	unsigned int	 x, y;
	float		 pct;
	int		 rc = 0;

	/*
	 * Scan in our dimensions, if applicable.
	 * It's unreasonable for them to be over 32 characters, so use
	 * that as a cap to the size.
	 */

	if (param->dims.size && 
	    param->dims.size < sizeof(dimbuf) - 1) {
		memset(dimbuf, 0, sizeof(dimbuf));
		memcpy(dimbuf, param->dims.data, param->dims.size);
		rc = sscanf(dimbuf, "%ux%u", &x, &y);
	}

	/* Extended attributes override dimensions. */

	if (!HBUF_PUTSL(ob, "\\includegraphics["))
		return 0;
	if (param->attr_width.size || param->attr_height.size) {
		if (param->attr_width.size &&
		    param->attr_width.size < sizeof(dimbuf) - 1) {
			memset(dimbuf, 0, sizeof(dimbuf));
			memcpy(dimbuf, param->attr_width.data, 
				param->attr_width.size);

			/* Try to parse as a percentage. */

			if (sscanf(dimbuf, "%e%%", &pct) == 1) {
				if (!hbuf_printf(ob, "width=%.2f"
				     "\\linewidth", pct / 100.0))
					return 0;
			} else {
				if (!hbuf_printf(ob, "width=%.*s", 
				    (int)param->attr_width.size, 
				    param->attr_width.data))
					return 0;
			}
		}
		if (param->attr_height.size &&
		    param->attr_height.size < sizeof(dimbuf) - 1) {
			if (param->attr_width.size && 
			    !HBUF_PUTSL(ob, ", "))
				return 0;
			if (!hbuf_printf(ob, "height=%.*s", 
			    (int)param->attr_height.size, 
			    param->attr_height.data))
				return 0;
		}
	} else if (rc > 0) {
		if (!hbuf_printf(ob, "width=%upx", x))
			return 0;
		if (rc > 1 && !hbuf_printf(ob, ", height=%upx", y))
			return 0;
	}

	if (!HBUF_PUTSL(ob, "]{"))
		return 0;
	cp = memrchr(param->link.data, '.', param->link.size);
	if (cp != NULL) {
		if (!HBUF_PUTSL(ob, "{"))
			return 0;
		if (!rndr_escape_text
		    (ob, param->link.data, cp - param->link.data))
			return 0;
		if (!HBUF_PUTSL(ob, "}"))
			return 0;
		if (!rndr_escape_text(ob, cp, 
		    param->link.size - (cp - param->link.data)))
			return 0;
	} else {
		if (!rndr_escape(ob, &param->link))
			return 0;
	}
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_raw_html(struct lowdown_buf *ob,
	const struct rndr_raw_html *param,
	const struct latex *st)
{

	if (st->oflags & LOWDOWN_LATEX_SKIP_HTML)
		return 1;
	return rndr_escape(ob, &param->text);
}

static int
rndr_table(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	/* Open the table in rndr_table_header. */

	if (ob->size && !hbuf_putc(ob, '\n'))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "\\end{longtable}\n");
}

static int
rndr_table_header(struct lowdown_buf *ob,
	const struct lowdown_buf *content, 
	const struct rndr_table_header *param)
{
	size_t	 i;
	char	 align;
	int	 fl;

	if (!HBUF_PUTSL(ob, "\\begin{longtable}[]{"))
		return 0;

	for (i = 0; i < param->columns; i++) {
		fl = param->flags[i] & HTBL_FL_ALIGNMASK;
		if (fl == HTBL_FL_ALIGN_CENTER)
			align = 'c';
		else if (fl == HTBL_FL_ALIGN_RIGHT)
			align = 'r';
		else
			align = 'l';
		if (!hbuf_putc(ob, align))
			return 0;
	}
	if (!HBUF_PUTSL(ob, "}\n"))
		return 0;
	return hbuf_putb(ob, content);
}

static int
rndr_tablecell(struct lowdown_buf *ob,
	const struct lowdown_buf *content, 
	const struct rndr_table_cell *param)
{

	if (!hbuf_putb(ob, content))
		return 0;
	return (param->col < param->columns - 1) ?
		HBUF_PUTSL(ob, " & ") :
		HBUF_PUTSL(ob, "  \\\\\n");
}

static int
rndr_superscript(struct lowdown_buf *ob,
	const struct lowdown_buf *content)
{

	if (!HBUF_PUTSL(ob, "\\textsuperscript{"))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "}");
}

static int
rndr_normal_text(struct lowdown_buf *ob,
	const struct rndr_normal_text *param)
{

	return rndr_escape(ob, &param->text);
}

static int
rndr_footnote_ref(struct lowdown_buf *ob,
	const struct lowdown_buf *content, struct latex *st)
{

	if (!hbuf_printf(ob, "\\footnote[%zu]{", ++st->footsz))
		return 0;
	if (!hbuf_putb(ob, content))
		return 0;
	return HBUF_PUTSL(ob, "}\n");
}

static int
rndr_math(struct lowdown_buf *ob,
	const struct rndr_math *param)
{

	if (param->blockmode && !HBUF_PUTSL(ob, "\\["))
		return 0;
	else if (!param->blockmode && !HBUF_PUTSL(ob, "\\("))
		return 0;
	if (!hbuf_putb(ob, &param->text))
		return 0;
	if (param->blockmode && !HBUF_PUTSL(ob, "\\]"))
		return 0;
	else if (!param->blockmode && !HBUF_PUTSL(ob, "\\)"))
		return 0;
	return 1;
}

static int
rndr_doc_footer(struct lowdown_buf *ob, const struct latex *st)
{

	if (st->oflags & LOWDOWN_STANDALONE)
		return HBUF_PUTSL(ob, "\\end{document}\n");
	return 1;
}

static int
rndr_doc_header(struct lowdown_buf *ob,
	const struct lowdown_metaq *mq, const struct latex *st)
{
	const struct lowdown_meta	*m;
	const char			*author = NULL, *title = NULL,
					*affil = NULL, *date = NULL,
					*rcsauthor = NULL, 
					*rcsdate = NULL;

	if (!(st->oflags & LOWDOWN_STANDALONE))
		return 1;

	if (!HBUF_PUTSL(ob, 
	    "% Options for packages loaded elsewhere\n"
	    "\\PassOptionsToPackage{unicode}{hyperref}\n"
	    "\\PassOptionsToPackage{hyphens}{url}\n"
	    "%\n"
	    "\\documentclass[11pt,a4paper]{article}\n"
	    "\\usepackage{amsmath,amssymb}\n"
	    "\\usepackage{lmodern}\n"
	    "\\usepackage{iftex}\n"
	    "\\ifPDFTeX\n"
	    "  \\usepackage[T1]{fontenc}\n"
	    "  \\usepackage[utf8]{inputenc}\n"
	    "  \\usepackage{textcomp} % provide euro and other symbols\n"
	    "\\else % if luatex or xetex\n"
	    "  \\usepackage{unicode-math}\n"
	    "  \\defaultfontfeatures{Scale=MatchLowercase}\n"
	    "  \\defaultfontfeatures[\\rmfamily]{Ligatures=TeX,Scale=1}\n"
	    "\\fi\n"
	    "\\usepackage{xcolor}\n"
	    "\\usepackage{graphicx}\n"
	    "\\usepackage{longtable}\n"
	    "\\usepackage{hyperref}\n"
	    "\\begin{document}\n"))
		return 0;

	TAILQ_FOREACH(m, mq, entries)
		if (strcasecmp(m->key, "author") == 0)
			author = m->value;
		else if (strcasecmp(m->key, "affiliation") == 0)
			affil = m->value;
		else if (strcasecmp(m->key, "date") == 0)
			date = m->value;
		else if (strcasecmp(m->key, "rcsauthor") == 0)
			rcsauthor = rcsauthor2str(m->value);
		else if (strcasecmp(m->key, "rcsdate") == 0)
			rcsdate = rcsdate2str(m->value);
		else if (strcasecmp(m->key, "title") == 0)
			title = m->value;

	/* Overrides. */

	if (title == NULL)
		title = "Untitled article";
	if (rcsauthor != NULL)
		author = rcsauthor;
	if (rcsdate != NULL)
		date = rcsdate;

	if (!hbuf_printf(ob, "\\title{%s}\n", title))
		return 0;

	if (author != NULL) {
		if (!hbuf_printf(ob, "\\author{%s", author))
			return 0;
		if (affil != NULL && 
		    !hbuf_printf(ob, " \\\\ %s", affil))
			return 0;
		if (!HBUF_PUTSL(ob, "}\n"))
			return 0;
	}

	if (date != NULL && !hbuf_printf(ob, "\\date{%s}\n", date))
		return 0;

	return HBUF_PUTSL(ob, "\\maketitle\n");
}

static int
rndr_meta(struct lowdown_buf *ob,
	const struct lowdown_buf *content,
	struct lowdown_metaq *mq,
	const struct lowdown_node *n, struct latex *st)
{
	struct lowdown_meta	*m;
	ssize_t			 val;
	const char		*ep;

	if ((m = calloc(1, sizeof(struct lowdown_meta))) == NULL)
		return 0;
	TAILQ_INSERT_TAIL(mq, m, entries);

	m->key = strndup(n->rndr_meta.key.data,
		n->rndr_meta.key.size);
	if (m->key == NULL)
		return 0;
	m->value = strndup(content->data, content->size);
	if (m->value == NULL)
		return 0;

	if (strcmp(m->key, "shiftheadinglevelby") == 0) {
		val = (ssize_t)strtonum
			(m->value, -100, 100, &ep);
		if (ep == NULL)
			st->headers_offs = val + 1;
	} else if (strcmp(m->key, "baseheaderlevel") == 0) {
		val = (ssize_t)strtonum
			(m->value, 1, 100, &ep);
		if (ep == NULL)
			st->headers_offs = val;
	}

	return 1;
}

static int
rndr(struct lowdown_buf *ob,
	struct lowdown_metaq *mq, void *arg, 
	const struct lowdown_node *n)
{
	struct lowdown_buf		*tmp;
	struct latex			*st = arg;
	const struct lowdown_node	*child;
	int				 ret = 0;

	if ((tmp = hbuf_new(64)) == NULL)
		return 0;

	TAILQ_FOREACH(child, &n->children, entries)
		if (!rndr(tmp, mq, st, child))
			goto out;

	/*
	 * These elements can be put in either a block or an inline
	 * context, so we're safe to just use them and forget.
	 */

	if (n->chng == LOWDOWN_CHNG_INSERT && 
	    !HBUF_PUTSL(ob, "{\\color{blue} "))
		goto out;
	if (n->chng == LOWDOWN_CHNG_DELETE &&
	    !HBUF_PUTSL(ob, "{\\color{red} "))
		goto out;

	switch (n->type) {
	case LOWDOWN_BLOCKCODE:
		if (!rndr_blockcode(ob, &n->rndr_blockcode))
			return 0;
		break;
	case LOWDOWN_BLOCKQUOTE:
		if (!rndr_blockquote(ob, tmp))
			return 0;
		break;
	case LOWDOWN_DEFINITION:
		if (!rndr_definition(ob, tmp))
			return 0;
		break;
	case LOWDOWN_DEFINITION_TITLE:
		if (!rndr_definition_title(ob, tmp))
			return 0;
		break;
	case LOWDOWN_DOC_HEADER:
		if (!rndr_doc_header(ob, mq, st))
			return 0;
		break;
	case LOWDOWN_META:
		if (n->chng != LOWDOWN_CHNG_DELETE &&
		    !rndr_meta(ob, tmp, mq, n, st))
			return 0;
		break;
	case LOWDOWN_HEADER:
		if (!rndr_header(ob, tmp, n, st))
			return 0;
		break;
	case LOWDOWN_HRULE:
		if (!rndr_hrule(ob))
			return 0;
		break;
	case LOWDOWN_LIST:
		if (!rndr_list(ob, tmp, &n->rndr_list))
			return 0;
		break;
	case LOWDOWN_LISTITEM:
		if (!rndr_listitem(ob, tmp, &n->rndr_listitem))
			return 0;
		break;
	case LOWDOWN_PARAGRAPH:
		if (!rndr_paragraph(ob, tmp))
			return 0;
		break;
	case LOWDOWN_TABLE_BLOCK:
		if (!rndr_table(ob, tmp))
			return 0;
		break;
	case LOWDOWN_TABLE_HEADER:
		if (!rndr_table_header(ob, tmp, &n->rndr_table_header))
			return 0;
		break;
	case LOWDOWN_TABLE_CELL:
		if (!rndr_tablecell(ob, tmp, &n->rndr_table_cell))
			return 0;
		break;
	case LOWDOWN_BLOCKHTML:
		if (!rndr_raw_block(ob, &n->rndr_blockhtml, st))
			return 0;
		break;
	case LOWDOWN_LINK_AUTO:
		if (!rndr_autolink(ob, &n->rndr_autolink))
			return 0;
		break;
	case LOWDOWN_CODESPAN:
		if (!rndr_codespan(ob, &n->rndr_codespan))
			return 0;
		break;
	case LOWDOWN_DOUBLE_EMPHASIS:
		if (!rndr_double_emphasis(ob, tmp))
			return 0;
		break;
	case LOWDOWN_EMPHASIS:
		if (!rndr_emphasis(ob, tmp))
			return 0;
		break;
	case LOWDOWN_HIGHLIGHT:
		if (!rndr_highlight(ob, tmp))
			return 0;
		break;
	case LOWDOWN_IMAGE:
		if (!rndr_image(ob, &n->rndr_image))
			return 0;
		break;
	case LOWDOWN_LINEBREAK:
		if (!rndr_linebreak(ob))
			return 0;
		break;
	case LOWDOWN_LINK:
		if (!rndr_link(ob, tmp, &n->rndr_link))
			return 0;
		break;
	case LOWDOWN_TRIPLE_EMPHASIS:
		if (!rndr_triple_emphasis(ob, tmp))
			return 0;
		break;
	case LOWDOWN_SUPERSCRIPT:
		if (!rndr_superscript(ob, tmp))
			return 0;
		break;
	case LOWDOWN_FOOTNOTE:
		if (!rndr_footnote_ref(ob, tmp, st))
			return 0;
		break;
	case LOWDOWN_MATH_BLOCK:
		if (!rndr_math(ob, &n->rndr_math))
			return 0;
		break;
	case LOWDOWN_RAW_HTML:
		if (!rndr_raw_html(ob, &n->rndr_raw_html, st))
			return 0;
		break;
	case LOWDOWN_NORMAL_TEXT:
		if (!rndr_normal_text(ob, &n->rndr_normal_text))
			return 0;
		break;
	case LOWDOWN_ENTITY:
		if (!rndr_entity(ob, &n->rndr_entity))
			return 0;
		break;
	case LOWDOWN_ROOT:
		if (!hbuf_putb(ob, tmp))
			return 0;
		if (!rndr_doc_footer(ob, st))
			return 0;
		break;
	default:
		if (!hbuf_putb(ob, tmp))
			return 0;
		break;
	}

	if ((n->chng == LOWDOWN_CHNG_INSERT ||
	     n->chng == LOWDOWN_CHNG_DELETE) && !HBUF_PUTSL(ob, "}"))
		goto out;

	ret = 1;
out:
	hbuf_free(tmp);
	return ret;
}

int
lowdown_latex_rndr(struct lowdown_buf *ob,
	void *arg, const struct lowdown_node *n)
{
	struct latex		*st = arg;
	struct lowdown_metaq	 metaq;
	int			 rc;

	TAILQ_INIT(&st->headers_used);
	TAILQ_INIT(&metaq);
	st->headers_offs = 1;
	st->footsz = 0;

	rc = rndr(ob, &metaq, st, n);

	lowdown_metaq_free(&metaq);
	hentryq_clear(&st->headers_used);
	return rc;
}

void *
lowdown_latex_new(const struct lowdown_opts *opts)
{
	struct latex	*p;

	if ((p = calloc(1, sizeof(struct latex))) == NULL)
		return NULL;

	p->oflags = opts == NULL ? 0 : opts->oflags;
	return p;
}

void
lowdown_latex_free(void *arg)
{

	free(arg);
}
