/*	$Id$ */
/*
 * Copyright (c) 2008, Natacha Porté
 * Copyright (c) 2011, Vicent Martí
 * Copyright (c) 2014, Xavier Mendez, Devin Torres and the Hoedown authors
 * Copyright (c) 2016--2021 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

/*
 * Make sure these are larger than enum hlist_fl.
 */
#define HLIST_LI_END	(1 << 6) /* End of list item. */

/*
 * Mask of all list item types.
 */
#define	HLIST_FL_MASK	(HLIST_FL_DEF | \
			 HLIST_FL_ORDERED | \
			 HLIST_FL_UNORDERED)

/*
 * Reference to a link.
 */
struct	link_ref {
	struct lowdown_buf	*name; /* id of link (or NULL) */
	struct lowdown_buf	*link; /* link address */
	struct lowdown_buf	*title; /* optional title */
	struct lowdown_buf	*attrs; /* optional attributes */
	TAILQ_ENTRY(link_ref)	 entries;
};

TAILQ_HEAD(link_refq, link_ref);

/*
 * Reference to a footnote.  This keeps track of all footnotes
 * definitions and whether there's both a definition and reference.
 */
struct	foot_ref {
	size_t			 num; /* if used, the order */
	struct lowdown_node	*ref; /* if used, the reference */
	struct lowdown_buf	 name; /* identifier */
	struct lowdown_buf	 contents; /* definition */
	TAILQ_ENTRY(foot_ref)	 entries;
};

TAILQ_HEAD(foot_refq, foot_ref);

struct 	lowdown_doc {
	struct link_refq	  refq; /* all internal references */
	struct foot_refq	  footq; /* all footnotes */
	size_t			  foots; /* # of used footnotes */
	int			  active_char[256]; /* jump table */
	unsigned int		  ext_flags; /* options */
	int			  in_link_body; /* parsing link body */
	int			  in_footnote; /* prevent nested */
	size_t			  nodes; /* number of nodes */
	struct lowdown_node	 *current; /* current node */
	struct lowdown_metaq	 *metaq; /* raw metadata key/values */
	size_t			  depth; /* current parse tree depth */
	size_t			  maxdepth; /* max parse tree depth */
	char			**meta; /* primer metadata */
	size_t			  metasz; /* size of meta */
	char			**metaovr; /* override metadata */
	size_t			  metaovrsz; /* size of metaovr */
};

/*
 * Function pointer to render active chars, where "data" is the pointer
 * of the beginning of the span and "offset" is the number of valid
 * chars before data.
 * Returns the number of chars taken care of, or <0 on failure.
 */
typedef ssize_t (*char_trigger)(struct lowdown_doc *, char *, size_t, size_t);

static ssize_t char_emphasis(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_linebreak(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_codespan(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_escape(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_entity(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_langle_tag(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_autolink_url(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_autolink_email(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_autolink_www(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_link(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_image(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_superscript(struct lowdown_doc *, char *, size_t, size_t);
static ssize_t char_math(struct lowdown_doc *, char *, size_t, size_t);

enum markdown_char_t {
	MD_CHAR_NONE = 0,
	MD_CHAR_EMPHASIS,
	MD_CHAR_CODESPAN,
	MD_CHAR_LINEBREAK,
	MD_CHAR_LINK,
	MD_CHAR_IMAGE,
	MD_CHAR_LANGLE,
	MD_CHAR_ESCAPE,
	MD_CHAR_ENTITY,
	MD_CHAR_AUTOLINK_URL,
	MD_CHAR_AUTOLINK_EMAIL,
	MD_CHAR_AUTOLINK_WWW,
	MD_CHAR_SUPERSCRIPT,
	MD_CHAR_QUOTE,
	MD_CHAR_MATH
};

static const char_trigger markdown_char_ptrs[] = {
	NULL,
	&char_emphasis,
	&char_codespan,
	&char_linebreak,
	&char_link,
	&char_image,
	&char_langle_tag,
	&char_escape,
	&char_entity,
	&char_autolink_url,
	&char_autolink_email,
	&char_autolink_www,
	&char_superscript,
	NULL,
	&char_math
};

static int
parse_block(struct lowdown_doc *, char *, size_t);

static ssize_t
parse_listitem(struct lowdown_buf *, struct lowdown_doc *,
	char *, size_t, enum hlist_fl *, size_t);

/*
 * Add a node to the parse stack, or retrieve a current node if
 * requesting multiple LOWDOWN_NORMAL_TEXTs in sequence.  Returns the
 * node, initialised to the given type, after adjusting the parse
 * position.  Returns NULL on memory allocation failure.
 */
static struct lowdown_node *
pushnode(struct lowdown_doc *doc, enum lowdown_rndrt t)
{
	struct lowdown_node	*n;

	/*
	 * Special case: if we're pushing a NORMAL_TEXT node, see if one
	 * already exists and return that.  This means that each push
	 * for text nodes should be careful to use hbuf_push() instead
	 * of hbuf_create() when adding text content.
	 */

	if (t == LOWDOWN_NORMAL_TEXT && doc->current != NULL) {
		n = TAILQ_LAST(&doc->current->children, lowdown_nodeq);
		if (n != NULL && n->type == t) {
			doc->depth++;
			doc->current = n;
			return n;
		}
	}

	/* New node. */

	if ((doc->depth++ > doc->maxdepth) && doc->maxdepth)
		return NULL;
	if ((n = calloc(1, sizeof(struct lowdown_node))) == NULL)
		return NULL;

	n->id = doc->nodes++;
	n->type = t;
	n->parent = doc->current;
	TAILQ_INIT(&n->children);
	if (n->parent != NULL)
		TAILQ_INSERT_TAIL(&n->parent->children, n, entries);
	doc->current = n;
	return n;
}

/*
 * Sets a buffer with the contents of "data" of size "datasz".  The
 * buffer must be empty.  Return FALSE on failure, TRUE on success.
 */
static int
hbuf_create(struct lowdown_buf *buf, const char *data, size_t datasz)
{

	assert(buf->size == 0);
	assert(buf->data == NULL);
	memset(buf, 0, sizeof(struct lowdown_buf));
	if (datasz) {
		if ((buf->data = malloc(datasz)) == NULL)
			return 0;
		buf->unit = 1;
		buf->size = buf->maxsize = datasz;
		memcpy(buf->data, data, datasz);
	}
	return 1;
}

/*
 * See hbuf_create().
 */
static int
hbuf_createb(struct lowdown_buf *buf, const struct lowdown_buf *nbuf)
{

	return hbuf_create(buf, nbuf->data, nbuf->size);
}

/*
 * Pushes data into the buffer, which is initialised if empty.  Return
 * FALSE on failure, TRUE on success.
 */
static int
hbuf_push(struct lowdown_buf *buf, const char *data, size_t datasz)
{

	if (buf->size == 0 || buf->data == NULL)
		return hbuf_create(buf, data, datasz);
	return hbuf_put(buf, data, datasz);
}


/*
 * See pushnode().
 * Pops the current node on the stack, replacing it with the parent.
 */
static void
popnode(struct lowdown_doc *doc, const struct lowdown_node *n)
{

	assert(doc->depth > 0);
	doc->depth--;
	assert(doc->current == n);
	doc->current = doc->current->parent;
}

/*
 * Remove the backslash from a text sequence.
 * Return zero on failure (memory), non-zero on success.
 */
static int
unscape_text(struct lowdown_buf *ob, struct lowdown_buf *src)
{
	size_t	 i, org;

	for (i = 0; i < src->size; i += 2) {
		org = i;
		while (i < src->size && src->data[i] != '\\')
			i++;
		if (i > org &&
		    !hbuf_put(ob, src->data + org, i - org))
			return 0;
		if (i + 1 >= src->size)
			break;
		if (!hbuf_putc(ob, src->data[i + 1]))
			return 0;
	}

	return 1;
}

static struct link_ref *
find_link_ref(struct link_refq *q, char *name, size_t length)
{
	struct link_ref	*ref;

	TAILQ_FOREACH(ref, q, entries)
		if ((ref->name == NULL && length == 0) ||
		    (ref->name != NULL &&
		     ref->name->size == length &&
		     memcmp(ref->name->data, name, length) == 0))
			return ref;

	return NULL;
}

static void
free_link_refs(struct link_refq *q)
{
	struct link_ref	*r;

	while ((r = TAILQ_FIRST(q)) != NULL) {
		TAILQ_REMOVE(q, r, entries);
		hbuf_free(r->link);
		hbuf_free(r->name);
		hbuf_free(r->title);
		hbuf_free(r->attrs);
		free(r);
	}
}

static void
free_foot_refq(struct foot_refq *q)
{
	struct foot_ref	*ref;

	while ((ref = TAILQ_FIRST(q)) != NULL) {
		TAILQ_REMOVE(q, ref, entries);
		hbuf_free(&ref->contents);
		hbuf_free(&ref->name);
		free(ref);
	}
}

/*
 * Check whether a char is a Markdown spacing char.
 * Right now we only consider spaces the actual space and a newline:
 * tabs and carriage returns are filtered out during the preprocessing
 * phase.
 * If we wanted to actually be UTF-8 compliant, we should instead
 * extract an Unicode codepoint from this character and check for space
 * properties.
 */
static int
xisspace(int c)
{

	return c == ' ' || c == '\n';
}

/*
 * Returns the number of leading spaces from data starting from offset
 * to size.
 * If maxlen is greater than zero, only at most maxlen number of leading
 * spaces will be counted.
 * Otherwise, all leading spaces will be counted.
 */
static size_t
countspaces(const char *data, size_t offset, size_t size, size_t maxlen)
{
	size_t	 i;

	for (i = offset; i < size; i++) {
		if (maxlen > 0 && i - offset == maxlen)
			break;
		if (data[i] != ' ')
			break;
	}

	return i;
}

/*
 * Replace all spacing characters in data with spaces.
 * As a special case, this collapses a newline with the previous space,
 * if possible.
 * Return zero on failure (memory), non-zero on success.
 */
static int
replace_spacing(struct lowdown_buf *ob, const char *data, size_t size)
{
	size_t	 i, mark;

	if (!hbuf_grow(ob, size))
		return 0;

	for (i = 0; ; i++) {
		mark = i;
		while (i < size && data[i] != '\n')
			i++;
		if (!hbuf_put(ob, data + mark, i - mark))
			return 0;
		if (i >= size)
			break;
		if (!(i > 0 && data[i - 1] == ' '))
			if (!hbuf_putc(ob, ' '))
				return 0;
	}

	return 1;
}

/*
 * Looks for the address part of a mail autolink and '>'.
 * This is less strict than the original markdown e-mail address
 * matching.
 */
static size_t
is_mail_autolink(const char *data, size_t size)
{
	size_t	 i, nb = 0;

	/* Assumed to be: [-@._a-zA-Z0-9]+ with exactly one '@'. */

	for (i = 0; i < size; ++i) {
		if (isalnum((unsigned char)data[i]))
			continue;

		switch (data[i]) {
		case '@':
			nb++;
		case '-':
		case '.':
		case '_':
			break;
		case '>':
			return (nb == 1) ? i + 1 : 0;
		default:
			return 0;
		}
	}

	return 0;
}

/*
 * Returns the length of the given tag, or 0 is it's not valid.
 */
static size_t
tag_length(const char *data, size_t size, enum halink_type *ltype)
{
	size_t	 i, j;

	/* A valid tag can't be shorter than 3 chars. */

	if (size < 3)
		return 0;

	if (data[0] != '<')
		return 0;

        /* HTML comment, laxist form. */

        if (size > 5 && data[1] == '!' &&
	    data[2] == '-' && data[3] == '-') {
		i = 5;
		while (i < size && !(data[i - 2] == '-' &&
		       data[i - 1] == '-' && data[i] == '>'))
			i++;
		i++;
		if (i <= size)
			return i;
        }

	/*
	 * Begins with a '<' optionally followed by '/', followed by letter or
	 * number.
	 */

        i = (data[1] == '/') ? 2 : 1;

	if (!isalnum((unsigned char)data[i]))
		return 0;

	/* Scheme test. */

	*ltype = HALINK_NONE;

	/* Try to find the beginning of an URI. */

	while (i < size && (isalnum((unsigned char)data[i]) ||
	       data[i] == '.' || data[i] == '+' || data[i] == '-'))
		i++;

	if (i > 1 && data[i] == '@')
		if ((j = is_mail_autolink(data + i, size - i)) != 0) {
			*ltype = HALINK_EMAIL;
			return i + j;
		}

	if (i > 2 && data[i] == ':') {
		*ltype = HALINK_NORMAL;
		i++;
	}

	/* Completing autolink test: no spacing or ' or ". */

	if (i >= size)
		*ltype = HALINK_NONE;
	else if (*ltype) {
		j = i;
		while (i < size) {
			if (data[i] == '\\')
				i += 2;
			else if (data[i] == '>' || data[i] == '\'' ||
				 data[i] == '"' || data[i] == ' ' ||
				 data[i] == '\n')
				break;
			else
				i++;
		}

		if (i >= size)
			return 0;
		if (i > j && data[i] == '>')
			return i + 1;

		/* One of the forbidden chars has been found. */

		*ltype = HALINK_NONE;
	}

	/* Looking for something looking like a tag end. */

	while (i < size && data[i] != '>')
		i++;
	if (i >= size)
		return 0;
	return i + 1;
}

/*
 * Parses inline markdown elements.
 * This function is important because it handles raw input that we pass
 * directly to the output formatter ("normal_text").
 * Return zero on failure, non-zero on success.
 */
static int
parse_inline(struct lowdown_doc *doc, char *data, size_t size)
{
	size_t	 	 	 i = 0, end = 0, consumed = 0;
	ssize_t			 rc;
	struct lowdown_buf	 work;
	const int		*active_char = doc->active_char;
	struct lowdown_node 	*n;

	memset(&work, 0, sizeof(struct lowdown_buf));
	
	while (i < size) {
		/* Copying non-macro chars into the output. */

		while (end < size &&
		       active_char[(unsigned char)data[end]] == 0)
			end++;

		/* Only allocate if non-empty... */

		if (end - i > 0) {
			n = pushnode(doc, LOWDOWN_NORMAL_TEXT);
			if (n == NULL)
				return 0;
			if (!hbuf_push(&n->rndr_normal_text.text,
			    data + i, end - i))
				return 0;
			popnode(doc, n);
		}

		/* End of file? */

		if (end >= size)
			break;

		i = end;
		rc = markdown_char_ptrs[
			active_char[(unsigned char)data[end]]]
			(doc, data + i, i - consumed, size - i);
		if (rc < 0)
			return 0;
		end = rc;

		/* Check if no action from the callback. */

		if (end == 0) {
			end = i + 1;
			continue;
		}

		i += end;
		end = consumed = i;
	}

	return 1;
}

/*
 * Returns whether special char at data[loc] is escaped by '\\'.
 */
static int
is_escaped(const char *data, size_t loc)
{
	size_t	 i = loc;

	while (i >= 1 && data[i - 1] == '\\')
		i--;

	/* Odd numbers of backslashes escapes data[loc]. */

	return (loc - i) % 2;
}

/*
 * Looks for the next emph char, skipping other constructs.
 */
static size_t
find_emph_char(const char *data, size_t size, char c)
{
	size_t 	 i = 0, span_nb, bt, tmp_i;
	char 	 cc;

	while (i < size) {
		while (i < size && data[i] != c &&
		       data[i] != '[' && data[i] != '`')
			i++;

		if (i == size)
			return 0;

		/* Not counting escaped chars. */

		if (is_escaped(data, i)) {
			i++;
			continue;
		}

		if (data[i] == c)
			return i;

		/* Skipping a codespan. */

		if (data[i] == '`') {
			span_nb = 0;
			tmp_i = 0;

			/* Counting the number of opening backticks. */

			while (i < size && data[i] == '`') {
				i++;
				span_nb++;
			}

			if (i >= size)
				return 0;

			/* Finding the matching closing sequence. */

			bt = 0;
			while (i < size && bt < span_nb) {
				if (!tmp_i && data[i] == c)
					tmp_i = i;

				if (data[i] == '`')
					bt++;
				else
					bt = 0;
				i++;
			}

			/*
			 * Not a well-formed codespan; use found
			 * matching emph char.
			 */
			if (bt < span_nb && i >= size)
				return tmp_i;
		} else if (data[i] == '[') {
			tmp_i = 0;

			/* Skipping a link. */

			i++;
			while (i < size && data[i] != ']') {
				if (!tmp_i && data[i] == c)
					tmp_i = i;
				i++;
			}

			i++;
			while (i < size && xisspace(data[i]))
				i++;

			if (i >= size)
				return tmp_i;

			switch (data[i]) {
			case '[':
				cc = ']';
				break;
			case '(':
				cc = ')';
				break;
			default:
				if (tmp_i)
					return tmp_i;
				else
					continue;
			}

			i++;
			while (i < size && data[i] != cc) {
				if (!tmp_i && data[i] == c)
					tmp_i = i;
				i++;
			}

			if (i >= size)
				return tmp_i;

			i++;
		}
	}

	return 0;
}

/*
 * Parsing single emphase.
 * Closed by a symbol not preceded by spacing and not followed by
 * symbol.
 * Return 0 if not an emphasis, <0 on failure, >0 on success.
 */
static ssize_t
parse_emph1(struct lowdown_doc *doc, char *data, size_t size, char c)
{
	size_t	 		 i = 0, len;
	struct lowdown_node	*n;

	/* Skipping one symbol if coming from emph3. */

	if (size > 1 && data[0] == c && data[1] == c)
		i = 1;

	while (i < size) {
		len = find_emph_char(data + i, size - i, c);
		if (!len)
			return 0;
		i += len;
		if (i >= size)
			return 0;

		if (data[i] == c && !xisspace(data[i - 1])) {
			if ((doc->ext_flags & LOWDOWN_NOINTEM) &&
			    i + 1 < size &&
			    isalnum((unsigned char)data[i + 1]))
				continue;

			n = pushnode(doc, LOWDOWN_EMPHASIS);
			if (n == NULL)
				return -1;
			if (!parse_inline(doc, data, i))
				return -1;
			popnode(doc, n);
			return i + 1;
		}
	}

	return 0;
}

/*
 * Parsing single emphase.
 * Return 0 if not an emphasis, <0 on failure, >0 on success.
 */
static ssize_t
parse_emph2(struct lowdown_doc *doc, char *data, size_t size, char c)
{
	size_t			 i = 0, len;
	struct lowdown_node	*n;
	enum lowdown_rndrt	 t;

	while (i < size) {
		len = find_emph_char(data + i, size - i, c);
		if (len == 0)
			return 0;
		i += len;

		if (i + 1 < size && data[i] == c &&
		    data[i + 1] == c && i &&
		    !xisspace(data[i - 1])) {
			if (c == '~')
				t = LOWDOWN_STRIKETHROUGH;
			else if (c == '=')
				t = LOWDOWN_HIGHLIGHT;
			else
				t = LOWDOWN_DOUBLE_EMPHASIS;

			if ((n = pushnode(doc, t)) == NULL)
				return -1;
			if (!parse_inline(doc, data, i))
				return -1;
			popnode(doc, n);
			return i + 2;
		}
		i++;
	}

	return 0;
}

/*
 * Parsing single emphase
 * Finds the first closing tag, and delegates to the other emph.
 * Return 0 if not an emphasis, <0 on failure, >0 on success.
 */
static size_t
parse_emph3(struct lowdown_doc *doc, char *data, size_t size, char c)
{
	size_t	 		 i = 0, len;
	ssize_t			 rc;
	struct lowdown_node	*n;

	while (i < size) {
		len = find_emph_char(data + i, size - i, c);
		if (len == 0)
			return 0;
		i += len;

		/* Skip spacing preceded symbols. */

		if (data[i] != c || xisspace(data[i - 1]))
			continue;

		/* Case for triple, double, and single asterisk. */

		if (i + 2 < size && data[i + 1] == c &&
		    data[i + 2] == c) {
			n = pushnode(doc, LOWDOWN_TRIPLE_EMPHASIS);
			if (n == NULL)
				return -1;
			if (!parse_inline(doc, data, i))
				return -1;
			popnode(doc, n);
			return i + 3;
		} else if (i + 1 < size && data[i + 1] == c) {
			rc = parse_emph1(doc, data - 2, size + 2, c);
			if (rc < 0)
				return -1;
			assert(rc == 0 || rc >= 2);
			return rc == 0 ? 0 : rc - 2;
		} else {
			rc = parse_emph2(doc, data - 1, size + 1, c);
			if (rc < 0)
				return -1;
			return rc == 0 ? 0 : rc - 1;
		}
	}

	return 0;
}

/*
 * Parses a math span until the given ending delimiter.
 * Return 0 if not math, <0 on failure, >0 on success.
 */
static ssize_t
parse_math(struct lowdown_doc *doc, char *data, size_t offset,
	size_t size, const char *end, size_t delimsz, int blockmode)
{
	size_t			 i;
	struct lowdown_node	*n;

	/*
	 * Find ending delimiter.
	 * All text within the equation is opaque, so we don't need to
	 * care about embedded macros.
	 */

	for (i = delimsz; ; i++) {
		while (i < size && data[i] != end[0])
			i++;
		if (i >= size)
			return 0;
		if (!is_escaped(data, i) && !(i + delimsz > size) &&
		    memcmp(data + i, end, delimsz) == 0)
			break;
	}

	i += delimsz;

	if (!(doc->ext_flags & LOWDOWN_MATH)) {
		n = pushnode(doc, LOWDOWN_NORMAL_TEXT);
		if (n == NULL)
			return -1;
		if (!hbuf_push(&n->rndr_normal_text.text, data, i))
			return -1;
		popnode(doc, n);
		return i;
	}

	n = pushnode(doc, LOWDOWN_MATH_BLOCK);
	if (n == NULL)
		return -1;
  	if (!hbuf_create(&n->rndr_math.text,
	    data + delimsz, i - 2 * delimsz))
		return -1;
	n->rndr_math.blockmode = blockmode;
	popnode(doc, n);
	return i;
}

/*
 * Single and double emphasis parsing.
 */
static ssize_t
char_emphasis(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	char	 c = data[0];
	ssize_t	 ret;

	if (doc->ext_flags & LOWDOWN_NOINTEM)
		if (offset > 0 && !xisspace(data[-1]) &&
		    data[-1] != '>' && data[-1] != '(')
			return 0;

	/*
	 * Spacing cannot follow an opening emphasis: strikethrough and
	 * highlight only takes '~~'.
	 * FIXME: don't depend upon the "ret =" as the last part of an
	 * "or" chain---it's hard to read.
	 */

	if (size > 2 && data[1] != c) {
		if (c == '~' || c == '=' || xisspace(data[1]) ||
		    (ret = parse_emph1
		     (doc, data + 1, size - 1, c)) == 0)
			return 0;
		return ret > 0 ? ret + 1 : ret;
	}

	if (size > 3 && data[1] == c && data[2] != c) {
		if (xisspace(data[2]) ||
		    (ret = parse_emph2
		     (doc, data + 2, size - 2, c)) == 0)
			return 0;
		return ret > 0 ? ret + 2 : ret;
	}

	if (size > 4 && data[1] == c && data[2] == c && data[3] != c) {
		if (c == '~' || c == '=' || xisspace(data[3]) ||
		    (ret = parse_emph3
		     (doc, data + 3, size - 3, c)) == 0)
			return 0;
		return ret > 0 ? ret + 3 : ret;
	}

	return 0;
}

/*
 * '\n' preceded by two spaces (assuming linebreak != 0)
 */
static ssize_t
char_linebreak(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_node 	*n;
	size_t		 	 w;
	struct lowdown_buf	*b;

	if (offset < 2 || data[-1] != ' ' || data[-2] != ' ')
		return 0;

	/* Removing the last space from nodes. */

	assert(doc->current != NULL);
	n = TAILQ_LAST(&doc->current->children, lowdown_nodeq);
	assert(n != NULL && LOWDOWN_NORMAL_TEXT == n->type);
	b = &n->rndr_normal_text.text;

	while (b->size && b->data[b->size - 1] == ' ')
		b->size--;

	/*
	 * Swallow leading white-space of next line.
	 * XXX: is this just CommonMark?
	 */

	for (w = 1; w < size; w++)
		if (data[w] != ' ')
			break;

	if ((n = pushnode(doc, LOWDOWN_LINEBREAK)) == NULL)
		return -1;
	popnode(doc, n);
	return w;
}

/*
 * '`' parsing a code span (assuming codespan != 0)
 */
static ssize_t
char_codespan(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_buf	 work;
	struct lowdown_node 	*n;
	size_t	 		 end, nb = 0, i, f_begin, f_end;

	memset(&work, 0, sizeof(struct lowdown_buf));

	/* Counting the number of backticks in the delimiter. */

	while (nb < size && data[nb] == '`')
		nb++;

	/* Finding the next delimiter. */

	i = 0;
	for (end = nb; end < size && i < nb; end++) {
		if (data[end] == '`')
			i++;
		else
			i = 0;
	}

	if (i < nb && end >= size)
		return 0; /* no matching delimiter */

	/* Trimming outside spaces. */

	f_begin = countspaces(data, nb, end, 0);

	f_end = end - nb;
	while (f_end > nb && data[f_end-1] == ' ')
		f_end--;

	/* Real code span. */

	if ((n = pushnode(doc, LOWDOWN_CODESPAN)) == NULL)
		return -1;

	if (f_begin < f_end) {
		work.data = data + f_begin;
		work.size = f_end - f_begin;
		if (!hbuf_createb(&n->rndr_codespan.text, &work))
			return -1;
	}

	popnode(doc, n);

	return end;
}

/*
 * '\\' backslash escape
 */
static ssize_t
char_escape(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	static const char 	*escape_chars =
		"\\`*_{}[]()#+-.!:|&<>^~=\"$";
	struct lowdown_buf	 work;
	size_t		 	 w;
	ssize_t		 	 ret;
	const char		*end;
	struct lowdown_node 	*n;

	memset(&work, 0, sizeof(struct lowdown_buf));

	if (size > 1) {
		if (data[1] == '\\' &&
		    (doc->ext_flags & LOWDOWN_MATH) &&
		    size > 2 &&
		    (data[2] == '(' || data[2] == '[')) {
			end = (data[2] == '[') ? "\\\\]" : "\\\\)";
			ret = parse_math(doc, data, offset,
				size, end, 3, data[2] == '[');
			if (ret != 0)
				return ret;
		}

		/* Swallow leading white-space of next line. */

		if (LOWDOWN_COMMONMARK & doc->ext_flags &&
		    data[1] == '\n') {
			for (w = 2; w < size; w++)
				if (data[w] != ' ')
					break;
			n = pushnode(doc, LOWDOWN_LINEBREAK);
			if (n == NULL)
				return -1;
			popnode(doc, n);
			return w;
		}

		if (strchr(escape_chars, data[1]) == NULL)
			return 0;
		if ((n = pushnode(doc, LOWDOWN_NORMAL_TEXT)) == NULL)
			return -1;
		if (!hbuf_push(&n->rndr_normal_text.text, data + 1, 1))
			return -1;
		popnode(doc, n);
	} else if (size == 1) {
		if ((n = pushnode(doc, LOWDOWN_NORMAL_TEXT)) == NULL)
			return -1;
		if (!hbuf_push(&n->rndr_normal_text.text, data, 1))
			return -1;
		popnode(doc, n);
	}

	return 2;
}

/*
 * '&': parse entity, or escape if it's not an entity.
 * Valid entities are assumed to be anything matching &#?[A-Za-z0-9]+;
 */
static ssize_t
char_entity(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	size_t	 		 end = 1;
	struct lowdown_node 	*n;

	if (end < size && data[end] == '#')
		end++;

	while (end < size && isalnum((unsigned char)data[end]))
		end++;

	if (end < size && data[end] == ';')
		end++; /* real entity */
	else
		return 0; /* lone '&' */

	if ((n = pushnode(doc, LOWDOWN_ENTITY)) == NULL)
		return -1;
	if (!hbuf_create(&n->rndr_entity.text, data, end))
		return -1;
	popnode(doc, n);
	return end;
}

/*
 * '<': parse link when tags or autolinks are allowed.
 */
static ssize_t
char_langle_tag(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_buf 	 work;
	struct lowdown_buf	*u_link = NULL;
	enum halink_type 	 altype = HALINK_NONE;
	size_t 	 	 	 end = tag_length(data, size, &altype);
	int 		 	 ret = 0;
	struct lowdown_node 	*n;
	
	memset(&work, 0, sizeof(struct lowdown_buf));

	work.data = data;
	work.size = end;

	if (end > 2) {
		if (altype != HALINK_NONE) {
			if ((u_link = hbuf_new(64)) == NULL)
				goto err;
			work.data = data + 1;
			work.size = end - 2;
			if (!unscape_text(u_link, &work))
				goto err;

			n = pushnode(doc, LOWDOWN_LINK_AUTO);
			if (n == NULL)
				goto err;
			n->rndr_autolink.type = altype;
			if (!hbuf_createb(&n->rndr_autolink.link, u_link))
				goto err;
			popnode(doc, n);
		} else {
			n = pushnode(doc, LOWDOWN_RAW_HTML);
			if (n == NULL)
				goto err;
			if (!hbuf_create
			    (&n->rndr_raw_html.text, data, end))
				goto err;
			popnode(doc, n);
		}
		ret = 1;
	}

	hbuf_free(u_link);
	return !ret ? 0 : end;
err:
	hbuf_free(u_link);
	return -1;
}

/*
 * 'w': parse URL when autolinking is allowed (from "www").
 */
static ssize_t
char_autolink_www(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_buf	*link = NULL, *link_url = NULL;
	size_t	 		 link_len, rewind;
	struct lowdown_node 	*n;
	ssize_t			 ret;

	if (doc->in_link_body)
		return 0;
	if ((link = hbuf_new(64)) == NULL)
		goto err;
	ret = halink_www(&rewind, link, data, offset, size);
	if (ret < 0)
		goto err;
	link_len = ret;

	if (link_len > 0) {
		if ((link_url = hbuf_new(64)) == NULL)
			goto err;
		if (!HBUF_PUTSL(link_url, "http://"))
			goto err;
		if (!hbuf_put(link_url, link->data, link->size))
			goto err;

		if (doc->current &&
		    (n = TAILQ_LAST(&doc->current->children,
		     lowdown_nodeq)) != NULL &&
		    n->type == LOWDOWN_NORMAL_TEXT) {
			if (n->rndr_normal_text.text.size > rewind)
				n->rndr_normal_text.text.size -= rewind;
			else
				n->rndr_normal_text.text.size = 0;
		}

		if ((n = pushnode(doc, LOWDOWN_LINK_AUTO)) == NULL)
			goto err;
		n->rndr_autolink.type = HALINK_NORMAL;
		if (!hbuf_createb(&n->rndr_autolink.link, link_url))
			goto err;
		popnode(doc, n);
	}

	hbuf_free(link);
	hbuf_free(link_url);
	return link_len;
err:
	hbuf_free(link);
	hbuf_free(link_url);
	return -1;
}

/*
 * '@': parse email when autolinking is allowed (from the at sign).
 */
static ssize_t
char_autolink_email(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_buf	*link = NULL;
	size_t	 		 link_len, rewind;
	ssize_t			 ret;
	struct lowdown_node 	*n;

	if (doc->in_link_body)
		return 0;
	if ((link = hbuf_new(64)) == NULL)
		goto err;
	ret = halink_email(&rewind, link, data, offset, size);
	if (ret < 0)
		goto err;
	link_len = ret;

	if (link_len > 0) {
		if (doc->current &&
		    (n = TAILQ_LAST(&doc->current->children,
		     lowdown_nodeq)) != NULL &&
		    n->type == LOWDOWN_NORMAL_TEXT) {
			if (n->rndr_normal_text.text.size > rewind)
				n->rndr_normal_text.text.size -= rewind;
			else
				n->rndr_normal_text.text.size = 0;
		}

		if ((n = pushnode(doc, LOWDOWN_LINK_AUTO)) == NULL)
			goto err;
		n->rndr_autolink.type = HALINK_EMAIL;
		if (!hbuf_createb(&n->rndr_autolink.link, link))
			goto err;
		popnode(doc, n);
	}

	hbuf_free(link);
	return link_len;
err:
	hbuf_free(link);
	return -1;
}

/*
 * ':': parse URL when autolinking is allowed (from the schema).
 */
static ssize_t
char_autolink_url(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_buf	*link = NULL;
	size_t			 link_len, rewind;
	struct lowdown_node 	*n;
	ssize_t			 ret;

	if (doc->in_link_body)
		return 0;
	if ((link = hbuf_new(64)) == NULL)
		goto err;
	ret = halink_url(&rewind, link, data, offset, size);
	if (ret < 0)
		goto err;
	link_len = ret;

	if (link_len > 0) {
		if (doc->current &&
		    (n = TAILQ_LAST(&doc->current->children,
		     lowdown_nodeq)) != NULL &&
		    n->type == LOWDOWN_NORMAL_TEXT) {
			if (n->rndr_normal_text.text.size > rewind)
				n->rndr_normal_text.text.size -= rewind;
			else
				n->rndr_normal_text.text.size = 0;
		}

		if ((n = pushnode(doc, LOWDOWN_LINK_AUTO)) == NULL)
			goto err;
		n->rndr_autolink.type = HALINK_NORMAL;
		if (!hbuf_createb(&n->rndr_autolink.link, link))
			goto err;
		popnode(doc, n);
	}

	hbuf_free(link);
	return link_len;
err:
	hbuf_free(link);
	return -1;
}

/*
 * '!': parse an image.
 */
static ssize_t
char_image(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	ssize_t	 ret;

	if (size < 2 || data[1] != '[')
		return 0;

	ret = char_link(doc, data + 1, offset + 1, size - 1);
	return ret <= 0 ? ret : ret + 1;
}

/*
 * Parse extended attributes from the buffer "data".  The buffer should
 * not have any enclosing characters, e.g., { foo }.  Return 0 on
 * failure or position of *next* word.
 */
static size_t
parse_ext_attrs(const char *data, size_t size,
	struct lowdown_buf **attrid,
	struct lowdown_buf **attrcls,
	struct lowdown_buf **attrwidth,
	struct lowdown_buf **attrheight)
{
	size_t	 word_b, word_e;

	word_b = 0;

	while (word_b < size) {
		while (word_b < size && data[word_b] == ' ')
			word_b++;
		word_e = word_b;
		while (word_e < size && data[word_e] != ' ')
		     word_e++;

		/* Classes. */

		if (attrid != NULL &&
		    word_e > word_b + 1 &&
		    data[word_b] == '#') {
			if (*attrid == NULL &&
			    (*attrid = hbuf_new(64)) == NULL)
				return 0;
			hbuf_truncate(*attrid);
			if (!hbuf_put(*attrid,
			     data + word_b + 1, word_e - word_b - 1))
				return 0;
		}

		if (attrwidth != NULL &&
		    word_e > word_b + 7 &&
	  	    strncasecmp(&data[word_b], "width=", 6) == 0) {
			if (*attrwidth == NULL &&
			    (*attrwidth = hbuf_new(64)) == NULL)
				return 0;
			hbuf_truncate(*attrwidth);
			if (!hbuf_put(*attrwidth,
			     data + word_b + 6, word_e - word_b - 6))
				return 0;
		}
		if (attrheight != NULL &&
		    word_e > word_b + 8 &&
	  	    strncasecmp(&data[word_b], "height=", 7) == 0) {
			if (*attrheight == NULL &&
			    (*attrheight = hbuf_new(64)) == NULL)
				return 0;
			hbuf_truncate(*attrheight);
			if (!hbuf_put(*attrheight,
			     data + word_b + 7, word_e - word_b - 7))
				return 0;
		}

		if (attrcls != NULL &&
		    word_e > word_b + 1 &&
		    data[word_b] == '.') {
			if (*attrcls != NULL &&
			    !hbuf_putc(*attrcls, ' '))
				return 0;
			if (*attrcls == NULL &&
			    (*attrcls = hbuf_new(64)) == NULL)
				return 0;
			if (!hbuf_put(*attrcls,
			     data + word_b + 1, word_e - word_b - 1))
				return 0;
		}
		word_b = word_e + 1;
	}

	return word_b;
}

/*
 * Parse a header's extended attributes.  Return FALSE on failure, TRUE
 * on success.
 */
static int
parse_header_ext_attrs(struct lowdown_node *n)
{
	struct lowdown_node	*nn;
	struct lowdown_buf	*b, *attrid = NULL, *attrcls = NULL;
	size_t			 i;
	int			 rc = 0;

	/*
	 * The last node on the line must be non-empty normal text and
	 * must end with a '}'.
	 */

	nn = TAILQ_LAST(&n->children, lowdown_nodeq);
	if (nn == NULL ||
	    nn->type != LOWDOWN_NORMAL_TEXT ||
	    nn->rndr_normal_text.text.size == 0 ||
	    nn->rndr_normal_text.text.data
	     [nn->rndr_normal_text.text.size - 1] != '}')
		return 1;

	/* Scan from the trailing '}' to the opening '{'. */

	b = &nn->rndr_normal_text.text;
	assert(b->size && b->data[b->size - 1] == '}');
	for (i = b->size - 1; i > 0; i--)
		if (b->data[i] == '{')
			break;
	if (b->data[i] != '{')
		return 1;

	/* Parse the extended attributes. */

	if (!parse_ext_attrs(&b->data[i + 1], b->size - i - 2,
	    &attrid, &attrcls, NULL, NULL))
		goto out;

	if (attrid != NULL &&
	    !hbuf_createb(&n->rndr_header.attr_id, attrid))
		goto out;
	if (attrcls != NULL &&
	    !hbuf_createb(&n->rndr_header.attr_cls, attrcls))
		goto out;

	b->size = i;
	while (b->size && b->data[b->size - 1] == ' ')
		b->size--;

	/* Is there nothing left? */

	if (b->size == 0) {
		TAILQ_REMOVE(&n->children, nn, entries);
		lowdown_node_free(nn);
	}

	rc = 1;
out:
	hbuf_free(attrid);
	hbuf_free(attrcls);
	return rc;
}

/*
 * '[': parsing a link, footnote, metadata, or image.
 */
static ssize_t
char_link(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	struct lowdown_buf	*content = NULL, *link = NULL,
				*title = NULL, *u_link = NULL,
				*dims = NULL, *idp = NULL,
				*linkp = NULL, *titlep = NULL,
				*attrcls = NULL, *attrid = NULL,
				*attrwidth = NULL, *attrheight = NULL;
	size_t			 i = 1, j, txt_e, link_b = 0, link_e = 0,
				 title_b = 0, title_e = 0, nb_p,
				 dims_b = 0, dims_e = 0;
	int 	 		 ret = 0, in_title = 0, qtype = 0,
				 is_img, is_footnote, is_metadata;
	struct lowdown_buf	 id;
	struct link_ref 	*lr = NULL;
	struct foot_ref	 	*fr;
	struct lowdown_node 	*n;
	struct lowdown_meta	*m;

	is_img = offset && data[-1] == '!' &&
		!is_escaped(data - offset, offset - 1);
	is_footnote = (doc->ext_flags & LOWDOWN_FOOTNOTES) &&
		data[1] == '^';
	is_metadata = (doc->ext_flags & LOWDOWN_METADATA) &&
		data[1] == '%';

	/* Looking for the matching closing bracket. */

	i += find_emph_char(data + i, size - i, ']');
	txt_e = i;

	if (i < size && data[i] == ']')
		i++;
	else
		goto cleanup;

	/*
	 * If we start as an image then change into metadata or a
	 * footnote, make sure to emit the exclamation mark.
	 */

	if (is_img && (is_footnote || is_metadata)) {
		n = pushnode(doc, LOWDOWN_NORMAL_TEXT);
		if (n == NULL)
			goto err;
		if (!hbuf_push(&n->rndr_normal_text.text, &data[-1], 1))
			goto err;
		popnode(doc, n);
	}

	/*
	 * Footnote (in footer): look up footnote by its key in our
	 * queue of footnotes.  This queue was created in the first pass
	 * of the compiler.  If we've already listed the footnote, don't
	 * render it twice.  Don't allow embedded footnotes as well.
	 */

	if (is_footnote) {
		memset(&id, 0, sizeof(struct lowdown_buf));
		if (txt_e < 3)
			goto cleanup;
		id.data = data + 2;
		id.size = txt_e - 2;

		TAILQ_FOREACH(fr, &doc->footq, entries)
			if (hbuf_eq(&fr->name, &id))
				break;

		/* Override. */

		if (doc->in_footnote)
			fr = NULL;

		/*
		 * Mark footnote used.  If it's NULL, then there was no
		 * footnote found.  If it is NULL and the reference is
		 * defined, then we've already registered the footnote.
		 * XXX: Markdown, as is, can only use one footnote
		 * reference per definition.  This is stupid.
		 */

		if (fr != NULL && fr->ref == NULL) {
			n = pushnode(doc, LOWDOWN_FOOTNOTE);
			if (n == NULL)
				goto err;
			fr->num = ++doc->foots;
			fr->ref = n;
			assert(doc->in_footnote == 0);
			doc->in_footnote = 1;
			if (!parse_block(doc,
			    fr->contents.data, fr->contents.size))
				goto err;
			assert(doc->in_footnote);
			doc->in_footnote = 0;
		} else {
			n = pushnode(doc, LOWDOWN_NORMAL_TEXT);
			if (n == NULL)
				goto err;
			if (!hbuf_push(&n->rndr_normal_text.text,
			    data, txt_e + 1))
				goto err;
		}

		popnode(doc, n);
		ret = 1;
		goto cleanup;
	}

	/*
	 * Metadata: simply copy the variable (if found) into our
	 * stream.  It's raw text, so we need to pass it into our
	 * "normal text" formatter.
	 */

	if (is_metadata) {
		memset(&id, 0, sizeof(struct lowdown_buf));
		if (txt_e < 3)
			goto cleanup;
		id.data = data + 2;
		id.size = txt_e - 2;

		/* FIXME: slow O(n). */

		TAILQ_FOREACH(m, doc->metaq, entries) {
			if (!hbuf_streq(&id, m->key))
				continue;
			assert(m->value != NULL);
			n = pushnode(doc, LOWDOWN_NORMAL_TEXT);
			if (n == NULL)
				goto err;
			if (!hbuf_push(&n->rndr_normal_text.text,
			    m->value, strlen(m->value)))
				goto err;
			popnode(doc, n);
			break;
		}

		ret = 1;
		goto cleanup;
	}

	/*
	 * Skip any amount of spacing.  (This is much more laxist than
	 * original markdown syntax.)
	 */

	while (i < size && xisspace(data[i]))
		i++;

	/* Different style of links (regular, reference, shortcut. */

	if (i < size && data[i] == '(') {
		i++;
		while (i < size && xisspace(data[i]))
			i++;

		link_b = i;

		/*
		 * Looking for link end: ' " )
		 * Count the number of open parenthesis.
		*/

		nb_p = 0;

		while (i < size) {
			if (data[i] == '\\') {
				i += 2;
			} else if (data[i] == '(' && i != 0) {
				nb_p++;
				i++;
			} else if (data[i] == ')') {
				if (nb_p == 0)
					break;
				else
					nb_p--;
				i++;
			} else if (i >= 1 && xisspace(data[i-1]) &&
				   (data[i] == '\'' ||
				    data[i] == '=' ||
				    data[i] == '"'))
				break;
			else
				i++;
		}

		if (i >= size)
			goto cleanup;

		link_e = i;

		/*
		 * We might be at the end of the link, or we might be at
		 * the title of the link.
		 * In the latter case, progress til link-end.
		 */
again:
		if (data[i] == '\'' || data[i] == '"') {
			/*
			 * Looking for title end if present.
			 * This is a quoted part after the image.
			 */

			qtype = data[i];
			in_title = 1;
			i++;
			title_b = i;

			for ( ; i < size; i++)
				if (data[i] == '\\')
					i++;
				else if (data[i] == qtype)
					in_title = 0;
				else if ((data[i] == '=') && !in_title)
					break;
				else if ((data[i] == ')') && !in_title)
					break;

			if (i >= size)
				goto cleanup;

			/* Skipping spacing after title. */

			title_e = i - 1;
			while (title_e > title_b &&
			       xisspace(data[title_e]))
				title_e--;

			/* Checking for closing quote presence. */

			if (data[title_e] != '\'' && 
			    data[title_e] != '"') {
				title_b = title_e = 0;
				link_e = i;
			}

			/*
			 * If we're followed by a dimension string, then
			 * jump back into the parsing engine for it.
			 */

			if (data[i] == '=')
				goto again;
		} else if (data[i] == '=') {
			dims_b = ++i;
			for ( ; i < size; i++)
				if (data[i] == '\\')
					i++;
				else if ('\'' == data[i] || '"' == data[i])
					break;
				else if (data[i] == ')')
					break;

			if (i >= size)
				goto cleanup;

			/* Skipping spacing after dimensions. */

			dims_e = i;
			while (dims_e > dims_b &&
			       xisspace(data[dims_e]))
				dims_e--;

			/*
			 * If we're followed by a title string, then
			 * jump back into the parsing engine for it.
			 */

			if (data[i] == '"' || data[i] == '\'')
				goto again;
		}

		/* Remove spacing at the end of the link. */

		while (link_e > link_b && xisspace(data[link_e - 1]))
			link_e--;

		/* Remove optional angle brackets around the link. */

		if (data[link_b] == '<' && data[link_e - 1] == '>') {
			link_b++;
			link_e--;
		}

		/* building escaped link and title */
		if (link_e > link_b) {
			link = linkp = hbuf_new(64);
			if (linkp == NULL)
				goto err;
			if (!hbuf_put(link,
			    data + link_b, link_e - link_b))
				goto err;
		}

		if (title_e > title_b) {
			title = titlep = hbuf_new(64);
			if (titlep == NULL)
				goto err;
			if (!hbuf_put(title,
			    data + title_b, title_e - title_b))
				goto err;
		}

		if (dims_e > dims_b) {
			if ((dims = hbuf_new(64)) == NULL)
				goto err;
			if (!hbuf_put(dims,
			    data + dims_b, dims_e - dims_b))
				goto err;
		}

		i++;
	} else if (i < size && data[i] == '[') {
		if ((idp = hbuf_new(64)) == NULL)
			goto err;

		/* Looking for the id. */

		i++;
		link_b = i;
		while (i < size && data[i] != ']')
			i++;
		if (i >= size)
			goto cleanup;
		link_e = i;

		/* Finding the link_ref. */

		if (link_b == link_e) {
			if (!replace_spacing
			    (idp, data + 1, txt_e - 1))
				goto err;
		} else
			if (!hbuf_put(idp,
			    data + link_b, link_e - link_b))
				goto err;

		lr = find_link_ref(&doc->refq, idp->data, idp->size);
		if (lr == NULL)
			goto cleanup;

		/* Keeping link and title from link_ref. */

		link = lr->link;
		title = lr->title;
		if (lr->attrs != NULL && parse_ext_attrs
		    (lr->attrs->data, lr->attrs->size,
		     &attrid, &attrcls, &attrwidth, &attrheight) == 0)
			goto err;
		i++;
	} else {
		/*
		 * Shortcut reference style link.
		 */
		if ((idp = hbuf_new(64)) == NULL)
			goto err;

		/* Crafting the id. */

		if (!replace_spacing(idp, data + 1, txt_e - 1))
			goto err;

		/* Finding the link_ref. */

		lr = find_link_ref(&doc->refq, idp->data, idp->size);
		if (lr == NULL)
			goto cleanup;

		/* Keeping link and title from link_ref. */

		link = lr->link;
		title = lr->title;
		if (lr->attrs != NULL && parse_ext_attrs
		    (lr->attrs->data, lr->attrs->size,
		     &attrid, &attrcls, &attrwidth, &attrheight) == 0)
			goto err;

		/* Rewinding the spacing. */

		i = txt_e + 1;
	}

	/* PHP markdown extra attributes (if not ref link). */

	if ((doc->ext_flags & LOWDOWN_ATTRS) && lr == NULL &&
	    i + 2 < size && data[i] == '{') {
		i++;

		/* Find trailing marker. */

		for (j = i; j < size && data[j] != '}'; j++)
			continue;
		j = parse_ext_attrs(&data[i], j - i,
			&attrid, &attrcls, &attrwidth, &attrheight);
		if (j == 0)
			goto err;
		i += j;
		if (i < size && data[i] == '}')
			i++;
	}

	n = pushnode(doc, is_img ? LOWDOWN_IMAGE : LOWDOWN_LINK);
	if (n == NULL)
		goto err;

	/*
	 * Building content: img alt is kept, only link content is
	 * parsed.
	 */

	if (txt_e > 1) {
		if ( ! is_img) {
			/*
			 * Disable autolinking when parsing inline the
			 * content of a link.
			 */
			doc->in_link_body = 1;
			if (!parse_inline(doc, data + 1, txt_e - 1))
				goto err;
			doc->in_link_body = 0;
		} else {
			if ((content = hbuf_new(64)) == NULL)
				goto err;
			if (!hbuf_put(content, data + 1, txt_e - 1))
				goto err;
		}
	}

	if (link) {
		if ((u_link = hbuf_new(64)) == NULL)
			goto err;
		if (!unscape_text(u_link, link))
			goto err;
	}

	/* Calling the relevant rendering function. */

	if (is_img) {
		if (u_link != NULL &&
		    !hbuf_createb(&n->rndr_image.link, u_link))
			goto err;
		if (title != NULL &&
		    !hbuf_createb(&n->rndr_image.title, title))
			goto err;
		if (dims != NULL &&
		    !hbuf_createb(&n->rndr_image.dims, dims))
			goto err;
		if (content != NULL &&
		    !hbuf_createb(&n->rndr_image.alt, content))
			goto err;
		if (attrcls != NULL &&
		    !hbuf_createb(&n->rndr_image.attr_cls, attrcls))
			goto err;
		if (attrid != NULL &&
		    !hbuf_createb(&n->rndr_image.attr_id, attrid))
			goto err;
		if (attrwidth != NULL &&
		    !hbuf_createb(&n->rndr_image.attr_width, attrwidth))
			goto err;
		if (attrheight != NULL &&
		    !hbuf_createb(&n->rndr_image.attr_height, attrheight))
			goto err;
		ret = 1;
	} else {
		if (u_link != NULL &&
		    !hbuf_createb(&n->rndr_link.link, u_link))
			goto err;
		if (title != NULL &&
		    !hbuf_createb(&n->rndr_link.title, title))
			goto err;
		if (attrcls != NULL &&
		    !hbuf_createb(&n->rndr_link.attr_cls, attrcls))
			goto err;
		if (attrid != NULL &&
		    !hbuf_createb(&n->rndr_link.attr_id, attrid))
			goto err;
		ret = 1;
	}

	popnode(doc, n);
	goto cleanup;
err:
	ret = -1;
cleanup:
	hbuf_free(attrid);
	hbuf_free(attrcls);
	hbuf_free(attrheight);
	hbuf_free(attrwidth);
	hbuf_free(linkp);
	hbuf_free(titlep);
	hbuf_free(dims);
	hbuf_free(idp);
	hbuf_free(content);
	hbuf_free(u_link);
	return ret > 0 ? (ssize_t)i : ret;
}

static ssize_t
char_superscript(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{
	size_t	 sup_start, sup_len;
	struct lowdown_node *n;

	if (size < 2)
		return 0;

	if (data[1] == '(') {
		sup_start = 2;
		sup_len = find_emph_char(data + 2, size - 2, ')') + 2;
		if (sup_len == size)
			return 0;
	} else {
		sup_start = sup_len = 1;
		while (sup_len < size && !xisspace(data[sup_len]))
			sup_len++;
	}

	if (sup_len - sup_start == 0)
		return (sup_start == 2) ? 3 : 0;

	if ((n = pushnode(doc, LOWDOWN_SUPERSCRIPT)) == NULL)
		return -1;
	if (!parse_inline(doc, data + sup_start, sup_len - sup_start))
		return -1;
	popnode(doc, n);
	return (sup_start == 2) ? sup_len + 1 : sup_len;
}

static ssize_t
char_math(struct lowdown_doc *doc,
	char *data, size_t offset, size_t size)
{

	return size > 1 && data[1] == '$' ?
		parse_math(doc, data, offset, size, "$$", 2, 1) :
		parse_math(doc, data, offset, size, "$", 1, 0);
}

/*
 * Returns the line length when it is empty, 0 otherwise.
 */
static size_t
is_empty(const char *data, size_t size)
{
	size_t	 i;

	for (i = 0; i < size && data[i] != '\n'; i++)
		if (data[i] != ' ')
			return 0;

	return i + 1;
}

/*
 * Returns whether a line is a horizontal rule.
 */
static int
is_hrule(const char *data, size_t size)
{
	size_t	 i = 0, n = 0;
	char	 c;

	/* Skipping initial spaces. */

	if (size < 3)
		return 0;

	i = countspaces(data, 0, size, 3);

	/* Looking at the hrule char. */

	if (i + 2 >= size ||
	    (data[i] != '*' && data[i] != '-' && data[i] != '_'))
		return 0;

	c = data[i];

	/* The whole line must be the char or space. */

	while (i < size && data[i] != '\n') {
		if (data[i] == c)
			n++;
		else if (data[i] != ' ')
			return 0;
		i++;
	}

	return n >= 3;
}

/*
 * Check if a line is a code fence; return the end of the code fence.
 * If passed, width of the fence rule and character will be returned.
 */
static size_t
is_codefence(const char *data, size_t size, size_t *width, char *chr)
{
	size_t	 i = 0, n = 1;
	char	 c;

	/* Skipping initial spaces. */

	if (size < 3)
		return 0;

	i = countspaces(data, 0, size, 3);

	/* Looking at the hrule char. */

	c = data[i];

	if (i + 2 >= size || !(c == '~' || c == '`'))
		return 0;

	/* The fence must be that same character. */

	while (++i < size && data[i] == c)
		++n;

	if (n < 3)
		return 0;

	if (width)
		*width = n;
	if (chr)
		*chr = c;

	return i;
}

/*
 * Expects single line, checks if it's a codefence and extracts
 * language.
 * Return zero if not a code-fence, >0 offset otherwise.
 */
static size_t
parse_codefence(char *data, size_t size,
	struct lowdown_buf *lang, size_t *width, char *chr)
{
	size_t		 i, w, lang_start;

	i = w = is_codefence(data, size, width, chr);

	if (i == 0)
		return 0;

	while (i < size && xisspace(data[i]))
		i++;

	lang_start = i;

	while (i < size && !xisspace(data[i]))
		i++;

	lang->data = data + lang_start;
	lang->size = i - lang_start;

	/* Avoid parsing a codespan as a fence */

	i = lang_start + 2;

	while (i < size &&
	       !(data[i] == *chr &&
		 data[i-1] == *chr &&
		 data[i-2] == *chr))
		i++;

	return i < size ? 0 : w;
}

/*
 * Returns whether the line is a hash-prefixed header.
 * Return zero if not an at-header, non-zero otherwise.
 */
static int
is_atxheader(const struct lowdown_doc *doc,
	const char *data, size_t size)
{
	size_t	 level;

	if (data[0] != '#')
		return 0;

	/*
	 * CommonMark requires a space.
	 * Classical Markdown does not.
	 */

	if (doc->ext_flags & LOWDOWN_COMMONMARK) {
		level = 0;
		while (level < size && level < 6 && data[level] == '#')
			level++;
		if (level < size && data[level] != ' ')
			return 0;
	}

	return 1;
}

/*
 * Tests for level 1 setext-style header ("=") or level 2 ("-").
 * Returns zero if it's not, non-zero otherwise.
 */
static int
is_headerline(const char *data, size_t size)
{
	size_t	 i;
	char	 hchr;
	int	 level;

	if ('=' == *data || '-' == *data) {
		level = '=' == *data ? 1 : 2;
		hchr = *data;
	} else
		return 0;

	for (i = 1; i < size && data[i] == hchr; i++)
		continue;
	i = countspaces(data, i, size, 0);

	return (i >= size || data[i] == '\n') ? level : 0;
}

static int
is_next_headerline(const char *data, size_t size)
{
	size_t	 i = 0;

	while (i < size && data[i] != '\n')
		i++;

	if (++i >= size)
		return 0;
	return is_headerline(data + i, size - i);
}

/*
 * Returns unordered list item prefix.
 * This does nothing if LOWDOWN_DEFLIST is not set.
 */
static size_t
prefix_dli(const struct lowdown_doc *doc, const char *data, size_t size)
{
	size_t i;

	if (!(doc->ext_flags & LOWDOWN_DEFLIST))
		return 0;

	i = countspaces(data, 0, size, 3);

	if (i + 1 >= size || data[i] != ':' || data[i + 1] != ' ')
		return 0;
	if (is_next_headerline(data + i, size - i))
		return 0;

	return i + 2;
}

/*
 * Returns blockquote prefix length.
 */
static size_t
prefix_quote(const char *data, size_t size)
{
	size_t i;

	i = countspaces(data, 0, size, 3);

	if (i < size && data[i] == '>')
		return countspaces(data, i + 1, size, 1);

	return 0;
}

/*
 * Returns prefix length for block code.
 */
static size_t
prefix_code(const char *data, size_t size)
{

	if (countspaces(data, 0, size, 4) == 4)
		return 4;

	return 0;
}

/*
 * Returns ordered list item prefix.
 * On success (return value >0) and if "value" is not NULL *and* we're
 * also commonmark processing, copy and NUL-terminate the value into it.
 * If all of those except for commonmark, simply NUL-terminate the
 * string.
 */
static size_t
prefix_oli(const struct lowdown_doc *doc,
	const char *data, size_t size, char *value)
{
	size_t 		 i, st, vsize;
	const char	*vdata;

	i = countspaces(data, 0, size, 3);

	if (i >= size || !isdigit((unsigned char)data[i]))
		return 0;

	st = i;
	vdata = &data[i];

	while (i < size && isdigit((unsigned char)data[i]))
		i++;

	/* Commonmark limits us to nine characters. */

	vsize = i - st;
	if ((doc->ext_flags & LOWDOWN_COMMONMARK) && vsize > 9)
		return 0;

	/*
	 * Commonmark accepts ')' and '.' following the numeric prefix,
	 * while regular markdown only has '.'.
	 */

	if (doc->ext_flags & LOWDOWN_COMMONMARK) {
		if (i + 1 >= size ||
		    (data[i] != '.' && data[i] != ')') ||
		    data[i + 1] != ' ')
			return 0;
	} else if (i + 1 >= size || data[i] != '.' || data[i + 1] != ' ')
		return 0;

	if (is_next_headerline(data + i, size - i))
		return 0;

	if (value != NULL) {
		if (doc->ext_flags & LOWDOWN_COMMONMARK) {
			assert(vsize > 0);
			assert(vsize < 10);
			memcpy(value, vdata, vsize);
			value[vsize] = '\0';
		} else
			value[0] = '\0';
	}

	return i + 2;
}

/*
 * Returns unordered list item prefix, including a GFM checkbox.  The
 * "checked" pointer, if not NULL, is set to whether the check is set
 * (>0), unset (=0), or not there (<0).
 */
static size_t
prefix_uli(const struct lowdown_doc *doc,
	const char *data, size_t size, int *checked)
{
	size_t	 i;

	if (checked != NULL)
		*checked = -1;

	i = countspaces(data, 0, size, 3);

	if (i + 1 >= size ||
	    (data[i] != '*' && data[i] != '+' &&
	     data[i] != '-') ||
	    data[i + 1] != ' ')
		return 0;

	if (is_next_headerline(data + i, size - i))
		return 0;

	if (!(doc->ext_flags & LOWDOWN_TASKLIST) || i + 5 >= size)
		return i + 2;

	if (data[i + 2] == '[' &&
	    (data[i + 3] == ' ' ||
	     data[i + 3] == 'x' ||
	     data[i + 3] == 'X') &&
	    data[i + 4] == ']' &&
	    data[i + 5] == ' ') {
		if (checked != NULL)
			*checked = data[i + 3] != ' ';
		return i + 6;
	}

	return i + 2;
}

/*
 * Handles parsing of a blockquote fragment.
 * Return <0 on failure, otherwise the end offset.
 */
static ssize_t
parse_blockquote(struct lowdown_doc *doc, char *data, size_t size)
{
	size_t			 beg = 0, end = 0, pre, work_size = 0;
	char			*work_data = NULL;
	struct lowdown_node	*n;

	while (beg < size) {
		for (end = beg + 1;
		     end < size && data[end - 1] != '\n';
		     end++)
			continue;

		pre = prefix_quote(data + beg, end - beg);

		/* Skip prefix or empty line followed by non-quote. */

		if (pre)
			beg += pre;
		else if (is_empty(data + beg, end - beg) &&
			 (end >= size ||
			  (prefix_quote(data + end, size - end) == 0 &&
			   !is_empty(data + end, size - end))))
			break;

		if (beg < end) {
			if (!work_data)
				work_data = data + beg;
			else if (data + beg != work_data + work_size)
				memmove(work_data + work_size,
					data + beg, end - beg);
			work_size += end - beg;
		}
		beg = end;
	}

	n = pushnode(doc, LOWDOWN_BLOCKQUOTE);
	if (n == NULL)
		return -1;
	if (!parse_block(doc, work_data, work_size))
		return -1;
	popnode(doc, n);
	return end;
}

/*
 * Handles parsing of a regular paragraph, which terminates at sections
 * or blank lines.
 * Returns <0 on failure or the number of characters parsed from the
 * paragraph input.
 */
static ssize_t
parse_paragraph(struct lowdown_doc *doc, char *data, size_t size)
{
	struct lowdown_buf	 work;
	struct lowdown_node 	*n;
	size_t		 	 i = 0, end = 0, beg, lines = 0;
	int		 	 level = 0, beoln = 0;

	memset(&work, 0, sizeof(struct lowdown_buf));
	work.data = data;

	while (i < size) {
		/* Parse ahead to the next newline. */

		for (end = i + 1;
		     end < size && data[end - 1] != '\n'; end++)
			continue;

		/*
		 * Empty line: end of paragraph.
		 * However, check if we have a dli prefix following
		 * that, which means that we're a block-mode dli.
		 */

		if (is_empty(data + i, size - i)) {
			beoln = 1;
			break;
		}

		/* Header line: end of paragraph. */

		if ((level = is_headerline(data + i, size - i)) != 0)
			break;

		/* Other ways of ending a paragraph. */

		if (is_atxheader(doc, data + i, size - i) ||
		    is_hrule(data + i, size - i) ||
		    (lines == 1 &&
		     prefix_dli(doc, data + i, size - i)) ||
		    prefix_quote(data + i, size - i)) {
			end = i;
			break;
		}

		lines++;
		i = end;
	}

	work.size = i;

	while (work.size && data[work.size - 1] == '\n')
		work.size--;

	/*
	 * The paragraph isn't ending on a header line.
	 * So it's a regular paragraph.
	 */

	if (!level) {
		n = pushnode(doc, LOWDOWN_PARAGRAPH);
		if (n == NULL)
			return -1;
		n->rndr_paragraph.lines = lines;
		n->rndr_paragraph.beoln = beoln;
		if (!parse_inline(doc, work.data, work.size))
			return -1;
		popnode(doc, n);
		return end;
	}

	/* Paragraph material prior to header break. */
	
	if (work.size) {
		i = work.size;
		work.size -= 1;
		while (work.size && data[work.size] != '\n')
			work.size -= 1;
		beg = work.size + 1;
		while (work.size && data[work.size - 1] == '\n')
			work.size -= 1;

		if (work.size > 0) {
			n = pushnode(doc, LOWDOWN_PARAGRAPH);
			if (n == NULL)
				return -1;
			n->rndr_paragraph.lines = lines - 1;
			n->rndr_paragraph.beoln = beoln;
			if (!parse_inline(doc, work.data, work.size))
				return -1;
			popnode(doc, n);
			work.data += beg;
			work.size = i - beg;
		} else
			work.size = i;
	}

	/* Definition data parts. */

	if ((n = pushnode(doc, LOWDOWN_HEADER)) == NULL)
		return -1;
	assert(level > 0);
	n->rndr_header.level = level - 1;
	if (!parse_inline(doc, work.data, work.size))
		return -1;
	popnode(doc, n);

	if ((doc->ext_flags & LOWDOWN_ATTRS) &&
	    !parse_header_ext_attrs(n))
		return -1;

	return end;
}

/*
 * Handles parsing of a block-level code fragment.
 * Return <0 on failure, 0 if not a fragment, >0 on success.
 */
static ssize_t
parse_fencedcode(struct lowdown_doc *doc, char *data, size_t size)
{
	struct lowdown_buf	 text, lang;
	size_t	 		 i = 0, text_start, line_start,
				 w, w2, width, width2;
	char	 		 chr, chr2;
	struct lowdown_node 	*n;

	memset(&text, 0, sizeof(struct lowdown_buf));
	memset(&lang, 0, sizeof(struct lowdown_buf));

	/* Parse codefence line. */

	while (i < size && data[i] != '\n')
		i++;
	if ((w = parse_codefence(data, i, &lang, &width, &chr)) == 0)
		return 0;

	/* Search for end. */

	i++;
	text_start = i;
	while ((line_start = i) < size) {
		while (i < size && data[i] != '\n')
			i++;
		w2 = is_codefence(data + line_start,
			i - line_start, &width2, &chr2);
		if (w == w2 &&
		    width == width2 &&
		    chr == chr2 &&
		    is_empty(data +
		    (line_start+w), i - (line_start+w)))
			break;
		i++;
	}

	text.data = data + text_start;
	text.size = line_start - text_start;

	if ((n = pushnode(doc, LOWDOWN_BLOCKCODE)) == NULL)
		return -1;

	if (!hbuf_create(&n->rndr_blockcode.text,
	    data + text_start, line_start - text_start))
		return -1;
	if (!hbuf_createb(&n->rndr_blockcode.lang, &lang))
		return -1;
	popnode(doc, n);
	return i;
}

static ssize_t
parse_blockcode(struct lowdown_doc *doc, char *data, size_t size)
{
	size_t	 		 beg = 0, end, pre;
	struct lowdown_buf	*work = NULL;
	struct lowdown_node 	*n;

	if ((work = hbuf_new(256)) == NULL)
		goto err;

	while (beg < size) {
		for (end = beg + 1;
		     end < size && data[end - 1] != '\n';
		     end++)
			continue;

		pre = prefix_code(data + beg, end - beg);

		/*
		 * Skip prefix or non-empty non-prefixed line breaking
		 * the pre.
		 */

		if (pre)
			beg += pre;
		else if (!is_empty(data + beg, end - beg))
			break;

		/*
		 * Verbatim copy to the working buffer, escaping
		 * entities.
		 */

		if (beg < end) {
			if (is_empty(data + beg, end - beg)) {
				if (!hbuf_putc(work, '\n'))
					goto err;
			} else {
				if (!hbuf_put(work,
				    data + beg, end - beg))
					goto err;
			}
		}
		beg = end;
	}

	while (work->size && work->data[work->size - 1] == '\n')
		work->size -= 1;

	if (!hbuf_putc(work, '\n'))
		goto err;

	if ((n = pushnode(doc, LOWDOWN_BLOCKCODE)) == NULL)
		goto err;
	if (!hbuf_createb(&n->rndr_blockcode.text, work))
		goto err;
	popnode(doc, n);
	hbuf_free(work);
	return beg;
err:
	hbuf_free(work);
	return -1;
}

/*
 * Parsing of a single list item assuming initial prefix is already
 * removed.
 */
static ssize_t
parse_listitem(struct lowdown_buf *ob, struct lowdown_doc *doc,
	char *data, size_t size, enum hlist_fl *flags, size_t num)
{
	struct lowdown_buf	*work = NULL;
	size_t			 beg = 0, end, pre, sublist = 0,
				 orgpre, i, has_next_uli = 0, dli_lines,
				 has_next_oli = 0, has_next_dli = 0;
	int			 in_empty = 0, has_inside_empty = 0,
				 in_fence = 0, ff, checked = -1;
	struct lowdown_node	*n;

	/* Keeping track of the first indentation prefix. */

	orgpre = countspaces(data, 0, size, 3);

	beg = prefix_uli(doc, data, size, &checked);

	if (!beg)
		beg = prefix_oli(doc, data, size, NULL);
	if (!beg)
		beg = prefix_dli(doc, data, size);
	if (!beg)
		return 0;

	/* Skipping to the beginning of the following line. */

	end = beg;
	while (end < size && data[end - 1] != '\n')
		end++;

	/* Getting working buffers. */

	if ((work = hbuf_new(64)) == NULL)
		goto err;

	/* Putting the first line into the working buffer. */

	if (!hbuf_put(work, data + beg, end - beg))
		goto err;
	beg = end;
	dli_lines = 1;

	/*
	 * Process the following lines.
	 * Use the "dli_lines" variable to see if we should consider an
	 * opening dli prefix to be a valid dli token.
	 */

	while (beg < size) {
		has_next_uli = has_next_oli = has_next_dli = 0;
		end++;

		while (end < size && data[end - 1] != '\n')
			end++;

		/* Process an empty line. */

		if (is_empty(data + beg, end - beg)) {
			in_empty = 1;
			beg = end;
			dli_lines = 0;
			continue;
		}

		dli_lines++;

		/* Calculating the indentation. */

		pre = i = countspaces(data, beg, end, 4) - beg;

		if (doc->ext_flags & LOWDOWN_FENCED)
			if (is_codefence(data + beg + i,
			    end - beg - i, NULL, NULL))
				in_fence = !in_fence;

		/*
		 * Only check for new list items if we are **not**
		 * inside a fenced code block.
		 * We only allow dli if we've had a single line of
		 * content beforehand.
		 */

		if (!in_fence) {
			has_next_uli = prefix_uli(doc,
				data + beg + i, end - beg - i, NULL);
			has_next_dli =  dli_lines <= 2 && prefix_dli
				(doc, data + beg + i, end - beg - i);
			has_next_oli = prefix_oli
				(doc, data + beg + i, end - beg - i, NULL);
			if (has_next_uli || has_next_dli || has_next_oli)
				dli_lines = 0;
		}

		/* Checking for a new item. */

		if ((has_next_uli &&
		     !is_hrule(data + beg + i, end - beg - i)) ||
		    has_next_oli || has_next_dli) {
			if (in_empty)
				has_inside_empty = 1;

			/*
			 * The following item must have the same (or
			 * less) indentation.
			 */

			if (pre <= orgpre) {
				/*
				 * If the following item has different
				 * list type, we end this list.
				 */

				ff = *flags & HLIST_FL_MASK;
				assert(ff == HLIST_FL_ORDERED ||
				       ff == HLIST_FL_UNORDERED ||
				       ff == HLIST_FL_DEF);

				if (in_empty &&
				    (((ff == HLIST_FL_ORDERED) &&
				      (has_next_uli || has_next_dli)) ||
				     ((ff == HLIST_FL_UNORDERED) &&
				      (has_next_oli || has_next_dli)) ||
				     ((ff == HLIST_FL_DEF) &&
				      (has_next_oli || has_next_uli)))) {
					*flags |= HLIST_LI_END;
				}

				break;
			}

			if (!sublist)
				sublist = work->size;
		} else if (in_empty && pre == 0) {
			/*
			 * Joining only indented stuff after empty
			 * lines; note that now we only require 1 space
			 * of indentation to continue a list.
			 */

			*flags |= HLIST_LI_END;
			break;
		}

		if (in_empty) {
			if (!hbuf_putc(work, '\n'))
				goto err;
			has_inside_empty = 1;
			in_empty = 0;
		}

		/*
		 * Adding the line without prefix into the working
		 * buffer.
		 */

		if (!hbuf_put(work, data + beg + i, end - beg - i))
			goto err;
		beg = end;
	}

	/* Render of li contents. */

	if (has_inside_empty)
		*flags |= HLIST_FL_BLOCK;

	if ((n = pushnode(doc, LOWDOWN_LISTITEM)) == NULL)
		goto err;
	n->rndr_listitem.flags = *flags;
	n->rndr_listitem.num = num;

	if (checked > 0)
		n->rndr_listitem.flags |= HLIST_FL_CHECKED;
	else if (checked == 0)
		n->rndr_listitem.flags |= HLIST_FL_UNCHECKED;

	if (*flags & HLIST_FL_BLOCK) {
		/* Intermediate render of block li. */

		if (sublist && sublist < work->size) {
			if (!parse_block(doc,
			    work->data, sublist))
				goto err;
			if (!parse_block(doc,
			    work->data + sublist,
			    work->size - sublist))
				goto err;
		} else {
			if (!parse_block(doc,
			    work->data, work->size))
				goto err;
		}
	} else {
		/* Intermediate render of inline li. */

		if (sublist && sublist < work->size) {
			if (!parse_inline(doc,
			    work->data, sublist))
				goto err;
			if (!parse_block(doc,
			    work->data + sublist,
			    work->size - sublist))
				goto err;
		} else {
			if (!parse_inline(doc,
			    work->data, work->size))
				goto err;
		}
	}

	popnode(doc, n);
	hbuf_free(work);
	return beg;
err:
	hbuf_free(work);
	return -1;
}

/*
 * Parse definition list.
 * This must follow a single-line paragraph, which it integrates as the
 * title of the list.
 * (The paragraph can contain arbitrary styling.)
 */
static ssize_t
parse_definition(struct lowdown_doc *doc, char *data, size_t size)
{
	struct lowdown_buf   	*work = NULL;
	size_t			 i = 0, k = 1;
	ssize_t			 ret;
	enum hlist_fl		 flags = HLIST_FL_DEF;
	struct lowdown_node	*n, *nn, *cur, *prev;

	if ((work = hbuf_new(256)) == NULL)
		goto err;

	/* Record whether we want to start in block mode. */

	cur = TAILQ_LAST(&doc->current->children, lowdown_nodeq);
	if (cur->rndr_paragraph.beoln)
		flags |= HLIST_FL_BLOCK;

	/* Do we need to merge into a previous definition list? */

	prev = TAILQ_PREV(cur, lowdown_nodeq, entries);

	if (prev != NULL && prev->type == LOWDOWN_DEFINITION) {
		n = doc->current = prev;
		flags |= n->rndr_definition.flags;
		doc->depth++;
	} else {
		n = pushnode(doc, LOWDOWN_DEFINITION);
		if (n == NULL)
			goto err;
		n->rndr_definition.flags = flags;
	}

	TAILQ_REMOVE(&cur->parent->children, cur, entries);
	TAILQ_INSERT_TAIL(&n->children, cur, entries);
	cur->type = LOWDOWN_DEFINITION_TITLE;
	cur->parent = n;

	while (i < size) {
		nn = pushnode(doc, LOWDOWN_DEFINITION_DATA);
		if (nn == NULL)
			goto err;
		ret = parse_listitem(work, doc,
			data + i, size - i, &flags, k++);
		if (ret < 0)
			goto err;
		i += ret;
		popnode(doc, nn);
		if (ret == 0 || (flags & HLIST_LI_END))
			break;
	}

	if (flags & HLIST_FL_BLOCK)
		n->rndr_definition.flags |= HLIST_FL_BLOCK;

	popnode(doc, n);
	hbuf_free(work);
	return i;
err:
	hbuf_free(work);
	return -1;
}

/*
 * Parsing ordered or unordered list block.
 * If "oli_data" is not NULL, it's the numeric string prefix of the
 * ordered entry.  It's either zero-length or well-formed.
 */
static ssize_t
parse_list(struct lowdown_doc *doc,
	char *data, size_t size, const char *oli_data)
{
	struct lowdown_buf	*work = NULL;
	size_t	 	     	 i = 0, pos;
	ssize_t			 ret;
	enum hlist_fl	     	 flags;
	struct lowdown_node 	*n;

	flags = oli_data != NULL ?
		HLIST_FL_ORDERED : HLIST_FL_UNORDERED;
	if ((work = hbuf_new(256)) == NULL)
		goto err;
	if ((n = pushnode(doc, LOWDOWN_LIST)) == NULL)
		goto err;
	n->rndr_list.start = 1;
	n->rndr_list.flags = flags;

	if (oli_data != NULL && oli_data[0] != '\0') {
		n->rndr_list.start = strtonum
			(oli_data, 0, UINT32_MAX, NULL);
		if (n->rndr_list.start == 0)
			n->rndr_list.start = 1;
	}

	pos = n->rndr_list.start;
	while (i < size) {
		ret = parse_listitem(work, doc,
			data + i, size - i, &flags, pos++);
		if (ret < 0)
			goto err;
		i += ret;
		if (ret == 0 || (flags & HLIST_LI_END))
			break;
	}

	if (flags & HLIST_FL_BLOCK)
		n->rndr_list.flags |= HLIST_FL_BLOCK;

	popnode(doc, n);
	hbuf_free(work);
	return i;
err:
	hbuf_free(work);
	return -1;
}

/*
 * Parsing of atx-style headers.
 */
static ssize_t
parse_atxheader(struct lowdown_doc *doc, char *data, size_t size)
{
	size_t 	 		 level = 0, i, end, skip;
	struct lowdown_node	*n;

	while (level < size && level < 6 && data[level] == '#')
		level++;

	i = countspaces(data, level, size, 0);

	for (end = i; end < size && data[end] != '\n'; end++)
		continue;

	skip = end;

	while (end && data[end - 1] == '#')
		end--;

	while (end && data[end - 1] == ' ')
		end--;

	if (end > i) {
		if ((n = pushnode(doc, LOWDOWN_HEADER)) == NULL)
			return -1;
		assert(level > 0);
		n->rndr_header.level = level - 1;
		if (!parse_inline(doc, data + i, end - i))
			return -1;
		popnode(doc, n);
		if ((doc->ext_flags & LOWDOWN_ATTRS) &&
		    !parse_header_ext_attrs(n))
			return -1;
	}

	return skip;
}

/*
 * Check for end of HTML block : </tag>( *)\n
 * Returns tag length on match, 0 otherwise.
 * Assumes data starts with "<".
 */
static size_t
htmlblock_is_end(const char *tag, size_t tag_len,
	struct lowdown_doc *doc, const char *data, size_t size)
{
	size_t i = tag_len + 3, w;

	/*
	 * Try to match the end tag
	 * Note: we're not considering tags like "</tag >" which are
	 * still valid.
	 */

	if (i > size ||
	    data[1] != '/' ||
	    strncasecmp(data + 2, tag, tag_len) != 0 ||
	    data[tag_len + 2] != '>')
		return 0;

	/* Rest of the line must be empty. */

	if ((w = is_empty(data + i, size - i)) == 0 && i < size)
		return 0;

	return i + w;
}

/*
 * Try to find HTML block ending tag.
 * Returns the length on match, 0 otherwise.
 */
static size_t
htmlblock_find_end(const char *tag, size_t tag_len,
	struct lowdown_doc *doc, const char *data, size_t size)
{
	size_t	i, w = 0;

	for (i = 0; ; i++) {
		while (i < size && data[i] != '<')
			i++;
		if (i >= size)
			return 0;
		w = htmlblock_is_end(tag,
			tag_len, doc, data + i, size - i);
		if (w)
			break;
	}

	return i + w;
}

/*
 * Try to find end of HTML block in strict mode (it must be an
 * unindented line, and have a blank line afterwards). 
 * Returns the length on match, 0 otherwise.
 */
static size_t
htmlblock_find_end_strict(const char *tag, size_t tag_len,
	struct lowdown_doc *doc, const char *data, size_t size)
{
	size_t i = 0, mark;

	while (1) {
		mark = i;
		while (i < size && data[i] != '\n')
			i++;
		if (i < size)
			i++;
		if (i == mark)
			return 0;

		if (data[mark] == ' ' && mark > 0)
			continue;
		mark += htmlblock_find_end(tag, tag_len,
			doc, data + mark, i - mark);
		if (mark == i &&
		    (is_empty(data + i, size - i) || i >= size))
			break;
	}

	return i;
}

/*
 * Canonicalise a sequence of length "len" bytes in "str".
 * This returns NULL if the sequence is not recognised, or a
 * nil-terminated string of the sequence otherwise.
 */
static const char *
hhtml_find_block(const char *str, size_t len)
{
	size_t			 i;
	static const char	*tags[] = {
		"address",
		"article",
		"aside",
		"blockquote",
		"del",
		"details",
		"dialog",
		"dd",
		"div",
		"dl",
		"dt",
		"fieldset",
		"figcaption",
		"figure",
		"footer",
		"form",
		"h1",
		"h2",
		"h3",
		"h4",
		"h5",
		"h6",
		"header",
		"hgroup",
		"iframe",
		"ins",
		"li",
		"main",
		"math",
		"nav",
		"noscript",
		"ol",
		"p",
		"pre",
		"section",
		"script",
		"style",
		"table",
		"ul",
		NULL,
	};

	for (i = 0; tags[i] != NULL; i++)
		if (strncasecmp(tags[i], str, len) == 0)
			return tags[i];

	return NULL;
}

/*
 * Parsing of inline HTML block.
 * Return <0 on failure, >0 on success, 0 if not a block.
 */
static ssize_t
parse_htmlblock(struct lowdown_doc *doc, char *data, size_t size)
{
	struct lowdown_buf	 work;
	size_t	 	 	 i, j = 0, tag_len, tag_end;
	const char		*curtag = NULL;
	struct lowdown_node 	*n;

	memset(&work, 0, sizeof(struct lowdown_buf));

	work.data = data;

	/* Identification of the opening tag. */

	if (size < 2 || data[0] != '<')
		return 0;

	i = 1;
	while (i < size && data[i] != '>' && data[i] != ' ')
		i++;
	if (i < size)
		curtag = hhtml_find_block(data + 1, i - 1);

	/* Handling of special cases. */

	if (!curtag) {
		/* HTML comment, laxist form. */

		if (size > 5 && data[1] == '!' &&
		    data[2] == '-' && data[3] == '-') {
			i = 5;
			while (i < size && !(data[i - 2] == '-' &&
			       data[i - 1] == '-' && data[i] == '>'))
				i++;
			i++;

			if (i < size)
				j = is_empty(data + i, size - i);

			if (j) {
				n = pushnode(doc, LOWDOWN_BLOCKHTML);
				if (n == NULL)
					return -1;
				work.size = i + j;
				if (!hbuf_createb
				    (&n->rndr_blockhtml.text, &work))
					return -1;
				popnode(doc, n);
				return work.size;
			}
		}

		/*
		 * HR, which is the only self-closing block tag
		 * considered.
		 * FIXME: we should also do <br />.
		 */

		if (size > 4 &&
		    (data[1] == 'h' || data[1] == 'H') &&
		    (data[2] == 'r' || data[2] == 'R')) {
			i = 3;
			while (i < size && data[i] != '>')
				i++;
			if (i + 1 < size) {
				i++;
				j = is_empty(data + i, size - i);
				if (j) {
					n = pushnode(doc,
						LOWDOWN_BLOCKHTML);
					if (n == NULL)
						return -1;
					work.size = i + j;
					if (!hbuf_createb
					    (&n->rndr_blockhtml.text,
					     &work))
						return -1;
					popnode(doc, n);
					return work.size;
				}
			}
		}

		/* No special case recognised. */

		return 0;
	}

	/* Looking for a matching closing tag in strict mode. */

	tag_len = strlen(curtag);
	tag_end = htmlblock_find_end_strict
		(curtag, tag_len, doc, data, size);

	/*
	 * If not found, trying a second pass looking for indented match
	 * but not if tag is "ins" or "del" (following original
	 * Markdown.pl).
	 */

	if (!tag_end &&
	    strcmp(curtag, "ins") != 0 &&
	    strcmp(curtag, "del") != 0)
		tag_end = htmlblock_find_end(curtag,
			tag_len, doc, data, size);

	if (!tag_end)
		return 0;

	/* The end of the block has been found. */

	n = pushnode(doc, LOWDOWN_BLOCKHTML);
	if (n == NULL)
		return -1;

	work.size = tag_end;
	if (!hbuf_createb(&n->rndr_blockhtml.text, &work))
		return -1;
	popnode(doc, n);
	return tag_end;
}

/*
 * Parse a table row.
 * Return zero on failure, non-zero on success.
 */
static int
parse_table_row(struct lowdown_buf *ob, struct lowdown_doc *doc,
	char *data, size_t size, size_t columns,
	const enum htbl_flags *col_data, enum htbl_flags header_flag)
{
	size_t	 		 i = 0, col, len, cell_start, cell_end;
	struct lowdown_buf	 empty_cell;
	struct lowdown_node	*n, *nn;

	if (i < size && data[i] == '|')
		i++;

	if ((n = pushnode(doc, LOWDOWN_TABLE_ROW)) == NULL)
		return 0;

	for (col = 0; col < columns && i < size; ++col) {
		while (i < size && xisspace(data[i]))
			i++;

		cell_start = i;

		len = find_emph_char(data + i, size - i, '|');

		/*
		 * Two possibilities for len == 0:
		 * (1) No more pipe char found in the current line.
		 * (2) The next pipe is right after the current one,
		 * i.e. empty cell.
		 * For case 1, we skip to the end of line; for case 2 we
		 * just continue.
		 */

		if (len == 0 && i < size && data[i] != '|')
			len = size - i;
		i += len;

		cell_end = i - 1;

		while (cell_end > cell_start &&
		       xisspace(data[cell_end]))
			cell_end--;

		nn = pushnode(doc, LOWDOWN_TABLE_CELL);
		if (nn == NULL)
			return 0;

		nn->rndr_table_cell.flags = col_data[col] | header_flag;
		nn->rndr_table_cell.col = col;
		nn->rndr_table_cell.columns = columns;

		if (!parse_inline(doc,
		    data + cell_start, 1 + cell_end - cell_start))
			return 0;
		popnode(doc, nn);
		i++;
	}

	for ( ; col < columns; ++col) {
		memset(&empty_cell, 0, sizeof(struct lowdown_buf));
		nn = pushnode(doc, LOWDOWN_TABLE_CELL);
		if (nn == NULL)
			return 0;
		nn->rndr_table_cell.flags = col_data[col] | header_flag;
		nn->rndr_table_cell.col = col;
		nn->rndr_table_cell.columns = columns;
		popnode(doc, nn);
	}

	popnode(doc, n);
	return 1;
}

/*
 * Parse the initial line of a table.
 * Return <0 on failure, 0 if not a table row, >0 for the offset.
 */
static ssize_t
parse_table_header(struct lowdown_node **np,
	struct lowdown_buf *ob, struct lowdown_doc *doc,
	char *data, size_t size, size_t *columns,
	enum htbl_flags **column_data)
{
	size_t	 		 i = 0, col, header_end, under_end,
				 dashes;
	ssize_t	 		 pipes = 0;
	struct lowdown_node	*n;

	while (i < size && data[i] != '\n')
		if (data[i++] == '|')
			pipes++;

	if (i == size || pipes == 0)
		return 0;

	header_end = i;

	while (header_end > 0 && xisspace(data[header_end - 1]))
		header_end--;

	if (data[0] == '|')
		pipes--;

	if (header_end && data[header_end - 1] == '|')
		pipes--;

	if (pipes < 0)
		return 0;

	*columns = pipes + 1;
	*column_data = calloc(*columns, sizeof(enum htbl_flags));
	if (*column_data == NULL)
		return -1;

	/* Parse the header underline */

	i++;
	if (i < size && data[i] == '|')
		i++;

	under_end = i;
	while (under_end < size && data[under_end] != '\n')
		under_end++;

	for (col = 0; col < *columns && i < under_end; ++col) {
		dashes = 0;
		i = countspaces(data, i, under_end, 0);

		if (data[i] == ':') {
			i++;
			(*column_data)[col] |= HTBL_FL_ALIGN_LEFT;
			dashes++;
		}

		while (i < under_end && data[i] == '-') {
			i++;
			dashes++;
		}

		if (i < under_end && data[i] == ':') {
			i++;
			(*column_data)[col] |= HTBL_FL_ALIGN_RIGHT;
			dashes++;
		}

		i = countspaces(data, i, under_end, 0);

		if (i < under_end && data[i] != '|' && data[i] != '+')
			break;

		if (dashes < 3)
			break;

		i++;
	}

	if (col < *columns)
		return 0;

	/* (This calls pushnode for the table row.) */

	*np = pushnode(doc, LOWDOWN_TABLE_BLOCK);
	if (*np == NULL)
		return -1;

	(*np)->rndr_table.columns = *columns;

	n = pushnode(doc, LOWDOWN_TABLE_HEADER);
	if (n == NULL)
		return -1;

	n->rndr_table_header.flags = calloc
		(*columns, sizeof(enum htbl_flags));
	if (n->rndr_table_header.flags == NULL)
		return -1;

	for (i = 0; i < *columns; i++)
		n->rndr_table_header.flags[i] = (*column_data)[i];
	n->rndr_table_header.columns = *columns;

	if (!parse_table_row(ob, doc, data, header_end,
	    *columns, *column_data, HTBL_FL_HEADER))
		return -1;

	popnode(doc, n);
	return under_end + 1;
}

/*
 * Parse a table block.
 * Return <0 on failure, zero if not a table, >0 offset otherwise.
 */
static ssize_t
parse_table(struct lowdown_doc *doc, char *data, size_t size)
{
	size_t		 	 i, columns, row_start, pipes;
	ssize_t			 ret;
	struct lowdown_buf 	*header_work = NULL, *body_work = NULL;
	enum htbl_flags		*col_data = NULL;
	struct lowdown_node	*n = NULL, *nn;

	if ((header_work = hbuf_new(64)) == NULL ||
	    (body_work = hbuf_new(256)) == NULL)
		goto err;

	ret = parse_table_header(&n, header_work,
		doc, data, size, &columns, &col_data);
	if (ret < 0)
		goto err;

	if ((i = ret) > 0) {
		nn = pushnode(doc, LOWDOWN_TABLE_BODY);
		if (nn == NULL)
			goto err;
		while (i < size) {
			pipes = 0;
			row_start = i;

			while (i < size && data[i] != '\n')
				if (data[i++] == '|')
					pipes++;

			if (pipes == 0 || i == size) {
				i = row_start;
				break;
			}

			if (!parse_table_row(body_work,
			     doc, data + row_start, i - row_start,
			     columns, col_data, 0))
				goto err;
			i++;
		}

		popnode(doc, nn);
		popnode(doc, n);
	}

	free(col_data);
	hbuf_free(header_work);
	hbuf_free(body_work);
	return i;
err:
	free(col_data);
	hbuf_free(header_work);
	hbuf_free(body_work);
	return -1;
}

/*
 * Parsing of one block, returning next char to parse.
 * We can assume, entering the block, that our output is newline
 * aligned.
 * Return zero on failure, non-zero on success.
 */
static int
parse_block(struct lowdown_doc *doc, char *data, size_t size)
{
	size_t	 		 beg = 0, end, i;
	char			*txt_data;
	char			 oli_data[10];
	struct lowdown_node	*n;
	ssize_t			 rc;

	/*
	 * What kind of block are we?
	 * Go through all types of blocks, one by one.
	 */

	while (beg < size) {
		txt_data = data + beg;
		end = size - beg;

		/* We are at a #header. */

		if (is_atxheader(doc, txt_data, end)) {
			rc = parse_atxheader(doc, txt_data, end);
			if (rc < 0)
				return 0;
			assert(rc > 0);
			beg += rc;
			continue;
		}

		/* We have some <HTML>. */

		if (data[beg] == '<') {
			rc = parse_htmlblock(doc, txt_data, end);
			if (rc > 0) {
				beg += rc;
				continue;
			} else if (rc < 0)
				return 0;
		}

		/* Empty line. */

		if ((i = is_empty(txt_data, end)) != 0) {
			beg += i;
			continue;
		}

		/* Horizontal rule. */

		if (is_hrule(txt_data, end)) {
			n = pushnode(doc, LOWDOWN_HRULE);
			if (n == NULL)
				return 0;
			while (beg < size && data[beg] != '\n')
				beg++;
			beg++;
			popnode(doc, n);
			continue;
		}

		/* Fenced code. */

		if (doc->ext_flags & LOWDOWN_FENCED) {
			rc = parse_fencedcode(doc, txt_data, end);
			if (rc > 0) {
				beg += rc;
				continue;
			} else if (rc < 0)
				return 0;

		}
		
		/* Table parsing. */

		if (doc->ext_flags & LOWDOWN_TABLES) {
			rc = parse_table(doc, txt_data, end);
			if (rc > 0) {
				beg += rc;
				continue;
			} else if (rc < 0)
				return 0;

		}

		/* We're a > block quote. */

		if (prefix_quote(txt_data, end)) {
			rc = parse_blockquote(doc, txt_data, end);
			if (rc < 0)
				return 0;
			beg += rc;
			continue;
		}

		/* Prefixed code (like block-quotes). */

		if (!(doc->ext_flags & LOWDOWN_NOCODEIND) &&
		    prefix_code(txt_data, end)) {
			rc = parse_blockcode(doc, txt_data, end);
			if (rc < 0)
				return 0;
			beg += rc;
			continue;
		}

		/* Some sort of unordered list. */

		if (prefix_uli(doc, txt_data, end, NULL)) {
			rc = parse_list(doc, txt_data, end, NULL);
			if (rc < 0)
				return 0;
			beg += rc;
			continue;
		}

		/*
		 * A definition list.
		 * Only use this is preceded by a one-line paragraph.
		 */

		if (doc->current != NULL &&
		    prefix_dli(doc, txt_data, end)) {
			n = TAILQ_LAST(&doc->current->children,
				lowdown_nodeq);
			if (n != NULL &&
			    n->type == LOWDOWN_PARAGRAPH &&
			    n->rndr_paragraph.lines == 1) {
				rc = parse_definition(doc, txt_data, end);
				if (rc < 0)
					return 0;
				beg += rc;
				continue;
			}
		}

		/* An ordered list. */

		if (prefix_oli(doc, txt_data, end, oli_data)) {
			rc = parse_list(doc, txt_data, end, oli_data);
			if (rc < 0)
				return 0;
			beg += rc;
			continue;
		}

		/* No match: just a regular paragraph. */

		if ((rc = parse_paragraph(doc, txt_data, end)) < 0)
			return 0;
		beg += rc;
	}

	return 1;
}

/*
 * Returns >0 if a line is a footnote definition, 0 if not, <0 on
 * failure.  This gathers any footnote content into the footq footnote
 * queue.
 */
static int
is_footnote(struct lowdown_doc *doc, const char *data,
	size_t beg, size_t end, size_t *last)
{
	size_t	 		 i = 0, ind = 0, start = 0,
				 id_offs, id_end;
	struct lowdown_buf	*contents = NULL;
	int			 in_empty = 0;
	struct foot_ref		*ref = NULL;

	/* up to 3 optional leading spaces */

	if (beg + 3 >= end)
		return 0;
	i = countspaces(data, beg, end, 3);

	/* id part: caret followed by anything between brackets */

	if (data[i] != '[')
		return 0;
	i++;
	if (i >= end || data[i] != '^')
		return 0;
	i++;
	id_offs = i;
	while (i < end && data[i] != '\n' &&
	       data[i] != '\r' && data[i] != ']')
		i++;
	if (i >= end || data[i] != ']')
		return 0;
	id_end = i;

	/* spacer: colon (space | tab)* newline? (space | tab)* */

	i++;
	if (i >= end || data[i] != ':')
		return 0;
	i++;

	/* getting content buffer */

	if ((contents = hbuf_new(64)) == NULL)
		return -1;

	start = i;

	/* process lines similar to a list item */

	while (i < end) {
		while (i < end && data[i] != '\n' && data[i] != '\r')
			i++;

		/* process an empty line */

		if (is_empty(data + start, i - start)) {
			in_empty = 1;
			if (i < end &&
			    (data[i] == '\n' || data[i] == '\r')) {
				i++;
				if (i < end && data[i] == '\n' &&
				    data[i - 1] == '\r')
					i++;
			}
			start = i;
			continue;
		}

		/* calculating the indentation */

		ind = countspaces(data, start, end, 4) - start;

		/* joining only indented stuff after empty lines;
		 * note that now we only require 1 space of indentation
		 * to continue, just like lists */

		if (ind == 0) {
			if (start == id_end + 2 &&
			    data[start] == '\t') {
				/* XXX: wtf? */
			} else
				break;
		} else if (in_empty)
			if (!hbuf_putc(contents, '\n'))
				goto err;

		in_empty = 0;

		/* adding the line into the content buffer */

		if (!hbuf_put(contents,
		    data + start + ind, i - start - ind))
			goto err;

		/* add carriage return */

		if (i < end) {
			if (!hbuf_putc(contents, '\n'))
				goto err;
			if (i < end &&
			    (data[i] == '\n' || data[i] == '\r')) {
				i++;
				if (i < end && data[i] == '\n' &&
				    data[i - 1] == '\r')
					i++;
			}
		}
		start = i;
	}

	if (last)
		*last = start;

	if ((ref = calloc(1, sizeof(struct foot_ref))) == NULL)
		goto err;

	TAILQ_INSERT_TAIL(&doc->footq, ref, entries);
	if (!hbuf_createb(&ref->contents, contents))
		return -1;
	if (!hbuf_create(&ref->name, data + id_offs, id_end - id_offs))
		return -1;
	hbuf_free(contents);
	return 1;
err:
	hbuf_free(contents);
	return -1;
}

/*
 * Returns >0 if the line is a reference, 0 if not, <0 on failure.
 */
static int
is_ref(struct lowdown_doc *doc, const char *data,
	size_t beg, size_t end, size_t *last)
{
	size_t	 	 i, id_offset, id_end, link_offset, link_end,
			 title_offset = 0, title_end = 0, line_end,
			 garbage, attr_offset = 0, attr_end = 0;
	struct link_ref	*ref;

	/* Up to 3 optional leading spaces. */

	if (beg + 3 >= end)
		return 0;
	i = countspaces(data, beg, end, 3);

	/* Id part: anything but a newline between brackets. */

	if (data[i] != '[')
		return 0;
	i++;
	id_offset = i;
	while (i < end && data[i] != '\n' &&
	       data[i] != '\r' && data[i] != ']')
		i++;
	if (i >= end || data[i] != ']')
		return 0;
	id_end = i;

	/* Spacer: colon (space | tab)* newline? (space | tab)* */

	i++;
	if (i >= end || data[i] != ':')
		return 0;
	i++;
	i = countspaces(data, i, end, 0);
	if (i < end && (data[i] == '\n' || data[i] == '\r')) {
		i++;
		if (i < end && data[i] == '\r' && data[i - 1] == '\n')
			i++;
	}
	i = countspaces(data, i, end, 0);
	if (i >= end)
		return 0;

	/*
	 * Link: spacing-free sequence, optionally between angle
	 * brackets.
	 */

	if (data[i] == '<')
		i++;

	link_offset = i;

	while (i < end && data[i] != ' ' &&
	       data[i] != '\n' && data[i] != '\r')
		i++;

	if (data[i - 1] == '>')
		link_end = i - 1;
	else
		link_end = i;

	/*
	 * Space: (space | tab)* (newline | '\'' | '"' | '(' )
	 * Optionally '{' for attributes.
	 */

	i = countspaces(data, i, end, 0);

	if (doc->ext_flags & LOWDOWN_ATTRS) {
		if (i < end && data[i] != '\n' && data[i] != '\r' &&
		    data[i] != '\'' && data[i] != '"' &&
		    data[i] != '(' && data[i] != '{')
			return 0;
	} else {
		if (i < end && data[i] != '\n' && data[i] != '\r' &&
		    data[i] != '\'' && data[i] != '"' &&
		    data[i] != '(')
			return 0;
	}

	line_end = 0;

	/* computing end-of-line */

	if (i >= end || data[i] == '\r' || data[i] == '\n')
		line_end = i;
	if (i + 1 < end && data[i] == '\n' && data[i + 1] == '\r')
		line_end = i + 1;

	/* optional (space|tab)* spacer after a newline */

	if (line_end)
		i = countspaces(data, line_end + 1, end, 0);

	/*
	 * Optional title: any non-newline sequence enclosed in '"()
	 * alone on its line.  This is... confusing, because we can have
	 * any number of embedded delimiters in the text and only the
	 * last one is valid.
	 *
	 *  [link1]: moo.com "hello "world" (hi) there
	 *                                     ^last
	 *
	 * The rule is that there must be only spaces between the last
	 * delimiter, whatever it is, and the newline OR opening curly
	 * brace (if parsing), which signifies extended attributes.
	 */

	if (i + 1 < end &&
	    (data[i] == '\'' || data[i] == '"' || data[i] == '(')) {
		title_offset = ++i;
		for (garbage = 0; i < end; i++) {
			if (data[i] == '\'' || data[i] == '"' ||
			    data[i] == ')') {
				title_end = i;
				garbage = 0;
				continue;
			}
			if (data[i] == '\n' || data[i] == '\r' ||
			    ((doc->ext_flags & LOWDOWN_ATTRS) &&
			     data[i] == '{'))
				break;
			if (data[i] != ' ')
				garbage = 1;
		}
		if (garbage)
			return 0;
	}

	/*
	 * Now optionally the attributes.  These use similar semantics
	 * where there can be any number of embedded delimiters: only
	 * the last one is recorded, and there may be no garbage between
	 * it and the newline.
	 */

	if ((doc->ext_flags & LOWDOWN_ATTRS) &&
	    i + 1 < end && data[i] == '{') {
		attr_offset = ++i;
		for (garbage = 0; i < end; i++) {
			if (data[i] == '}') {
				attr_end = i;
				garbage = 0;
				continue;
			}
			if (data[i] == '\n' || data[i] == '\r')
				break;
			if (data[i] != ' ')
				garbage = 1;
		}
		if (garbage)
			return 0;
	}

	if (i + 1 < end && data[i] == '\n' && data[i + 1] == '\r')
		line_end = i + 1;
	else
		line_end = i;

	/* Garbage after the link or empty link. */

	if (!line_end || link_end == link_offset)
		return 0;

	/* A valid ref has been found, filling-in return structures. */

	if (last)
		*last = line_end;

	if ((ref = calloc(1, sizeof(struct link_ref))) == NULL)
		return -1;
	TAILQ_INSERT_TAIL(&doc->refq, ref, entries);

	if (id_end - id_offset) {
		ref->name = hbuf_new(id_end - id_offset);
		if (ref->name == NULL)
			return -1;
		if (!hbuf_put(ref->name,
		    data + id_offset, id_end - id_offset))
			return -1;
	}

	ref->link = hbuf_new(link_end - link_offset);
	if (ref->link == NULL)
		return -1;

	if (!hbuf_put(ref->link,
	    data + link_offset, link_end - link_offset))
		return -1;

	if (title_end > title_offset) {
		ref->title = hbuf_new(title_end - title_offset);
		if (ref->title == NULL)
			return -1;
		if (!hbuf_put(ref->title,
		    data + title_offset, title_end - title_offset))
			return -1;
	}

	if (attr_end > attr_offset) {
		ref->attrs = hbuf_new(attr_end - attr_offset);
		if (ref->attrs == NULL)
			return -1;
		if (!hbuf_put(ref->attrs,
		    data + attr_offset, attr_end - attr_offset))
			return -1;
	}

	return 1;
}

/*
 * Replace tabs with 4 spaces.
 * Return zero on failure (memory), non-zero on success.
 */
static int
expand_tabs(struct lowdown_buf *ob, const char *line, size_t size)
{
	size_t  i, tab = 0, org;

	/*
	 * This code makes two assumptions:
	 *
	 * (1) Input is valid UTF-8.  (Any byte with top two bits 10 is
	 * skipped, whether or not it is a valid UTF-8 continuation
	 * byte.)
	 * (2) Input contains no combining characters.  (Combining
	 * characters should be skipped but are not.)
	 */

	for (i = 0; i < size; i++) {
		org = i;
		while (i < size && line[i] != '\t') {
			/* ignore UTF-8 continuation bytes */
			if ((line[i] & 0xc0) != 0x80)
				tab++;
			i++;
		}
		if (i > org && !hbuf_put(ob, line + org, i - org))
			return 0;
		if (i >= size)
			break;

		do {
			if (!hbuf_putc(ob, ' '))
				return 0;
			tab++;
		} while (tab % 4);
	}

	return 1;
}

struct lowdown_doc *
lowdown_doc_new(const struct lowdown_opts *opts)
{
	struct lowdown_doc	*doc;
	unsigned int		 extensions = opts ? opts->feat : 0;
	size_t			 i;

	doc = calloc(1, sizeof(struct lowdown_doc));
	if (doc == NULL)
		return NULL;

	doc->maxdepth = opts == NULL ? 128 : opts->maxdepth;
	doc->active_char['*'] = MD_CHAR_EMPHASIS;
	doc->active_char['_'] = MD_CHAR_EMPHASIS;
	if (extensions & LOWDOWN_STRIKE)
		doc->active_char['~'] = MD_CHAR_EMPHASIS;
	if (extensions & LOWDOWN_HILITE)
		doc->active_char['='] = MD_CHAR_EMPHASIS;
	doc->active_char['`'] = MD_CHAR_CODESPAN;
	doc->active_char['\n'] = MD_CHAR_LINEBREAK;
	doc->active_char['['] = MD_CHAR_LINK;
	doc->active_char['!'] = MD_CHAR_IMAGE;
	doc->active_char['<'] = MD_CHAR_LANGLE;
	doc->active_char['\\'] = MD_CHAR_ESCAPE;
	doc->active_char['&'] = MD_CHAR_ENTITY;
	if (extensions & LOWDOWN_AUTOLINK) {
		doc->active_char[':'] = MD_CHAR_AUTOLINK_URL;
		doc->active_char['@'] = MD_CHAR_AUTOLINK_EMAIL;
		doc->active_char['w'] = MD_CHAR_AUTOLINK_WWW;
	}
	if (extensions & LOWDOWN_SUPER)
		doc->active_char['^'] = MD_CHAR_SUPERSCRIPT;
	if (extensions & LOWDOWN_MATH)
		doc->active_char['$'] = MD_CHAR_MATH;

	doc->ext_flags = extensions;

	if (opts != NULL && opts->metasz > 0) {
		doc->meta = calloc(opts->metasz, sizeof(char *));
		if (doc->meta == NULL)
			goto err;
		doc->metasz = opts->metasz;
		for (i = 0; i < doc->metasz; i++) {
			doc->meta[i] = strdup(opts->meta[i]);
			if (doc->meta[i] == NULL)
				goto err;
		}
	}
	if (opts != NULL && opts->metaovrsz > 0) {
		doc->metaovr = calloc(opts->metaovrsz, sizeof(char *));
		if (doc->metaovr == NULL)
			goto err;
		doc->metaovrsz = opts->metaovrsz;
		for (i = 0; i < doc->metaovrsz; i++) {
			doc->metaovr[i] = strdup(opts->metaovr[i]);
			if (doc->metaovr[i] == NULL)
				goto err;
		}
	}

	return doc;
err:
	lowdown_doc_free(doc);
	return NULL;
}

/*
 * Parse a MMD meta-data value.
 * If the value is a single line, both leading and trailing whitespace
 * will be stripped.
 * If the value spans multiple lines, leading whitespace from the first
 * line will be stripped and any following lines will be taken as is.
 * Returns a pointer to the value and the length of the value will be
 * written to "len";
 */
static const char *
parse_metadata_val(const char *data, size_t sz, size_t *len)
{
	const char	*val;
	size_t		 i, nlines = 0, nspaces, peek = 0;
	int		 startws;

	/* Skip leading whitespace. */

	i = countspaces(data, 0, sz, 0);

	val = data;
	sz -= i;

	/* Find end of line and count trailing whitespace. */

	for (i = nspaces = 0; i < sz && data[i] != '\n'; i++)
		if (data[i] == ' ')
			nspaces++;
		else
			nspaces = 0;
	*len = i;

	/*
	 * Iterate through zero or more following multilines.
	 * Multilines are terminated by a line containing a colon (that
	 * is not offset by whitespace) or a blank line.
	 */

	startws = i + 1 < sz &&
		(data[i + 1] == ' ' ||
		 data[i + 1] == '\t');

	for (i++; i < sz; i++) {
		/*
		 * This block is executed within the line.
		 * We use "peek" to see how far into the line we are;
		 * thus, if we encounter a colon without leading
		 * whitespace, we know that we're in the next metadata
		 * and should stop.
		 */

		if (startws == 0 && data[i] == ':')
			break;

		peek++;
		if (data[i] != '\n')
			continue;

		/*
		 * We're at a newline: start the loop again by seeing if
		 * the next line starts with whitespace.
		 */

		nlines++;
		*len += peek;
		peek = 0;

		/* (Filtered out prior to calling parse_metdata().) */

		assert(!(i + 1 < sz && data[i + 1] == '\n'));

		/* Check if the next line has leading whitespace. */

		startws = i + 1 < sz &&
			(data[i + 1] == ' ' ||
			 data[i + 1] == '\t');
	}

	/* Last metadata in section. */

	if (i == sz && peek)
		*len += peek + 1;

	/* Only remove trailing whitespace from a single line. */

	if (nlines == 0)
		*len -= nspaces;

	return val;
}

/*
 * Parse MMD key-value meta-data pairs.
 * Store the output in the doc's "metaq", as we might be using the
 * values for variable replacement elsewhere in this document.
 * Returns 0 if this is not metadata, >0 of it is, <0 on failure.
 */
static int
parse_metadata(struct lowdown_doc *doc, const char *data, size_t sz)
{
	size_t	 	 	 i, j, pos = 0, vsz, keysz;
	struct lowdown_meta	*m;
	struct lowdown_node	*n, *nn;
	const char		*val, *key;
	char			*cp, *buf;

	if (sz == 0 || data[sz - 1] != '\n')
		return 0;

	/*
	 * Check the first line for a colon to see if we should do
	 * metadata parsing at all.
	 * This is a convenience for regular markdown so that initial
	 * lines (not headers) don't get sucked into metadata.
	 */

	for (pos = 0; pos < sz; pos++)
		if (data[pos] == '\n' || data[pos] == ':')
			break;

	if (pos == sz || data[pos] == '\n')
		return 0;

	/*
	 * Put the metadata into the document's metaq because we might
	 * set variables.
	 */

	for (pos = 0; pos < sz; ) {
		key = &data[pos];
		for (i = pos; i < sz; i++)
			if (data[i] == ':')
				break;

		keysz = i - pos;
		if ((cp = buf = malloc(keysz + 1)) == NULL)
			return -1;

		/*
		 * Normalise the key to lowercase alphanumerics, "-",
		 * and "_", discard whitespace, replace other characters
		 * with a question mark.
		 */

		for (j = 0; j < keysz; j++) {
			if (isalnum((unsigned char)key[j]) ||
			    '-' == key[j] || '_' == key[j]) {
				*cp++ = tolower((unsigned char)key[j]);
				continue;
			} else if (isspace((unsigned char)key[j]))
				continue;
			*cp++ = '?';
		}
		*cp = '\0';

		/*
		 * If we've already encountered this key, remove it from
		 * both the local queue and the meta nodes.
		 */

		TAILQ_FOREACH(m, doc->metaq, entries)
			if (strcmp(m->key, buf) == 0) {
				TAILQ_REMOVE(doc->metaq, m, entries);
				free(m->key);
				free(m->value);
				free(m);
				break;
			}

		assert(doc->current->type == LOWDOWN_DOC_HEADER);
		TAILQ_FOREACH(n, &doc->current->children, entries) {
			assert(n->type == LOWDOWN_META);
			if (hbuf_streq(&n->rndr_meta.key, buf)) {
				TAILQ_REMOVE(&doc->current->children, n, entries);
				lowdown_node_free(n);
				break;
			}
		}

		if ((n = pushnode(doc, LOWDOWN_META)) == NULL) {
			free(buf);
			return -1;
		}
		if (!hbuf_create(&n->rndr_meta.key, buf, cp - buf)) {
			free(buf);
			return -1;
		}
		free(buf);

		m = calloc(1, sizeof(struct lowdown_meta));
		if (m == NULL)
			return -1;
		TAILQ_INSERT_TAIL(doc->metaq, m, entries);

		m->key = strndup
			(n->rndr_meta.key.data,
			 n->rndr_meta.key.size);
		if (m->key == NULL)
			return -1;

		if (i == sz) {
			if ((m->value = strdup("")) == NULL)
				return -1;
			popnode(doc, n);
			break;
		}

		/*
		 * Parse the value, creating a node if nonempty.  Make
		 * sure that the metadata has an empty value if there's
		 * no value to be parsed.
		 */

		assert(data[i] == ':');
		i++;
		while (i < sz && isspace((unsigned char)data[i]))
			i++;
		if (i == sz) {
			if ((m->value = strdup("")) == NULL)
				return -1;
			popnode(doc, n);
			break;
		}

		val = parse_metadata_val(&data[i], sz - i, &vsz);

		if ((m->value = strndup(val, vsz)) == NULL)
			return -1;
		if ((nn = pushnode(doc, LOWDOWN_NORMAL_TEXT)) == NULL)
			return -1;
		if (!hbuf_push(&nn->rndr_normal_text.text, val, vsz))
			return -1;

		popnode(doc, nn);
		popnode(doc, n);

		pos = i + vsz + 1;
	}

	return 1;
}

/*
 * Parse the buffer in data of length size.
 * If both mp and mszp are not NULL, set them with the meta information
 * instead of locally destroying it.
 * (Obviously only applicable if LOWDOWN_METADATA has been set.)
 */
struct lowdown_node *
lowdown_doc_parse(struct lowdown_doc *doc, size_t *maxn,
	const char *data, size_t size, struct lowdown_metaq *metaq)
{
	static const char 	 UTF8_BOM[] = { 0xEF, 0xBB, 0xBF };
	struct lowdown_buf	*text;
	size_t		 	 beg, end, i;
	const char		*sv;
	struct lowdown_node 	*n, *root = NULL;
	struct lowdown_metaq	 mq;
	int			 c, rc = 0;

	/*
	 * Have a temporary "mq" if "metaq" is not set.  We clear this
	 * automatically at the tail of the function.
	 */

	TAILQ_INIT(&mq);

	if (metaq == NULL)
		metaq = &mq;

	/* Initialise the parser. */

	doc->nodes = 0;
	doc->depth = 0;
	doc->current = NULL;
	doc->in_link_body = 0;
	doc->foots = 0;
	doc->metaq = metaq;

	TAILQ_INIT(doc->metaq);
	TAILQ_INIT(&doc->refq);
	TAILQ_INIT(&doc->footq);

	if ((text = hbuf_new(64)) == NULL)
		goto out;
	if (!hbuf_grow(text, size))
		goto out;
	if ((root = pushnode(doc, LOWDOWN_ROOT)) == NULL)
		goto out;

	/*
	 * Skip a possible UTF-8 BOM, even though the Unicode standard
	 * discourages having these in UTF-8 documents.
	 */

	beg = 0;
	if (size >= 3 && memcmp(data, UTF8_BOM, 3) == 0)
		beg += 3;

	/*
	 * Zeroth pass: metadata.  First process given metadata, then
	 * in-document metadata, then overriding metadata.  The
	 * in-document metadata is conditionally processed.
	 */

	if ((n = pushnode(doc, LOWDOWN_DOC_HEADER)) == NULL)
		goto out;

	for (i = 0; i < doc->metasz; i++)
		if (parse_metadata(doc,
		    doc->meta[i], strlen(doc->meta[i])) < 0)
			goto out;

	/* FIXME: CRLF EOLNs. */

	if ((doc->ext_flags & LOWDOWN_METADATA) &&
	    beg < size - 1 &&
	    isalnum((unsigned char)data[beg])) {
		sv = &data[beg];
		for (end = beg + 1; end < size; end++) {
			if (data[end] == '\n' &&
			    data[end - 1] == '\n')
				break;
		}
		if ((c = parse_metadata(doc, sv, end - beg)) > 0)
			beg = end + 1;
		else if (c < 0)
			goto out;
	}

	for (i = 0; i < doc->metaovrsz; i++)
		if (parse_metadata(doc,
		    doc->metaovr[i], strlen(doc->metaovr[i])) < 0)
			goto out;

	popnode(doc, n);

	/*
	 * First pass: looking for references and footnotes, copying
	 * everything else.
	 */

	while (beg < size) {
		if (doc->ext_flags & LOWDOWN_FOOTNOTES) {
		    c = is_footnote(doc, data, beg, size, &end);
		    if (c > 0) {
			    beg = end;
			    continue;
		    } else if (c < 0)
			    goto out;
		}

		if ((c = is_ref(doc, data, beg, size, &end)) > 0) {
			beg = end;
			continue;
		} else if (c < 0)
			goto out;

		/* Skipping to the next line. */

		end = beg;
		while (end < size && data[end] != '\n' &&
		       data[end] != '\r')
			end++;

		/* Adding the line body if present. */

		if (end > beg &&
		    !expand_tabs(text, data + beg, end - beg))
			goto out;

		/* Add one \n per newline. */

		while (end < size && (data[end] == '\n' ||
		       data[end] == '\r')) {
			if (data[end] == '\n' ||
			    (end + 1 < size && data[end + 1] != '\n'))
				if (!hbuf_putc(text, '\n'))
					goto out;
			end++;
		}

		beg = end;
	}

	/*
	 * Second pass (after header): rendering the document body and
	 * footnotes.
	 */

	if (text->size) {
		/* Adding a final newline if not already present. */
		if (text->data[text->size - 1] != '\n' &&
		    text->data[text->size - 1] != '\r')
			if (!hbuf_putc(text, '\n'))
				goto out;
		if (!parse_block(doc, text->data, text->size))
			goto out;
	}

	rc = 1;
out:
	hbuf_free(text);
	free_link_refs(&doc->refq);
	free_foot_refq(&doc->footq);
	lowdown_metaq_free(&mq);

	if (rc) {
		if (maxn != NULL)
			*maxn = doc->nodes;
		popnode(doc, root);
		assert(doc->depth == 0);
	} else {
		lowdown_node_free(root);
		root = NULL;
	}
	return root;
}

void
lowdown_node_free(struct lowdown_node *p)
{
	struct lowdown_node *n;

	if (p == NULL)
		return;

	switch (p->type) {
	case LOWDOWN_BLOCKCODE:
		hbuf_free(&p->rndr_blockcode.text);
		hbuf_free(&p->rndr_blockcode.lang);
		break;
	case LOWDOWN_BLOCKHTML:
		hbuf_free(&p->rndr_blockhtml.text);
		break;
	case LOWDOWN_CODESPAN:
		hbuf_free(&p->rndr_codespan.text);
		break;
	case LOWDOWN_ENTITY:
		hbuf_free(&p->rndr_entity.text);
		break;
	case LOWDOWN_HEADER:
		hbuf_free(&p->rndr_header.attr_cls);
		hbuf_free(&p->rndr_header.attr_id);
		break;
	case LOWDOWN_IMAGE:
		hbuf_free(&p->rndr_image.link);
		hbuf_free(&p->rndr_image.title);
		hbuf_free(&p->rndr_image.dims);
		hbuf_free(&p->rndr_image.alt);
		hbuf_free(&p->rndr_image.attr_width);
		hbuf_free(&p->rndr_image.attr_height);
		hbuf_free(&p->rndr_image.attr_cls);
		hbuf_free(&p->rndr_image.attr_id);
		break;
	case LOWDOWN_LINK:
		hbuf_free(&p->rndr_link.link);
		hbuf_free(&p->rndr_link.title);
		hbuf_free(&p->rndr_link.attr_cls);
		hbuf_free(&p->rndr_link.attr_id);
		break;
	case LOWDOWN_LINK_AUTO:
		hbuf_free(&p->rndr_autolink.link);
		break;
	case LOWDOWN_MATH_BLOCK:
		hbuf_free(&p->rndr_math.text);
		break;
	case LOWDOWN_META:
		hbuf_free(&p->rndr_meta.key);
		break;
	case LOWDOWN_NORMAL_TEXT:
		hbuf_free(&p->rndr_normal_text.text);
		break;
	case LOWDOWN_RAW_HTML:
		hbuf_free(&p->rndr_raw_html.text);
		break;
	case LOWDOWN_TABLE_HEADER:
		free(p->rndr_table_header.flags);
		break;
	default:
		break;
	}

	while ((n = TAILQ_FIRST(&p->children)) != NULL) {
		TAILQ_REMOVE(&p->children, n, entries);
		lowdown_node_free(n);
	}

	free(p);
}

void
lowdown_metaq_free(struct lowdown_metaq *q)
{
	struct lowdown_meta	*m;

	if (q == NULL)
		return;

	while ((m = TAILQ_FIRST(q)) != NULL) {
		TAILQ_REMOVE(q, m, entries);
		free(m->key);
		free(m->value);
		free(m);
	}
}

void
lowdown_doc_free(struct lowdown_doc *doc)
{
	size_t	 i;

	if (doc == NULL)
		return;

	for (i = 0; i < doc->metasz; i++)
		free(doc->meta[i]);
	for (i = 0; i < doc->metaovrsz; i++)
		free(doc->metaovr[i]);

	free(doc->meta);
	free(doc->metaovr);
	free(doc);
}
