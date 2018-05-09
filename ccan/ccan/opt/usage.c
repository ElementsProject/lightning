/* Licensed under GPLv2+ - see LICENSE file for details */
#include <ccan/opt/opt.h>
#if HAVE_SYS_TERMIOS_H
#include <sys/ioctl.h>
#include <sys/termios.h> /* Required on Solaris for struct winsize */
#endif
#if HAVE_SYS_UNISTD_H
#include <sys/unistd.h> /* Required on Solaris for ioctl */
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "private.h"

/* We only use this for pointer comparisons. */
const char opt_hidden[1];

#define MIN_DESC_WIDTH 40
#define MIN_TOTAL_WIDTH 50

static unsigned int get_columns(void)
{
	int ws_col = 0;
	const char *env = getenv("COLUMNS");

	if (env)
		ws_col = atoi(env);

#ifdef TIOCGWINSZ
	if (!ws_col)
	{
		struct winsize w;
		if (ioctl(0, TIOCGWINSZ, &w) != -1)
			ws_col = w.ws_col;
	}
#endif
	if (!ws_col)
		ws_col = 80;

	return ws_col;
}

/* Return number of chars of words to put on this line.
 * Prefix is set to number to skip at start, maxlen is max width, returns
 * length (after prefix) to put on this line.
 * start is set if we start a new line in the source description. */
static size_t consume_words(const char *words, size_t maxlen, size_t *prefix,
			    bool *start)
{
	size_t oldlen, len;

	/* Always swollow leading whitespace. */
	*prefix = strspn(words, " \n");
	words += *prefix;

	/* Leading whitespace at start of line means literal. */
	if (*start && *prefix) {
		oldlen = strcspn(words, "\n");
	} else {
		/* Use at least one word, even if it takes us over maxlen. */
		oldlen = len = strcspn(words, " ");
		while (len <= maxlen) {
			oldlen = len;
			len += strspn(words+len, " ");
			if (words[len] == '\n')
				break;
			len += strcspn(words+len, " \n");
			if (len == oldlen)
				break;
		}
	}

	*start = (words[oldlen - 1] == '\n');
	return oldlen;
}

static char *add_str_len(char *base, size_t *len, size_t *max,
			 const char *str, size_t slen)
{
	if (slen >= *max - *len)
		base = opt_alloc.realloc(base, *max = (*max * 2 + slen + 1));
	memcpy(base + *len, str, slen);
	*len += slen;
	return base;
}

static char *add_str(char *base, size_t *len, size_t *max, const char *str)
{
	return add_str_len(base, len, max, str, strlen(str));
}

static char *add_indent(char *base, size_t *len, size_t *max, size_t indent)
{
	if (indent >= *max - *len)
		base = opt_alloc.realloc(base, *max = (*max * 2 + indent + 1));
	memset(base + *len, ' ', indent);
	*len += indent;
	return base;
}

static char *add_desc(char *base, size_t *len, size_t *max,
		      unsigned int indent, unsigned int width,
		      const struct opt_table *opt)
{
	size_t off, prefix, l;
	const char *p;
	bool same_line = false, start = true;

	base = add_str(base, len, max, opt->names);
	off = strlen(opt->names);
	if ((opt->type & OPT_HASARG)
	    && !strchr(opt->names, ' ')
	    && !strchr(opt->names, '=')) {
		base = add_str(base, len, max, " <arg>");
		off += strlen(" <arg>");
	}

	/* Do we start description on next line? */
	if (off + 2 > indent) {
		base = add_str(base, len, max, "\n");
		off = 0;
	} else {
		base = add_indent(base, len, max, indent - off);
		off = indent;
		same_line = true;
	}

	/* Indent description. */
	p = opt->desc;
	while ((l = consume_words(p, width - indent, &prefix, &start)) != 0) {
		if (!same_line)
			base = add_indent(base, len, max, indent);
		p += prefix;
		base = add_str_len(base, len, max, p, l);
		base = add_str(base, len, max, "\n");
		off = indent + l;
		p += l;
		same_line = false;
	}

	/* Empty description?  Make it match normal case. */
	if (same_line)
		base = add_str(base, len, max, "\n");

	if (opt->show) {
		char buf[OPT_SHOW_LEN + sizeof("...")];
		strcpy(buf + OPT_SHOW_LEN, "...");
		opt->show(buf, opt->u.arg);

		/* If it doesn't fit on this line, indent. */
		if (off + strlen(" (default: ") + strlen(buf) + strlen(")")
		    > width) {
			base = add_indent(base, len, max, indent);
		} else {
			/* Remove \n. */
			(*len)--;
		}

		base = add_str(base, len, max, " (default: ");
		base = add_str(base, len, max, buf);
		base = add_str(base, len, max, ")\n");
	}
	return base;
}

char *opt_usage(const char *argv0, const char *extra)
{
	unsigned int i;
	size_t max, len, width, indent;
	char *ret;

	width = get_columns();
	if (width < MIN_TOTAL_WIDTH)
		width = MIN_TOTAL_WIDTH;

	/* Figure out longest option. */
	indent = 0;
	for (i = 0; i < opt_count; i++) {
		size_t l;
		if (opt_table[i].desc == opt_hidden)
			continue;
		if (opt_table[i].type == OPT_SUBTABLE)
			continue;
		l = strlen(opt_table[i].names);
		if (opt_table[i].type == OPT_HASARG
		    && !strchr(opt_table[i].names, ' ')
		    && !strchr(opt_table[i].names, '='))
			l += strlen(" <arg>");
		if (l + 2 > indent)
			indent = l + 2;
	}

	/* Now we know how much to indent */
	if (indent + MIN_DESC_WIDTH > width)
		indent = width - MIN_DESC_WIDTH;

	len = max = 0;
	ret = NULL;

	ret = add_str(ret, &len, &max, "Usage: ");
	ret = add_str(ret, &len, &max, argv0);

	/* Find usage message from among registered options if necessary. */
	if (!extra) {
		extra = "";
		for (i = 0; i < opt_count; i++) {
			if (opt_table[i].cb == (void *)opt_usage_and_exit
			    && opt_table[i].u.carg) {
				extra = opt_table[i].u.carg;
				break;
			}
		}
	}
	ret = add_str(ret, &len, &max, " ");
	ret = add_str(ret, &len, &max, extra);
	ret = add_str(ret, &len, &max, "\n");

	for (i = 0; i < opt_count; i++) {
		if (opt_table[i].desc == opt_hidden)
			continue;
		if (opt_table[i].type == OPT_SUBTABLE) {
			ret = add_str(ret, &len, &max, opt_table[i].desc);
			ret = add_str(ret, &len, &max, ":\n");
			continue;
		}
		ret = add_desc(ret, &len, &max, indent, width, &opt_table[i]);
	}
	ret[len] = '\0';
	return ret;
}

void opt_usage_exit_fail(const char *msg, ...)
{
	va_list ap;

	if (opt_argv0)
		fprintf(stderr, "%s: ", opt_argv0);
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n%s",
		opt_usage(opt_argv0 ? opt_argv0 : "<program>", NULL));
	exit(1);
}
