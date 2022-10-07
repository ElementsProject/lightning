/*	$Id$ */
/*
 * Copyright (c) 2016, 2017, 2020 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <sys/param.h>
#if HAVE_CAPSICUM
# include <sys/resource.h>
# include <sys/capsicum.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h> /* INT_MAX */
#include <locale.h> /* set_locale() */
#if HAVE_SANDBOX_INIT
# include <sandbox.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h> /* struct winsize */
#include <unistd.h>

#include "lowdown.h"

/*
 * Start with all of the sandboxes.
 * The sandbox_pre() happens before we open our input file for reading,
 * while the sandbox_post() happens afterward.
 */

#if HAVE_PLEDGE

static void
sandbox_post(int fdin, int fddin, int fdout)
{

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
}

static void
sandbox_pre(void)
{

	if (pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");
}

#elif HAVE_SANDBOX_INIT

static void
sandbox_post(int fdin, int fddin, int fdout)
{
	char	*ep;
	int	 rc;

	rc = sandbox_init
		(kSBXProfilePureComputation,
		 SANDBOX_NAMED, &ep);
	if (rc != 0)
		errx(1, "sandbox_init: %s", ep);
}

static void
sandbox_pre(void)
{

	/* Do nothing. */
}

#elif HAVE_CAPSICUM

static void
sandbox_post(int fdin, int fddin, int fdout)
{
	cap_rights_t	 rights;

	cap_rights_init(&rights);

	cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_FSTAT);
	if (cap_rights_limit(fdin, &rights) < 0)
 		err(1, "cap_rights_limit");

	if (fddin != -1) {
		cap_rights_init(&rights, 
			CAP_EVENT, CAP_READ, CAP_FSTAT);
		if (cap_rights_limit(fddin, &rights) < 0)
			err(1, "cap_rights_limit");
	}

	cap_rights_init(&rights, CAP_EVENT, CAP_WRITE, CAP_FSTAT);
	if (cap_rights_limit(STDERR_FILENO, &rights) < 0)
 		err(1, "cap_rights_limit");

	cap_rights_init(&rights, CAP_EVENT, CAP_WRITE, CAP_FSTAT);
	if (cap_rights_limit(fdout, &rights) < 0)
 		err(1, "cap_rights_limit");

	if (cap_enter())
		err(1, "cap_enter");
}

static void
sandbox_pre(void)
{

	/* Do nothing. */
}

#else /* No sandbox. */

#warning Compiling without sandbox support.

static void
sandbox_post(int fdin, int fddin, int fdout)
{

	/* Do nothing. */
}

static void
sandbox_pre(void)
{

	/* Do nothing. */
}

#endif

static size_t
get_columns(void)
{
	struct winsize	 size;

	memset(&size, 0, sizeof(struct winsize));
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == -1)
		return 72;
	return size.ws_col;
}

/*
 * Recognise the metadata format of "foo = bar" and "foo: bar".
 * Translates from the former into the latter.
 * This way "foo = : bar" -> "foo : : bar", etc.
 * Errors out if the metadata is malformed (no colon or equal sign).
 */
static void
metadata_parse(char opt, char ***vals, size_t *valsz, const char *arg)
{
	const char	*loceq, *loccol;
	char		*cp;

	loceq = strchr(arg, '=');
	loccol = strchr(arg, ':');

	if ((loceq != NULL && loccol == NULL) ||
	    (loceq != NULL && loccol != NULL && loceq < loccol)) {
		if (asprintf(&cp, "%.*s: %s\n",
		    (int)(loceq - arg), arg, loceq + 1) == -1)
			err(1, NULL);
		*vals = reallocarray(*vals, *valsz + 1, sizeof(char *));
		if (*vals == NULL)
			err(1, NULL);
		(*vals)[*valsz] = cp;
		(*valsz)++;
		return;
	}
	if ((loccol != NULL && loceq == NULL) ||
	    (loccol != NULL && loceq != NULL && loccol < loceq)) {
		if (asprintf(&cp, "%s\n", arg) == -1)
			err(1, NULL);
		*vals = reallocarray(*vals, *valsz + 1, sizeof(char *));
		if (*vals == NULL)
			err(1, NULL);
		(*vals)[*valsz] = cp;
		(*valsz)++;
		return;
	}
	errx(1, "-%c: malformed metadata", opt);
}

int
main(int argc, char *argv[])
{
	FILE			*fin = stdin, *fout = stdout, 
				*din = NULL;
	const char		*fnin = "<stdin>", *fnout = NULL,
	      	 		*fndin = NULL, *extract = NULL, *er,
				*mainopts = "M:m:sT:t:o:X:",
	      			*diffopts = "M:m:sT:t:o:", *odtstyfn = NULL;
	struct lowdown_opts 	 opts;
	struct stat		 st;
	int			 c, diff = 0, fd,
				 status = 0, aoflag = 0, roflag = 0,
				 aiflag = 0, riflag = 0, centre = 0;
	char			*ret = NULL, *cp, *odtsty = NULL;
	size_t		 	 i, retsz = 0, rcols, sz;
	ssize_t			 ssz;
	struct lowdown_meta 	*m;
	struct lowdown_metaq	 mq;
	struct option 		 lo[] = {
		{ "html-skiphtml",	no_argument,	&aoflag, LOWDOWN_HTML_SKIP_HTML },
		{ "html-no-skiphtml",	no_argument,	&roflag, LOWDOWN_HTML_SKIP_HTML },
		{ "html-escapehtml",	no_argument,	&aoflag, LOWDOWN_HTML_ESCAPE },
		{ "html-no-escapehtml",	no_argument,	&roflag, LOWDOWN_HTML_ESCAPE },
		{ "html-hardwrap",	no_argument,	&aoflag, LOWDOWN_HTML_HARD_WRAP },
		{ "html-no-hardwrap",	no_argument,	&roflag, LOWDOWN_HTML_HARD_WRAP },
		{ "html-head-ids",	no_argument,	&aoflag, LOWDOWN_HTML_HEAD_IDS },
		{ "html-no-head-ids",	no_argument,	&roflag, LOWDOWN_HTML_HEAD_IDS },
		{ "html-owasp",		no_argument,	&aoflag, LOWDOWN_HTML_OWASP },
		{ "html-no-owasp",	no_argument,	&roflag, LOWDOWN_HTML_OWASP },
		{ "html-num-ent",	no_argument,	&aoflag, LOWDOWN_HTML_NUM_ENT },
		{ "html-no-num-ent",	no_argument,	&roflag, LOWDOWN_HTML_NUM_ENT },
		{ "latex-numbered",	no_argument,	&aoflag, LOWDOWN_LATEX_NUMBERED },
		{ "latex-no-numbered",	no_argument,	&roflag, LOWDOWN_LATEX_NUMBERED },
		{ "latex-skiphtml",	no_argument,	&aoflag, LOWDOWN_LATEX_SKIP_HTML },
		{ "latex-no-skiphtml",	no_argument,	&roflag, LOWDOWN_LATEX_SKIP_HTML },
		{ "nroff-skiphtml",	no_argument,	&aoflag, LOWDOWN_NROFF_SKIP_HTML },
		{ "nroff-no-skiphtml",	no_argument,	&roflag, LOWDOWN_NROFF_SKIP_HTML },
		{ "nroff-groff",	no_argument,	&aoflag, LOWDOWN_NROFF_GROFF },
		{ "nroff-no-groff",	no_argument,	&roflag, LOWDOWN_NROFF_GROFF },
		{ "nroff-numbered",	no_argument,	&aoflag, LOWDOWN_NROFF_NUMBERED },
		{ "nroff-no-numbered",	no_argument,	&roflag, LOWDOWN_NROFF_NUMBERED },
		{ "nroff-shortlinks",	no_argument, 	&aoflag, LOWDOWN_NROFF_SHORTLINK },
		{ "nroff-no-shortlinks",no_argument, 	&roflag, LOWDOWN_NROFF_SHORTLINK },
		{ "nroff-nolinks",	no_argument, 	&aoflag, LOWDOWN_NROFF_NOLINK },
		{ "nroff-no-nolinks",	no_argument, 	&roflag, LOWDOWN_NROFF_NOLINK },
		{ "odt-skiphtml",	no_argument,	&aoflag, LOWDOWN_ODT_SKIP_HTML },
		{ "odt-no-skiphtml",	no_argument,	&roflag, LOWDOWN_ODT_SKIP_HTML },
		{ "odt-style",		required_argument, NULL, 6 },
		{ "term-width",		required_argument, NULL, 1 },
		{ "term-hmargin",	required_argument, NULL, 2 },
		{ "term-vmargin",	required_argument, NULL, 3 },
		{ "term-columns",	required_argument, NULL, 4 },
		{ "gemini-link-end",	no_argument, 	&aoflag, LOWDOWN_GEMINI_LINK_END },
		{ "gemini-no-link-end",	no_argument, 	&roflag, LOWDOWN_GEMINI_LINK_END },
		{ "gemini-link-roman",	no_argument, 	&aoflag, LOWDOWN_GEMINI_LINK_ROMAN },
		{ "gemini-no-link-roman", no_argument, 	&roflag, LOWDOWN_GEMINI_LINK_ROMAN },
		{ "gemini-link-noref",	no_argument, 	&aoflag, LOWDOWN_GEMINI_LINK_NOREF },
		{ "gemini-no-link-noref", no_argument, 	&roflag, LOWDOWN_GEMINI_LINK_NOREF },
		{ "gemini-link-inline",	no_argument, 	&aoflag, LOWDOWN_GEMINI_LINK_IN },
		{ "gemini-no-link-inline",no_argument, 	&roflag, LOWDOWN_GEMINI_LINK_IN },
		{ "gemini-metadata",	no_argument, 	&aoflag, LOWDOWN_GEMINI_METADATA },
		{ "gemini-no-metadata",	no_argument, 	&roflag, LOWDOWN_GEMINI_METADATA },
		{ "term-shortlinks",	no_argument, 	&aoflag, LOWDOWN_TERM_SHORTLINK },
		{ "term-no-shortlinks",	no_argument, 	&roflag, LOWDOWN_TERM_SHORTLINK },
		{ "term-nolinks",	no_argument, 	&aoflag, LOWDOWN_TERM_NOLINK },
		{ "term-no-nolinks",	no_argument, 	&roflag, LOWDOWN_TERM_NOLINK },
		{ "term-no-colour",	no_argument, 	&aoflag, LOWDOWN_TERM_NOCOLOUR },
		{ "term-colour",	no_argument, 	&roflag, LOWDOWN_TERM_NOCOLOUR },
		{ "term-no-ansi",	no_argument, 	&aoflag, LOWDOWN_TERM_NOANSI },
		{ "term-ansi",		no_argument, 	&roflag, LOWDOWN_TERM_NOANSI },
		{ "out-smarty",		no_argument,	&aoflag, LOWDOWN_SMARTY },
		{ "out-no-smarty",	no_argument,	&roflag, LOWDOWN_SMARTY },
		{ "out-standalone",	no_argument,	&aoflag, LOWDOWN_STANDALONE },
		{ "out-no-standalone",	no_argument,	&roflag, LOWDOWN_STANDALONE },
		{ "parse-hilite",	no_argument,	&aiflag, LOWDOWN_HILITE },
		{ "parse-no-hilite",	no_argument,	&riflag, LOWDOWN_HILITE },
		{ "parse-tables",	no_argument,	&aiflag, LOWDOWN_TABLES },
		{ "parse-no-tables",	no_argument,	&riflag, LOWDOWN_TABLES },
		{ "parse-fenced",	no_argument,	&aiflag, LOWDOWN_FENCED },
		{ "parse-no-fenced",	no_argument,	&riflag, LOWDOWN_FENCED },
		{ "parse-footnotes",	no_argument,	&aiflag, LOWDOWN_FOOTNOTES },
		{ "parse-no-footnotes",	no_argument,	&riflag, LOWDOWN_FOOTNOTES },
		{ "parse-autolink",	no_argument,	&aiflag, LOWDOWN_AUTOLINK },
		{ "parse-no-autolink",	no_argument,	&riflag, LOWDOWN_AUTOLINK },
		{ "parse-strike",	no_argument,	&aiflag, LOWDOWN_STRIKE },
		{ "parse-no-strike",	no_argument,	&riflag, LOWDOWN_STRIKE },
		{ "parse-super",	no_argument,	&aiflag, LOWDOWN_SUPER },
		{ "parse-no-super",	no_argument,	&riflag, LOWDOWN_SUPER },
		{ "parse-math",		no_argument,	&aiflag, LOWDOWN_MATH },
		{ "parse-no-math",	no_argument,	&riflag, LOWDOWN_MATH },
		{ "parse-codeindent",	no_argument,	&riflag, LOWDOWN_NOCODEIND },
		{ "parse-no-codeindent",no_argument,	&aiflag, LOWDOWN_NOCODEIND },
		{ "parse-intraemph",	no_argument,	&riflag, LOWDOWN_NOINTEM },
		{ "parse-no-intraemph",	no_argument,	&aiflag, LOWDOWN_NOINTEM },
		{ "parse-metadata",	no_argument,	&aiflag, LOWDOWN_METADATA },
		{ "parse-no-metadata",	no_argument,	&riflag, LOWDOWN_METADATA },
		{ "parse-cmark",	no_argument,	&aiflag, LOWDOWN_COMMONMARK },
		{ "parse-no-cmark",	no_argument,	&riflag, LOWDOWN_COMMONMARK },
		{ "parse-deflists",	no_argument,	&aiflag, LOWDOWN_DEFLIST },
		{ "parse-no-deflists",	no_argument,	&riflag, LOWDOWN_DEFLIST },
		{ "parse-img-ext",	no_argument,	&aiflag, LOWDOWN_IMG_EXT }, /* TODO: remove */
		{ "parse-no-img-ext",	no_argument,	&riflag, LOWDOWN_IMG_EXT }, /* TODO: remove */
		{ "parse-ext-attrs",	no_argument,	&aiflag, LOWDOWN_ATTRS },
		{ "parse-no-ext-attrs",	no_argument,	&riflag, LOWDOWN_ATTRS },
		{ "parse-tasklists",	no_argument,	&aiflag, LOWDOWN_TASKLIST },
		{ "parse-no-tasklists",	no_argument,	&riflag, LOWDOWN_TASKLIST },
		{ "parse-maxdepth",	required_argument, NULL, 5 },
		{ NULL,			0,	NULL,	0 }
	};

	/* Get the real number of columns or 72. */

	rcols = get_columns();

	sandbox_pre();

	TAILQ_INIT(&mq);
	memset(&opts, 0, sizeof(struct lowdown_opts));

	opts.maxdepth = 128;
	opts.type = LOWDOWN_HTML;
	opts.feat =
		LOWDOWN_ATTRS |
		LOWDOWN_AUTOLINK |
		LOWDOWN_COMMONMARK |
		LOWDOWN_DEFLIST |
		LOWDOWN_FENCED |
		LOWDOWN_FOOTNOTES |
		LOWDOWN_METADATA |
		LOWDOWN_STRIKE |
		LOWDOWN_SUPER |
		LOWDOWN_TABLES |
		LOWDOWN_TASKLIST;
	opts.oflags = 
		LOWDOWN_HTML_ESCAPE |
		LOWDOWN_HTML_HEAD_IDS |
		LOWDOWN_HTML_NUM_ENT |
		LOWDOWN_HTML_OWASP |
		LOWDOWN_HTML_SKIP_HTML |
		LOWDOWN_NROFF_GROFF |
		LOWDOWN_NROFF_NUMBERED |
		LOWDOWN_NROFF_SKIP_HTML |
		LOWDOWN_ODT_SKIP_HTML |
		LOWDOWN_LATEX_SKIP_HTML |
		LOWDOWN_LATEX_NUMBERED |
		LOWDOWN_SMARTY;

	if (strcasecmp(getprogname(), "lowdown-diff") == 0) 
		diff = 1;

	while ((c = getopt_long(argc, argv, 
	       diff ? diffopts : mainopts, lo, NULL)) != -1)
		switch (c) {
		case 'M':
			metadata_parse(c, &opts.metaovr, 
				&opts.metaovrsz, optarg);
			break;
		case 'm':
			metadata_parse(c, &opts.meta, 
				&opts.metasz, optarg);
			break;
		case 'o':
			fnout = optarg;
			break;
		case 's':
			opts.oflags |= LOWDOWN_STANDALONE;
			break;
		case 't':
		case 'T':
			if (strcasecmp(optarg, "ms") == 0)
				opts.type = LOWDOWN_NROFF;
			else if (strcasecmp(optarg, "gemini") == 0)
				opts.type = LOWDOWN_GEMINI;
			else if (strcasecmp(optarg, "html") == 0)
				opts.type = LOWDOWN_HTML;
			else if (strcasecmp(optarg, "latex") == 0)
				opts.type = LOWDOWN_LATEX;
			else if (strcasecmp(optarg, "man") == 0)
				opts.type = LOWDOWN_MAN;
			else if (strcasecmp(optarg, "fodt") == 0)
				opts.type = LOWDOWN_FODT;
			else if (strcasecmp(optarg, "term") == 0)
				opts.type = LOWDOWN_TERM;
			else if (strcasecmp(optarg, "tree") == 0)
				opts.type = LOWDOWN_TREE;
			else if (strcasecmp(optarg, "null") == 0)
				opts.type = LOWDOWN_NULL;
			else
				goto usage;
			break;
		case 'X':
			extract = optarg;
			break;
		case 0:
			if (roflag)
				opts.oflags &= ~roflag;
			if (aoflag)
				opts.oflags |= aoflag;
			if (riflag)
				opts.feat &= ~riflag;
			if (aiflag)
				opts.feat |= aiflag;
			break;
		case 1:
			opts.cols = strtonum(optarg, 0, INT_MAX, &er);
			if (er == NULL)
				break;
			errx(1, "--term-width: %s", er);
		case 2:
			if (strcmp(optarg, "centre") == 0 ||
			    strcmp(optarg, "centre") == 0) {
				centre = 1;
				break;
			}
			opts.hmargin = strtonum
				(optarg, 0, INT_MAX, &er);
			if (er == NULL)
				break;
			errx(1, "--term-hmargin: %s", er);
		case 3:
			opts.vmargin = strtonum(optarg, 0, INT_MAX, &er);
			if (er == NULL)
				break;
			errx(1, "--term-vmargin: %s", er);
		case 4:
			rcols = strtonum(optarg, 1, INT_MAX, &er);
			if (er == NULL)
				break;
			errx(1, "--term-columns: %s", er);
		case 5:
			opts.maxdepth = strtonum(optarg, 0, INT_MAX, &er);
			if (er == NULL)
				break;
			errx(1, "--parse-maxdepth: %s", er);
		case 6:
			odtstyfn = optarg;
			break;
		default:
			goto usage;
		}

	argc -= optind;
	argv += optind;

	if (opts.type == LOWDOWN_TERM ||
 	    opts.type == LOWDOWN_GEMINI)
		setlocale(LC_CTYPE, "");

	/* 
	 * By default, try to show 80 columns.
	 * Don't show more than the number of available columns.
	 */

	if (opts.cols == 0) {
		if ((opts.cols = rcols) > 80)
			opts.cols = 80;
	} else if (opts.cols > rcols)
		opts.cols = rcols;

	/* If we're centred, set our margins. */

	if (centre && opts.cols < rcols)
		opts.hmargin = (rcols - opts.cols) / 2;

	/* 
	 * Diff mode takes two arguments: the first is mandatory (the
	 * old file) and the second (the new one) is optional.
	 * Non-diff mode takes an optional single argument.
	 */

	if ((diff && (argc == 0 || argc > 2)) || (!diff && argc > 1))
		goto usage;

	if (diff) {
		if (argc > 1 && strcmp(argv[1], "-")) {
			fnin = argv[1];
			if ((fin = fopen(fnin, "r")) == NULL)
				err(1, "%s", fnin);
		}
		fndin = argv[0];
		if ((din = fopen(fndin, "r")) == NULL)
			err(1, "%s", fndin);
	} else {
		if (argc && strcmp(argv[0], "-")) {
			fnin = argv[0];
			if ((fin = fopen(fnin, "r")) == NULL)
				err(1, "%s", fnin);
		}
	}

	/*
	 * If we have a style sheet specified for -Tfodt, load it now
	 * before we drop privileges.
	 */

	if (opts.type == LOWDOWN_FODT && odtstyfn != NULL) {
		if ((fd = open(odtstyfn, O_RDONLY)) == -1)
			err(1, "%s", odtstyfn);
		if (fstat(fd, &st) == -1)
			err(1, "%s", odtstyfn);
		if ((uint64_t)st.st_size > SIZE_MAX - 1)
			errx(1, "%s: file too long", odtstyfn);
		sz = (size_t)st.st_size;
		if ((odtsty = cp = malloc(sz + 1)) == NULL)
			err(1, NULL);
		while (sz > 0) {
			if ((ssz = read(fd, cp, sz)) == -1)
				err(1, "%s", odtstyfn);
			if (ssz == 0)
				errx(1, "%s: short file", odtstyfn);
			sz -= (size_t)ssz;
			cp += ssz;
		}
		*cp = '\0';
		close(fd);
		opts.odt.sty = odtsty;
	}

	/* Configure the output file. */

	if (fnout != NULL && strcmp(fnout, "-") &&
	    (fout = fopen(fnout, "w")) == NULL)
		err(1, "%s", fnout);

	sandbox_post(fileno(fin), din == NULL ? 
		-1 : fileno(din), fileno(fout));

	/* We're now completely sandboxed. */

	/* Require metadata when extracting. */

	if (extract)
		opts.feat |= LOWDOWN_METADATA;

	/* 
	 * Allow NO_COLOUR to dictate colours.
	 * This only works for -Tterm output when not in diff mode.
	 */

	if (getenv("NO_COLOR") != NULL ||
	    getenv("NO_COLOUR") != NULL)
		opts.oflags |= LOWDOWN_TERM_NOCOLOUR;

	if (diff) {
		opts.oflags &= ~LOWDOWN_TERM_NOCOLOUR;
		if (!lowdown_file_diff
		    (&opts, fin, din, &ret, &retsz))
			errx(1, "%s: failed parse", fnin);
	} else {
		if (!lowdown_file(&opts, fin, &ret, &retsz, &mq))
			errx(1, "%s: failed parse", fnin);
	}

	if (extract != NULL) {
		assert(!diff);
		TAILQ_FOREACH(m, &mq, entries) 
			if (strcasecmp(m->key, extract) == 0)
				break;
		if (m != NULL) {
			fprintf(fout, "%s\n", m->value);
		} else {
			status = 1;
			warnx("%s: unknown keyword", extract);
		}
	} else
		fwrite(ret, 1, retsz, fout);

	free(ret);
	free(odtsty);

	if (fout != stdout)
		fclose(fout);
	if (din != NULL)
		fclose(din);
	if (fin != stdin)
		fclose(fin);

	for (i = 0; i < opts.metasz; i++)
		free(opts.meta[i]);
	for (i = 0; i < opts.metaovrsz; i++)
		free(opts.metaovr[i]);

	free(opts.meta);
	free(opts.metaovr);

	lowdown_metaq_free(&mq);
	return status;
usage:
	if (!diff) {
		fprintf(stderr, 
			"usage: lowdown [-s] [input_options] [output_options] [-M metadata]\n"
			"               [-m metadata] [-o output] [-t mode] [-X keyword] [file]\n");
	} else
		fprintf(stderr, 
			"usage: lowdown-diff [-s] [input_options] [output_options] [-M metadata]\n"
			"                    [-m metadata] [-o output] [-t mode] oldfile [newfile]\n");
	return 1;
}
