/* Simple program to search for BOLT references in C files and make sure
 * they're accurate. */
#include "config.h"
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <dirent.h>

static bool verbose = false;

struct bolt_file {
	const char *prefix;
	const char *contents;
};

/* Turn any whitespace into a single space. */
static char *canonicalize(char *str)
{
	char *to = str, *from = str;
	bool have_space = true;

	while (*from) {
		if (cisspace(*from)) {
			if (!have_space)
				*(to++) = ' ';
			have_space = true;
		} else {
			*(to++) = *from;
			have_space = false;
		}
		from++;
	}
	if (have_space && to != str)
		to--;
	*to = '\0';
	tal_resize(&str, to + 1 - str);
	return str;
}

static bool get_files(const char *dir, const char *subdir,
		      struct bolt_file **files)
{
	char *path = path_join(NULL, dir, subdir);
	DIR *d = opendir(path);
	struct dirent *e;

	if (!d)
		return false;

	while ((e = readdir(d)) != NULL) {
		int preflen;
		struct bolt_file bf;

		/* Must end in .md */
		if (!strends(e->d_name, ".md"))
			continue;

		/* Prefix is anything up to - */
		preflen = strspn(e->d_name,
				 "0123456789"
				 "abcdefghijklmnopqrstuvwxyz"
				 "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
		if (!preflen)
			continue;
		if (preflen + strlen(".md") != strlen(e->d_name)
		    && e->d_name[preflen] != '-')
			continue;

		if (verbose)
			printf("Found bolt %.*s\n", preflen, e->d_name);

		bf.prefix = tal_strndup(*files, e->d_name, preflen);
		bf.contents
			= canonicalize(grab_file(*files,
						 path_join(path, path,
							   e->d_name)));
		tal_arr_expand(files, bf);
	}
	return true;
}

static struct bolt_file *get_bolt_files(const char *dir)
{
	struct bolt_file *bolts = tal_arr(NULL, struct bolt_file, 0);

	if (!get_files(dir, ".", &bolts))
		err(1, "Opening BOLT dir %s", dir);
	/* This currently does not exist. */
	get_files(dir, "early-drafts", &bolts);
	return bolts;
}

static char *find_bolt_ref(const char *prefix, char **p, size_t *len)
{
	for (;;) {
		char *bolt, *end;
		size_t preflen;

		/* Quote is of form 'BOLT #X:' */
		*p = strchr(*p, '*');
		if (!*p)
			return NULL;
		*p += 1;
		while (cisspace(**p))
			(*p)++;
		if (strncmp(*p, prefix, strlen(prefix)) != 0)
			continue;
		*p += strlen(prefix);
		while (cisspace(**p))
			(*p)++;
		if (**p != '#')
			continue;
		(*p)++;

		preflen = strcspn(*p, " :");
		bolt = tal_strndup(NULL, *p, preflen);

		(*p) += preflen;
		while (cisspace(**p))
			(*p)++;
		if (**p != ':')
			continue;
		(*p)++;

		end = strstr(*p, "*/");
		if (!end)
			*len = strlen(*p);
		else
			*len = end - *p;
		return bolt;
	}
}

static char *code_to_regex(const char *code, size_t len, bool escape)
{
	char *pattern = tal_arr(NULL, char, len*2 + 1), *p;
	size_t i;
	bool after_nl = true;

	/* We swallow '*' if first in line: block comments */
	p = pattern;
	for (i = 0; i < len; i++) {
		/* ... matches anything. */
		if (strstarts(code + i, "...")) {
			*(p++) = '.';
			*(p++) = '*';
			i += 2;
			continue;
		}

		switch (code[i]) {
		case '\n':
			after_nl = true;
			*(p++) = code[i];
			break;

		case '*':
			if (after_nl) {
				after_nl = false;
				continue;
			}
			/* Fall through. */
		case '.':
		case '$':
		case '^':
		case '[':
		case ']':
		case '{':
		case '}':
		case '(':
		case ')':
		case '+':
		case '|':
			if (escape)
				*(p++) = '\\';
			/* Fall through */
		default:
			*(p++) = code[i];
		}
	}
	*p = '\0';
	return canonicalize(pattern);
}

/* Moves *pos to start of line. */
static unsigned linenum(const char *raw, const char **pos)
{
	unsigned line = 0; /* Out-by-one below */
	const char *l = raw, *point = *pos;

	while (l < point) {
		*pos = l;
		l = strchr(l, '\n');
		line++;
		if (!l)
			break;
		l++;
	}
	return line;
}

static void fail_mismatch(const char *filename,
			  const char *raw, const char *pos,
			  size_t len, struct bolt_file *bolt)
{
	unsigned line = linenum(raw, &pos);
	char *try;

	fprintf(stderr, "%s:%u:mismatch:%.*s\n",
		filename, line, (int)strcspn(pos, "\n"), pos);
	/* Try to find longest match, as a hint. */
	try = code_to_regex(pos + strcspn(pos, "\n"), len, false);
	while (strlen(try)) {
		const char *p = strstr(bolt->contents, try);
		if (p) {
			fprintf(stderr, "Closest match: %s...[%.20s]\n",
				try, p + strlen(try));
			break;
		}
		try[strlen(try)-1] = '\0';
	}
	exit(1);
}

static void fail_nobolt(const char *filename,
			const char *raw, const char *pos,
			const char *bolt_prefix)
{
	unsigned line = linenum(raw, &pos);

	fprintf(stderr, "%s:%u:unknown bolt %s\n",
		filename, line, bolt_prefix);
	exit(1);
}

static struct bolt_file *find_bolt(const char *bolt_prefix,
				   struct bolt_file *bolts)
{
	size_t i, n = tal_count(bolts);
	int boltnum;
	char *endp;

	for (i = 0; i < n; i++)
		if (streq(bolts[i].prefix, bolt_prefix))
			return bolts+i;

	/* Now search for numerical match. */
	boltnum = strtol(bolt_prefix, &endp, 10);
	if (endp != bolt_prefix && *endp == 0) {
		for (i = 0; i < n; i++)
			if (atoi(bolts[i].prefix) == boltnum)
				return bolts+i;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();

	struct bolt_file *bolts;
	int i;
	char *prefix = "BOLT";

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<bolt-dir> <srcfile>...\n"
			   "A source checker for BOLT RFC references.",
			   "Print this message.");
	opt_register_noarg("--verbose", opt_set_bool, &verbose,
			   "Print out files as we find them");
	opt_register_arg("--prefix", opt_set_charp, opt_show_charp, &prefix,
			 "Only check these markers");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc < 2)
		opt_usage_exit_fail("Expected a bolt directory");

	bolts = get_bolt_files(argv[1]);

	for (i = 2; i < argc; i++) {
		char *f = grab_file(NULL, argv[i]), *p, *bolt;
		size_t len;
		if (!f)
			err(1, "Loading %s", argv[i]);

		if (verbose)
			printf("Checking %s...\n", argv[i]);

		p = f;
		while ((bolt = find_bolt_ref(prefix, &p, &len)) != NULL) {
			char *pattern = code_to_regex(p, len, true);
			struct bolt_file *b = find_bolt(bolt, bolts);
			if (!b)
				fail_nobolt(argv[i], f, p, bolt);
			if (!tal_strreg(f, b->contents, pattern, NULL))
				fail_mismatch(argv[i], f, p, len, b);

			if (verbose)
				printf("  Found %.10s... in %s\n",
				       p, b->prefix);
			p += len;
		}
		tal_free(f);
	}
	return 0;
}
