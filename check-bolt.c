/* Simple program to search for BOLT references in C files and make sure
 * they're accurate. */
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <sys/types.h>
#include <dirent.h>

static bool verbose = false;

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

static char **get_bolt_files(const char *dir)
{
	struct dirent *e;
	char **bolts = tal_arr(NULL, char *, 0);
	DIR *d = opendir(dir);
	if (!d)
		err(1, "Opening BOLT dir %s", dir);

	while ((e = readdir(d)) != NULL) {
		char *endp;
		unsigned long l;

		/* Must start with the bold number. */
		l = strtoul(e->d_name, &endp, 10);
		if (endp == e->d_name)
			continue;

		/* Must end in .md */
		if (!strends(e->d_name, ".md"))
			continue;

		if (l >= tal_count(bolts))
			tal_resizez(&bolts, l+1);

		if (verbose)
			printf("Found bolt %s: #%lu\n", e->d_name, l);

		bolts[l] = canonicalize(grab_file(NULL,
						  path_join(NULL, dir,
							    e->d_name)));
	}
	return bolts;
}

static char *find_bolt_ref(char *p, size_t *len, size_t *bolt)
{
	for (;;) {
		char *end;

		/* BOLT #X: */
		p = strstr(p, "BOLT");
		if (!p)
			return NULL;
		p += 4;
		while (cisspace(*p))
			p++;
		if (*p != '#')
			continue;
		p++;
		*bolt = strtoul(p, &end, 10);
		if (!*bolt || p == end)
			continue;
		p = end;
		while (cisspace(*p))
			p++;
		if (*p != ':')
			continue;
		p++;

		end = strstr(p, "*/");
		if (!end)
			*len = strlen(p);
		else
			*len = end - p;
		return p;
	}
}

static char *code_to_regex(const char *code, size_t len, bool escape)
{
	char *pattern = tal_arr(NULL, char, len*2 + 1), *p;
	size_t i;
	bool after_nl = false;

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
			/* Fall thru. */
		case '.':
		case '$':
		case '^':
		case '[':
		case ']':
		case '(':
		case ')':
		case '+':
		case '|':
			if (escape)
				*(p++) = '\\';
			/* Fall thru */
		default:
			*(p++) = code[i];
		}
	}
	*p = '\0';
	return canonicalize(pattern);
}

static void fail(const char *filename, const char *raw, const char *pos,
		 size_t len, const char *bolt)
{
	unsigned line = 0; /* Out-by-one below */
	const char *l = raw;

	while (l < pos) {
		l = strchr(l, '\n');
		line++;
		if (!l)
			l = pos + strlen(pos);
		else
			l++;
	}

	if (bolt) {
		char *try;

		fprintf(stderr, "%s:%u:%.*s\n", filename, line,
			(int)(l - pos), pos);
		/* Try to find longest match, as a hint. */
		try = code_to_regex(pos, len, false);
		while (strlen(try)) {
			const char *p = strstr(bolt, try);
			if (p) {
				fprintf(stderr, "Closest match: %s...[%.20s]\n",
					try, p + strlen(try));
				break;
			}
			try[strlen(try)-1] = '\0';
		}
	} else {
		fprintf(stderr, "%s:%u:Unknown bolt\n", filename, line);
	}		
	exit(1);
}
	
int main(int argc, char *argv[])
{
	char **bolts;
	int i;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<bolt-dir> <srcfile>...\n"
			   "A source checker for BOLT RFC references.",
			   "Print this message.");
	opt_register_noarg("--verbose", opt_set_bool, &verbose,
			   "Print out files as we find them");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc < 2)
		opt_usage_exit_fail("Expected a bolt directory");

	bolts = get_bolt_files(argv[1]);

	for (i = 2; i < argc; i++) {
		char *f = grab_file(NULL, argv[i]), *p;
		size_t len, bolt;
		if (!f)
			err(1, "Loading %s", argv[i]);

		if (verbose)
			printf("Checking %s...\n", argv[i]);

		p = f;
		while ((p = find_bolt_ref(p, &len, &bolt)) != NULL) {
			char *pattern = code_to_regex(p, len, true);
			if (bolt >= tal_count(bolts) || !bolts[bolt])
				fail(argv[i], f, p, len, NULL);
			if (!tal_strreg(f, bolts[bolt], pattern, NULL))
				fail(argv[i], f, p, len, bolts[bolt]);

			if (verbose)
				printf("  Found %.10s... in %zu\n",
				       p, bolt);
			p += len;
		}
		tal_free(f);
	}
	return 0;
}
	
