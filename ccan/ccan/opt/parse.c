/* Licensed under GPLv2+ - see LICENSE file for details */
/* Actual code to parse commandline. */
#include <ccan/opt/opt.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "private.h"

/* glibc does this as:
/tmp/opt-example: invalid option -- 'x'
/tmp/opt-example: unrecognized option '--long'
/tmp/opt-example: option '--someflag' doesn't allow an argument
/tmp/opt-example: option '--s' is ambiguous
/tmp/opt-example: option requires an argument -- 's'
*/
static int parse_err(void (*errlog)(const char *fmt, ...),
		     const char *argv0,
		     const char *arg, unsigned len,
		     const char *problem)
{
	errlog("%s: %.*s: %s", argv0, len, arg, problem);
	return -1;
}

static void consume_option(int *argc, char *argv[], unsigned optnum)
{
	memmove(&argv[optnum], &argv[optnum+1],
		sizeof(argv[optnum]) * (*argc-optnum));
	(*argc)--;
}

/* This sets the len and o to indicate how far it is into the
 * opt_table's names field. */
static struct opt_table *opt_find_long_extra(const char *arg,
					     const char **optarg,
					     unsigned int *len,
					     const char **o)
{
	unsigned i;

	*optarg = NULL;
	for (*o = first_lopt(&i, len);
	     *o;
	     *o = next_lopt(*o, &i, len)) {
		if (strncmp(arg, *o, *len) != 0)
			continue;
		if (arg[*len] == '=')
			*optarg = arg + *len + 1;
		else if (arg[*len] != '\0')
			continue;
		return &opt_table[i];

	}
	return NULL;
}

struct opt_table *opt_find_long(const char *arg, const char **optarg)
{
	unsigned len;
	const char *o;

	return opt_find_long_extra(arg, optarg ? optarg : &o, &len, &o);
}

static struct opt_table *opt_find_short_extra(char arg, const char **o)
{
	unsigned i;
	for (*o = first_sopt(&i); *o; *o = next_sopt(*o, &i)) {
		if (arg == **o)
			return &opt_table[i];
	}
	return NULL;
}

struct opt_table *opt_find_short(char arg)
{
	const char *o;
	return opt_find_short_extra(arg, &o);
}

/* Returns 1 if argument consumed, 0 if all done, -1 on error. */
int parse_one(int *argc, char *argv[], enum opt_type is_early, unsigned *offset,
	      void (*errlog)(const char *fmt, ...), bool unknown_ok)
{
	unsigned arg, len;
	const char *o, *optarg = NULL;
	char *problem = NULL;
	struct opt_table *ot;

	if (getenv("POSIXLY_CORRECT")) {
		/* Don't find options after non-options. */
		arg = 1;
	} else {
		for (arg = 1; argv[arg]; arg++) {
			if (argv[arg][0] == '-')
				break;
		}
	}

	if (!argv[arg] || argv[arg][0] != '-')
		return 0;

	/* Special arg terminator option. */
	if (strcmp(argv[arg], "--") == 0) {
		consume_option(argc, argv, arg);
		return 0;
	}

	/* Long options start with -- */
	if (argv[arg][1] == '-') {
		assert(*offset == 0);

		ot = opt_find_long_extra(argv[arg]+2, &optarg, &len, &o);
		if (!ot) {
			if (unknown_ok)
				goto ok;
			return parse_err(errlog, argv[0],
					 argv[arg], strlen(argv[arg]),
					 "unrecognized option");
		}

		/* For error messages, we include the leading '--' */
		o -= 2;
		len += 2;
	} else {
		ot = opt_find_short_extra(argv[arg][*offset + 1], &o);
		if (!ot) {
			if (unknown_ok) {
				(*offset)++;
				goto ok;
			}
			return parse_err(errlog, argv[0],
					 argv[arg], strlen(argv[arg]),
					 "unrecognized option");
		}

		(*offset)++;
		/* For error messages, we include the leading '-' */
		o--;
		len = 2;
	}

	if (ot->type & OPT_NOARG) {
		if (optarg)
			return parse_err(errlog, argv[0], o, len,
					 "doesn't allow an argument");
		if ((ot->type & OPT_EARLY) == is_early)
			problem = ot->cb(ot->u.arg);
	} else {
		if (!optarg) {
			/* Swallow any short options as optarg, eg -afile */
			if (*offset && argv[arg][*offset + 1]) {
				optarg = argv[arg] + *offset + 1;
				*offset = 0;
			} else
				optarg = argv[arg+1];
		}
		if (!optarg)
			return parse_err(errlog, argv[0], o, len,
					 "requires an argument");
		if ((ot->type & OPT_EARLY) == is_early)
			problem = ot->cb_arg(optarg, ot->u.arg);
	}

	if (problem) {
		parse_err(errlog, argv[0], o, len, problem);
		opt_alloc.free(problem);
		return -1;
	}

ok:
	/* If no more letters in that short opt, reset offset. */
	if (*offset && !argv[arg][*offset + 1])
		*offset = 0;

	/* All finished with that option? */
	if (*offset == 0) {
		consume_option(argc, argv, arg);
		if (optarg && optarg == argv[arg])
			consume_option(argc, argv, arg);
	}
	return 1;
}
