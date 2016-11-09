/* Licensed under GPLv2+ - see LICENSE file for details */
#ifndef CCAN_OPT_H
#define CCAN_OPT_H
#include <ccan/compiler/compiler.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stdbool.h>
#include <stdlib.h>

struct opt_table;

/**
 * OPT_WITHOUT_ARG() - macro for initializing an opt_table entry (without arg)
 * @names: the names of the option eg. "--foo", "-f" or "--foo|-f|--foobar".
 * @cb: the callback when the option is found.
 * @arg: the argument to hand to @cb.
 * @desc: the description for opt_usage(), or opt_hidden.
 *
 * This is a typesafe wrapper for initializing a struct opt_table.  The callback
 * of type "char *cb(type *)", "char *cb(const type *)" or "char *cb(void *)",
 * where "type" is the type of the @arg argument.
 *
 * If the @cb returns non-NULL, opt_parse() will stop parsing, use the
 * returned string to form an error message for errlog(), free() the
 * string (or see opt_set_alloc) and return false.
 *
 * Any number of equivalent short or long options can be listed in @names,
 * separated by '|'.  Short options are a single hyphen followed by a single
 * character, long options are two hyphens followed by one or more characters.
 *
 * See Also:
 *	OPT_WITH_ARG()
 */
#define OPT_WITHOUT_ARG(names, cb, arg, desc)	\
	{ (names), OPT_CB_NOARG((cb), 0, (arg)), { (arg) }, (desc) }

/**
 * OPT_WITH_ARG() - macro for initializing an opt_table entry (with arg)
 * @names: the option names eg. "--foo=<arg>", "-f" or "-f|--foo <arg>".
 * @cb: the callback when the option is found (along with <arg>).
 * @show: the callback to print the value in get_usage (or NULL)
 * @arg: the argument to hand to @cb and @show
 * @desc: the description for opt_usage(), or opt_hidden.
 *
 * This is a typesafe wrapper for initializing a struct opt_table.  The callback
 * is of type "char *cb(const char *, type *)",
 * "char *cb(const char *, const type *)" or "char *cb(const char *, void *)",
 * where "type" is the type of the @arg argument.  The first argument to the
 * @cb is the argument found on the commandline.
 *
 * Similarly, if @show is not NULL, it should be of type "void *show(char *,
 * const type *)".  It should write up to OPT_SHOW_LEN bytes into the first
 * argument; unless it uses the entire OPT_SHOW_LEN bytes it should
 * nul-terminate that buffer.
 *
 * Any number of equivalent short or long options can be listed in @names,
 * separated by '|'.  Short options are a single hyphen followed by a single
 * character, long options are two hyphens followed by one or more characters.
 * A space or equals in @names is ignored for parsing, and only used
 * for printing the usage.
 *
 * If the @cb returns non-NULL, opt_parse() will stop parsing, use the
 * returned string to form an error message for errlog(), free() the
 * string (or see opt_set_alloc) and return false.
 *
 * See Also:
 *	OPT_WITHOUT_ARG()
 */
#define OPT_WITH_ARG(name, cb, show, arg, desc)	\
	{ (name), OPT_CB_ARG((cb), 0, (show), (arg)), { (arg) }, (desc) }

/**
 * OPT_SUBTABLE() - macro for including another table inside a table.
 * @table: the table to include in this table.
 * @desc: description of this subtable (for opt_usage()) or NULL.
 */
#define OPT_SUBTABLE(table, desc)					\
	{ (const char *)(table), OPT_SUBTABLE,				\
	  sizeof(_check_is_entry(table)) ? NULL : NULL, NULL, NULL,	\
	  { NULL }, (desc) }

/**
 * OPT_EARLY_WITHOUT_ARG() - macro for a early opt_table entry (without arg)
 * @names: the names of the option eg. "--foo", "-f" or "--foo|-f|--foobar".
 * @cb: the callback when the option is found.
 * @arg: the argument to hand to @cb.
 * @desc: the description for opt_usage(), or opt_hidden.
 *
 * This is the same as OPT_WITHOUT_ARG, but for opt_early_parse() instead of
 * opt_parse().
 *
 * See Also:
 *	OPT_EARLY_WITH_ARG(), opt_early_parse()
 */
#define OPT_EARLY_WITHOUT_ARG(names, cb, arg, desc)	\
	{ (names), OPT_CB_NOARG((cb), OPT_EARLY, (arg)), { (arg) }, (desc) }

/**
 * OPT_EARLY_WITH_ARG() - macro for an early opt_table entry (with arg)
 * @names: the option names eg. "--foo=<arg>", "-f" or "-f|--foo <arg>".
 * @cb: the callback when the option is found (along with <arg>).
 * @show: the callback to print the value in get_usage (or NULL)
 * @arg: the argument to hand to @cb and @show
 * @desc: the description for opt_usage(), or opt_hidden.
 *
 * This is the same as OPT_WITH_ARG, but for opt_early_parse() instead of
 * opt_parse().
 *
 * See Also:
 *	OPT_EARLY_WITHOUT_ARG(), opt_early_parse()
 */
#define OPT_EARLY_WITH_ARG(name, cb, show, arg, desc)	\
	{ (name), OPT_CB_ARG((cb), OPT_EARLY, (show), (arg)), { (arg) }, (desc) }

/**
 * OPT_ENDTABLE - macro to create final entry in table.
 *
 * This must be the final element in the opt_table array.
 */
#define OPT_ENDTABLE { NULL, OPT_END, NULL, NULL, NULL, { NULL }, NULL }

/**
 * opt_register_table - register a table of options
 * @table: the table of options
 * @desc: description of this subtable (for opt_usage()) or NULL.
 *
 * The table must be terminated by OPT_ENDTABLE.
 *
 * Example:
 * static int verbose = 0;
 * static struct opt_table opts[] = {
 * 	OPT_WITHOUT_ARG("--verbose", opt_inc_intval, &verbose,
 *			"Verbose mode (can be specified more than once)"),
 * 	OPT_WITHOUT_ARG("-v", opt_inc_intval, &verbose,
 *			"Verbose mode (can be specified more than once)"),
 * 	OPT_WITHOUT_ARG("--usage", opt_usage_and_exit,
 * 			"args...\nA silly test program.",
 *			"Print this message."),
 * 	OPT_ENDTABLE
 * };
 *
 * ...
 *	opt_register_table(opts, NULL);
 */
void opt_register_table(const struct opt_table *table, const char *desc);

/**
 * opt_register_noarg - register an option with no arguments
 * @names: the names of the option eg. "--foo", "-f" or "--foo|-f|--foobar".
 * @cb: the callback when the option is found.
 * @arg: the argument to hand to @cb.
 * @desc: the verbose description of the option (for opt_usage()), or NULL.
 *
 * This is used for registering a single commandline option which takes
 * no argument.
 *
 * The callback is of type "char *cb(type *)", "char *cb(const type *)"
 * or "char *cb(void *)", where "type" is the type of the @arg
 * argument.
 *
 * If the @cb returns non-NULL, opt_parse() will stop parsing, use the
 * returned string to form an error message for errlog(), free() the
 * string (or see opt_set_alloc) and return false.
 */
#define opt_register_noarg(names, cb, arg, desc)			\
	_opt_register((names), OPT_CB_NOARG((cb), 0, (arg)), (arg), (desc))

/**
 * opt_register_arg - register an option with an arguments
 * @names: the names of the option eg. "--foo", "-f" or "--foo|-f|--foobar".
 * @cb: the callback when the option is found.
 * @show: the callback to print the value in get_usage (or NULL)
 * @arg: the argument to hand to @cb.
 * @desc: the verbose description of the option (for opt_usage()), or NULL.
 *
 * This is used for registering a single commandline option which takes
 * an argument.
 *
 * The callback is of type "char *cb(const char *, type *)",
 * "char *cb(const char *, const type *)" or "char *cb(const char *, void *)",
 * where "type" is the type of the @arg argument.  The first argument to the
 * @cb is the argument found on the commandline.
 *
 * If the @cb returns non-NULL, opt_parse() will stop parsing, use the
 * returned string to form an error message for errlog(), free() the
 * string (or see opt_set_alloc) and return false.
 *
 * Example:
 * static char *explode(const char *optarg, void *unused UNNEEDED)
 * {
 *	errx(1, "BOOM! %s", optarg);
 * }
 * ...
 *	opt_register_arg("--explode|--boom", explode, NULL, NULL, opt_hidden);
 */
#define opt_register_arg(names, cb, show, arg, desc)			\
	_opt_register((names), OPT_CB_ARG((cb),0,(show), (arg)), (arg), (desc))

/**
 * opt_register_early_noarg - register an early option with no arguments
 * @names: the names of the option eg. "--foo", "-f" or "--foo|-f|--foobar".
 * @cb: the callback when the option is found.
 * @arg: the argument to hand to @cb.
 * @desc: the verbose description of the option (for opt_usage()), or NULL.
 *
 * This is the same as opt_register_noarg(), but for opt_early_parse().
 *
 * See Also:
 *	opt_register_early_arg(), opt_early_parse()
 */
#define opt_register_early_noarg(names, cb, arg, desc)			\
	_opt_register((names), OPT_CB_NOARG((cb), OPT_EARLY, (arg)),	\
		      (arg), (desc))

/**
 * opt_register_early_arg - register an early option with an arguments
 * @names: the names of the option eg. "--foo", "-f" or "--foo|-f|--foobar".
 * @cb: the callback when the option is found.
 * @show: the callback to print the value in get_usage (or NULL)
 * @arg: the argument to hand to @cb.
 * @desc: the verbose description of the option (for opt_usage()), or NULL.
 *
 * This is the same as opt_register_arg(), but for opt_early_parse().
 *
 * See Also:
 *	opt_register_early_noarg(), opt_early_parse()
 */
#define opt_register_early_arg(names, cb, show, arg, desc)		\
	_opt_register((names), OPT_CB_ARG((cb), OPT_EARLY, (show),(arg)), \
		      (arg), (desc))

/**
 * opt_parse - parse arguments.
 * @argc: pointer to argc
 * @argv: argv array.
 * @errlog: the function to print errors
 *
 * This iterates through the command line and calls callbacks registered with
 * opt_register_arg()/opt_register_noarg() or OPT_WITHOUT_ARG/OPT_WITH_ARG
 * entries in tables registered with opt_register_table().  As this occurs
 * each option is removed from argc and argv.
 *
 * If there are unknown options, missing arguments or a callback
 * returns false, then an error message is printed and false is
 * returned: the erroneous option is not removed.
 *
 * On success, argc and argv will contain only the non-option
 * elements, and true is returned.
 *
 * Example:
 *	if (!opt_parse(&argc, argv, opt_log_stderr)) {
 *		printf("You screwed up, aborting!\n");
 *		exit(1);
 *	}
 *
 * See Also:
 *	opt_log_stderr, opt_log_stderr_exit, opt_early_parse()
 */
bool opt_parse(int *argc, char *argv[], void (*errlog)(const char *fmt, ...));

/**
 * opt_early_parse - parse early arguments.
 * @argc: argc
 * @argv: argv array.
 * @errlog: the function to print errors
 *
 * There are times when you want to parse some arguments before any other
 * arguments; this is especially important for debugging flags (eg. --verbose)
 * when you have complicated callbacks in option processing.
 *
 * You can use opt_early_parse() to only parse options registered with
 * opt_register_earlyarg()/opt_register_early_noarg() or
 * OPT_EARLY_WITHOUT_ARG/OPT_EARLY_WITH_ARG entries in tables registered with
 * opt_register_table().
 *
 * Note that unlike opt_parse(), argc and argv are not altered.
 *
 * Example:
 *	if (!opt_early_parse(argc, argv, opt_log_stderr)) {
 *		printf("You screwed up, aborting!\n");
 *		exit(1);
 *	}
 *
 * See Also:
 *	opt_parse()
 */
bool opt_early_parse(int argc, char *argv[],
		     void (*errlog)(const char *fmt, ...));

/**
 * opt_free_table - reset the opt library.
 *
 * This frees the internal memory and returns counters to zero.  Call
 * this as the last opt function to avoid memory leaks.  You can also
 * use this function to reset option handling to its initial state (no
 * options registered).
 */
void opt_free_table(void);

/**
 * opt_set_alloc - set alloc/realloc/free function for opt to use.
 * @allocfn: allocator function
 * @reallocfn: reallocator function, ptr may be NULL, size never 0.
 * @freefn: free function
 *
 * By default opt uses malloc/realloc/free, and simply crashes if they fail.
 * You can set your own variants here.
 */
void opt_set_alloc(void *(*allocfn)(size_t size),
		   void *(*reallocfn)(void *ptr, size_t size),
		   void (*freefn)(void *ptr));

/**
 * opt_log_stderr - print message to stderr.
 * @fmt: printf-style format.
 *
 * This is a helper for opt_parse, to print errors to stderr.
 *
 * See Also:
 *	opt_log_stderr_exit
 */
void opt_log_stderr(const char *fmt, ...);

/**
 * opt_log_stderr_exit - print message to stderr, then exit(1)
 * @fmt: printf-style format.
 *
 * Just like opt_log_stderr, only then does exit(1).  This means that
 * when handed to opt_parse, opt_parse will never return false.
 *
 * Example:
 *	// This never returns false; just exits if there's an erorr.
 *	opt_parse(&argc, argv, opt_log_stderr_exit);
 */
void opt_log_stderr_exit(const char *fmt, ...);

/**
 * opt_invalid_argument - helper to allocate an "Invalid argument '%s'" string
 * @arg: the argument which was invalid.
 *
 * This is a helper for callbacks to return a simple error string.
 */
char *opt_invalid_argument(const char *arg);

/**
 * opt_usage - create usage message
 * @argv0: the program name
 * @extra: extra details to print after the initial command, or NULL.
 *
 * Creates a usage message, with the program name, arguments, some extra details
 * and a table of all the options with their descriptions.  If an option has
 * description opt_hidden, it is not shown here.
 *
 * The table of options is formatted such that descriptions are
 * wrapped on space boundaries.  If a description has a "\n" that is
 * left intact, and the following characters indented appropriately.
 * If the description begins with one or more space/tab (or has a
 * space or tab following a "\n") that line is output without wrapping.
 *
 * If "extra" is NULL, then the extra information is taken from any
 * registered option which calls opt_usage_and_exit().  This avoids duplicating
 * that string in the common case.
 *
 * The result should be passed to free().
 *
 * See Also:
 *	opt_usage_and_exit()
 *
 * Example:
 *	opt_register_arg("--explode|--boom", explode, NULL, NULL,
 *			 "This line will be wrapped by opt_usage\n"
 *			 "  But this won't because it's indented.");
 */
char *opt_usage(const char *argv0, const char *extra);

/**
 * opt_usage_exit_fail - complain about bad usage to stderr, exit with status 1.
 * @msg...: printf-style message to output.
 *
 * This prints argv[0] (if opt_parse has been called), a colon, then
 * the message to stderr (just like errx()).  Then it prints out the
 * usage message, taken from any registered option which uses
 * opt_usage_and_exit() as described in opt_usage(argv0, NULL) above.
 * Then it exits with status 1.
 *
 * Example:
 *	if (argc != 5)
 *		opt_usage_exit_fail("Need 5 arguments, only got %u", argc);
 */
void opt_usage_exit_fail(const char *msg, ...) NORETURN;

/**
 * opt_hidden - string for undocumented options.
 *
 * This can be used as the desc parameter if you want an option not to be
 * shown by opt_usage().
 */
extern const char opt_hidden[];

/* Maximum length of arg to show in opt_usage */
#define OPT_SHOW_LEN 80

/* Standard helpers.  You can write your own: */
/* Sets the @b to true. */
char *opt_set_bool(bool *b);
/* Sets @b based on arg: (yes/no/true/false). */
char *opt_set_bool_arg(const char *arg, bool *b);
void opt_show_bool(char buf[OPT_SHOW_LEN], const bool *b);
/* The inverse */
char *opt_set_invbool(bool *b);
void opt_show_invbool(char buf[OPT_SHOW_LEN], const bool *b);
/* Sets @b based on !arg: (yes/no/true/false). */
char *opt_set_invbool_arg(const char *arg, bool *b);

/* Set a char *. */
char *opt_set_charp(const char *arg, char **p);
void opt_show_charp(char buf[OPT_SHOW_LEN], char *const *p);

/* Set an integer value, various forms.  Sets to 1 on arg == NULL. */
char *opt_set_intval(const char *arg, int *i);
void opt_show_intval(char buf[OPT_SHOW_LEN], const int *i);
char *opt_set_uintval(const char *arg, unsigned int *ui);
void opt_show_uintval(char buf[OPT_SHOW_LEN], const unsigned int *ui);
char *opt_set_longval(const char *arg, long *l);
void opt_show_longval(char buf[OPT_SHOW_LEN], const long *l);
char *opt_set_ulongval(const char *arg, unsigned long *ul);
void opt_show_ulongval(char buf[OPT_SHOW_LEN], const unsigned long *ul);

/* Set an floating point value, various forms. */
char *opt_set_floatval(const char *arg, float *f);
void opt_show_floatval(char buf[OPT_SHOW_LEN], const float *f);
char *opt_set_doubleval(const char *arg, double *d);
void opt_show_doubleval(char buf[OPT_SHOW_LEN], const double *d);

/* the following setting functions accept k, M, G, T, P, or E suffixes, which
   multiplies the numeric value by the corresponding power of 1000 or 1024
   (for the _si and _bi versions, respectively).
 */
char *opt_set_intval_bi(const char *arg, int *i);
char *opt_set_intval_si(const char *arg, int *i);
char *opt_set_uintval_bi(const char *arg, unsigned int *u);
char *opt_set_uintval_si(const char *arg, unsigned int *u);
char *opt_set_longval_bi(const char *arg, long *l);
char *opt_set_longval_si(const char *arg, long *l);
char *opt_set_ulongval_bi(const char *arg, unsigned long *ul);
char *opt_set_ulongval_si(const char *arg, unsigned long *ul);
char *opt_set_longlongval_bi(const char *arg, long long *ll);
char *opt_set_longlongval_si(const char *arg, long long *ll);
char *opt_set_ulonglongval_bi(const char *arg, unsigned long long *ll);
char *opt_set_ulonglongval_si(const char *arg, unsigned long long *ll);


void opt_show_intval_bi(char buf[OPT_SHOW_LEN], const int *x);
void opt_show_longval_bi(char buf[OPT_SHOW_LEN], const long *x);
void opt_show_longlongval_bi(char buf[OPT_SHOW_LEN], const long long *x);
void opt_show_uintval_bi(char buf[OPT_SHOW_LEN], const unsigned int *x);
void opt_show_ulongval_bi(char buf[OPT_SHOW_LEN], const unsigned long *x);
void opt_show_ulonglongval_bi(char buf[OPT_SHOW_LEN], const unsigned long long *x);

void opt_show_intval_si(char buf[OPT_SHOW_LEN], const int *x);
void opt_show_longval_si(char buf[OPT_SHOW_LEN], const long *x);
void opt_show_longlongval_si(char buf[OPT_SHOW_LEN], const long long *x);
void opt_show_uintval_si(char buf[OPT_SHOW_LEN], const unsigned int *x);
void opt_show_ulongval_si(char buf[OPT_SHOW_LEN], const unsigned long *x);
void opt_show_ulonglongval_si(char buf[OPT_SHOW_LEN], const unsigned long long *x);




/* Increment and decrement. */
char *opt_inc_intval(int *i);
char *opt_dec_intval(int *i);

/* Display version string to stdout, exit(0). */
char *opt_version_and_exit(const char *version);

/* Display usage string to stdout, exit(0). */
char *opt_usage_and_exit(const char *extra);

/* Below here are private declarations. */
/* You can use this directly to build tables, but the macros will ensure
 * consistency and type safety. */
enum opt_type {
	OPT_NOARG = 1,		/* -f|--foo */
	OPT_HASARG = 2,		/* -f arg|--foo=arg|--foo arg */
	OPT_SUBTABLE = 4,	/* Actually, longopt points to a subtable... */
	OPT_EARLY = 8,		/* Parse this from opt_early_parse() only. */
	OPT_END = 16,		/* End of the table. */
};

struct opt_table {
	const char *names; /* pipe-separated names, --longopt or -s */
	enum opt_type type;
	char *(*cb)(void *arg); /* OPT_NOARG */
	char *(*cb_arg)(const char *optarg, void *arg); /* OPT_HASARG */
	void (*show)(char buf[OPT_SHOW_LEN], const void *arg);
	union {
		const void *carg;
		void *arg;
		size_t tlen;
	} u;
	const char *desc;
};

/* Resolves to the four parameters for non-arg callbacks. */
#define OPT_CB_NOARG(cb, pre, arg)			\
	OPT_NOARG|(pre),				\
	typesafe_cb_cast3(char *(*)(void *),	\
			  char *(*)(typeof(*(arg))*),	\
			  char *(*)(const typeof(*(arg))*),	\
			  char *(*)(const void *), (cb)),	\
	NULL, NULL

/* Resolves to the four parameters for arg callbacks. */
#define OPT_CB_ARG(cb, pre, show, arg)					\
	OPT_HASARG|(pre), NULL,						\
	typesafe_cb_cast3(char *(*)(const char *,void *),	\
			  char *(*)(const char *, typeof(*(arg))*),	\
			  char *(*)(const char *, const typeof(*(arg))*), \
			  char *(*)(const char *, const void *),	\
			  (cb)),					\
	typesafe_cb_cast(void (*)(char buf[], const void *),		\
			 void (*)(char buf[], const typeof(*(arg))*), (show))

/* Non-typesafe register function. */
void _opt_register(const char *names, enum opt_type type,
		   char *(*cb)(void *arg),
		   char *(*cb_arg)(const char *optarg, void *arg),
		   void (*show)(char buf[OPT_SHOW_LEN], const void *arg),
		   const void *arg, const char *desc);

/* We use this to get typechecking for OPT_SUBTABLE */
static inline int _check_is_entry(struct opt_table *e UNUSED) { return 0; }

#endif /* CCAN_OPT_H */
