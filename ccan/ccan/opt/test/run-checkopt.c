#include "config.h"
#include <stdio.h>
#include <ccan/tap/tap.h>
#include <setjmp.h>
#include <stdlib.h>
#include <limits.h>
#include <err.h>
#include "utils.h"

/* We don't actually want it to exit... */
static jmp_buf exited;
#define failmsg save_and_jump

static void save_and_jump(const char *fmt, ...);

#include <ccan/opt/helpers.c>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/parse.c>

static char *output = NULL;

static int saved_vprintf(const char *fmt, va_list ap)
{
	char *p;
	int ret = vasprintf(&p, fmt, ap);

	if (output) {
		output = realloc(output, strlen(output) + strlen(p) + 1);
		strcat(output, p);
		free(p);
	} else
		output = p;
	return ret;
}

static void save_and_jump(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	saved_vprintf(fmt, ap);
	va_end(ap);
	longjmp(exited, 1);
}

static void reset(void)
{
	free(output);
	output = NULL;
	free(opt_table);
	opt_table = NULL;
	opt_count = opt_num_short = opt_num_short_arg = opt_num_long = 0;
}

int main(void)
{
	int exitval;

	plan_tests(14);

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* Bad type. */
		_opt_register("-a", OPT_SUBTABLE, (void *)opt_version_and_exit,
			      NULL, NULL, "1.2.3", "");
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output, "Option -a: unknown entry type"));
	}
	reset();

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* NULL description. */
		opt_register_noarg("-a", test_noarg, "", NULL);
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output, "Option -a: description cannot be NULL"));
	}
	reset();

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* Bad option name. */
		opt_register_noarg("a", test_noarg, "", "");
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output, "Option a: does not begin with '-'"));
	}

	reset();

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* Bad option name. */
		opt_register_noarg("--", test_noarg, "", "");
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output, "Option --: invalid long option '--'"));
	}

	reset();

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* Bad option name. */
		opt_register_noarg("--a|-aaa", test_noarg, "", "");
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output,
			   "Option --a|-aaa: invalid short option '-aaa'"));
	}
	reset();

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* Documentation for non-optios. */
		opt_register_noarg("--a foo", test_noarg, "", "");
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output,
			   "Option --a foo: does not take arguments 'foo'"));
	}
	reset();

	exitval = setjmp(exited);
	if (exitval == 0) {
		/* Documentation for non-optios. */
		opt_register_noarg("--a=foo", test_noarg, "", "");
		fail("_opt_register returned?");
	} else {
		ok1(exitval == 1);
		ok1(strstr(output,
			   "Option --a=foo: does not take arguments 'foo'"));
	}
	return exit_status();
}
