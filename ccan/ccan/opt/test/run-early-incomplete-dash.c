/* Regression test for the bare "-" argument in opt_early_parse_incomplete().
 *
 * parse_one() looks up argv[arg][*offset + 1] as a short option.  For a
 * bare "-" that is the terminating NUL (which can never be a registered
 * option); the unknown_ok path then increments *offset past the NUL and
 * the "any more letters?" check reads argv[arg][*offset + 1], one byte
 * beyond the end of the string.  With execve-style packed argv strings
 * that byte is the first character of the NEXT argument, so a non-option
 * operand can be mistaken for short-option letters inside "-", firing
 * callbacks for arguments the user never supplied as options.
 *
 * Currently fails (test 2) without the fix.
 */
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>
#include "utils.h"

static bool v;

int main(void)
{
	alarm(10);
	plan_tests(4);

	opt_register_early_noarg("-v", opt_set_bool, &v, "verbose");

	/* Mimic execve string packing: "prog\0-\0v\0"; the byte after the
	 * "-" string is 'v', the first char of the next (non-option) arg. */
	{
		static char storage[] = "prog\0-\0v\0";
		char *myargv[4] = { storage, storage + 5, storage + 7, NULL };

		v = false;
		ok1(opt_early_parse_incomplete(3, myargv, save_err_output));
		ok1(v == false); /* "v" is an operand; callback must not fire */
	}

	/* An isolated bare "-" must be handled (and terminate) too. */
	{
		char *myargv[3] = { (char *)"prog", (char *)"-", NULL };

		v = false;
		ok1(opt_early_parse_incomplete(2, myargv, save_err_output));
		ok1(v == false);
	}

	opt_free_table();
	free(err_output);
	return exit_status();
}
