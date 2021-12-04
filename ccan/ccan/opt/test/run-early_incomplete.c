/* With errlog == NULL, we never get a "failure". */
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>
#include "utils.h"

int main(int argc, char *argv[])
{
	plan_tests(8);

	/* Simple short args.*/
	opt_register_noarg("-a", test_noarg, NULL, "All");
	opt_register_early_noarg("-b|--blong", test_noarg, NULL, "All");

	/* This is OK. */
	ok1(parse_early_args_incomplete(&argc, &argv, "-c", NULL));
	ok1(test_cb_called == 0);

	/* Skips letters correctly */
	ok1(parse_early_args_incomplete(&argc, &argv, "-ca", NULL));
	ok1(test_cb_called == 0); /* a is not an early arg! */

	test_cb_called = 0;
	ok1(parse_early_args_incomplete(&argc, &argv, "-bca", NULL));
	ok1(test_cb_called == 1);

	test_cb_called = 0;
	ok1(parse_early_args_incomplete(&argc, &argv, "--unknown", "--also-unknown", "--blong", NULL));
	ok1(test_cb_called == 1);

	/* parse_args allocates argv */
	free(argv);
	return exit_status();
}
