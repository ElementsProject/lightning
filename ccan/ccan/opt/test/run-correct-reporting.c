/* Make sure when multiple equivalent options, correct one is used for errors */

#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>
#include "utils.h"

int main(int argc, char *argv[])
{
	plan_tests(12);

	/* --aaa without args. */
	opt_register_arg("-a|--aaa", test_arg, NULL, "aaa", "");
	ok1(!parse_args(&argc, &argv, "--aaa", NULL));
	ok1(strstr(err_output, ": --aaa: requires an argument"));
	free(err_output);
	err_output = NULL;
	ok1(!parse_args(&argc, &argv, "-a", NULL));
	ok1(strstr(err_output, ": -a: requires an argument"));
	free(err_output);
	err_output = NULL;

	/* Multiple */
	opt_register_arg("--bbb|-b|-c|--ccc", test_arg, NULL, "aaa", "");
	ok1(!parse_args(&argc, &argv, "--bbb", NULL));
	ok1(strstr(err_output, ": --bbb: requires an argument"));
	free(err_output);
	err_output = NULL;
	ok1(!parse_args(&argc, &argv, "-b", NULL));
	ok1(strstr(err_output, ": -b: requires an argument"));
	free(err_output);
	err_output = NULL;
	ok1(!parse_args(&argc, &argv, "-c", NULL));
	ok1(strstr(err_output, ": -c: requires an argument"));
	free(err_output);
	err_output = NULL;
	ok1(!parse_args(&argc, &argv, "--ccc", NULL));
	ok1(strstr(err_output, ": --ccc: requires an argument"));
	free(err_output);
	err_output = NULL;

	/* parse_args allocates argv */
	free(argv);
	return exit_status();
}

