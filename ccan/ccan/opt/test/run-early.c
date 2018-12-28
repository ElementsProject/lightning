/* With errlog == NULL, we never get a "failure". */
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>
#include "utils.h"

struct opt_table some_early_table[] = {
	OPT_EARLY_WITHOUT_ARG("--verbose|-v", test_noarg,
			      "vvv", "Description of verbose"),
	OPT_EARLY_WITH_ARG("--debug|-d", test_arg, show_arg,
			      "ddd", "Description of debug"),
	OPT_WITHOUT_ARG("-h|--hhh", test_noarg, "hhh", "Description of hhh"),
	OPT_ENDTABLE
};

int main(int argc, char *argv[])
{
	const char *myname = argv[0];

	plan_tests(37);

	/* Simple short arg.*/
	opt_register_noarg("-a", test_noarg, NULL, "All");
	opt_register_early_noarg("-b", test_noarg, NULL, "All");

	/* Early parsing doesn't mangle. */
	ok1(parse_early_args(&argc, &argv, "-a", NULL));
	ok1(argc == 2);
	ok1(argv[0] == myname);
	ok1(strcmp(argv[1], "-a") == 0);
	ok1(argv[2] == NULL);
	ok1(test_cb_called == 0);

	/* ... even if it processes arg. */
	ok1(parse_early_args(&argc, &argv, "-b", NULL));
	ok1(argc == 2);
	ok1(argv[0] == myname);
	ok1(strcmp(argv[1], "-b") == 0);
	ok1(argv[2] == NULL);
	ok1(test_cb_called == 1);

	ok1(parse_early_args(&argc, &argv, "-ab", NULL));
	ok1(argc == 2);
	ok1(argv[0] == myname);
	ok1(strcmp(argv[1], "-ab") == 0);
	ok1(argv[2] == NULL);
	ok1(test_cb_called == 2);

	ok1(parse_args(&argc, &argv, "-ab", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 3);

	opt_register_table(some_early_table, "Some early args");
	ok1(parse_early_args(&argc, &argv, "--verbose", "-dddd", "-h", NULL));
	ok1(argc == 4);
	ok1(argv[0] == myname);
	ok1(strcmp(argv[1], "--verbose") == 0);
	ok1(strcmp(argv[2], "-dddd") == 0);
	ok1(strcmp(argv[3], "-h") == 0);
	ok1(argv[4] == NULL);
	ok1(test_cb_called == 5);

	ok1(parse_args(&argc, &argv, "--verbose", "-d", "ddd", "-h", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 6);

	/* parse_args allocates argv */
	free(argv);
	return exit_status();
}
