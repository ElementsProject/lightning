#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>
#include "utils.h"

int main(int argc, char *argv[])
{
	const char *myname = argv[0];

	plan_tests(28);

	opt_register_noarg("-a", test_noarg, NULL, "All");
	opt_register_noarg("--aaa", test_noarg, NULL, "AAAAll");
	opt_register_arg("-b|--bbb", test_arg, NULL, "bbb", "AAAAAAll");

	ok1(strcmp(opt_table[0].names, "-a") == 0);
	ok1(opt_table[0].type == OPT_NOARG);
	ok1(strcmp(opt_table[1].names, "--aaa") == 0);
	ok1(opt_table[1].type == OPT_NOARG);
	ok1(strcmp(opt_table[2].names, "-b|--bbb") == 0);
	ok1(opt_table[2].type == OPT_HASARG);

	opt_table[0].type |= (1 << OPT_USER_START);
	opt_table[1].type |= ((1 << OPT_USER_END)-1) - ((1 << OPT_USER_START)-1);
	opt_table[2].type |= (1 << OPT_USER_END);

	/* Should all work fine! */
	ok1(parse_args(&argc, &argv, "-a", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(test_cb_called == 1);

	ok1(parse_args(&argc, &argv, "--aaa", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(test_cb_called == 2);

	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "-b", NULL) == false);
	ok1(test_cb_called == 2);
	ok1(parse_args(&argc, &argv, "-b", "bbb", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 3);

	ok1(parse_args(&argc, &argv, "--bbb", "bbb", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 4);

	/* parse_args allocates argv */
	free(argv);
	return exit_status();
}
