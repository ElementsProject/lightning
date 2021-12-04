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

	plan_tests(15);

	opt_register_noarg("--aaa|-a", test_noarg, NULL, "AAAAAAll");
	opt_register_arg("-b", test_arg, NULL, "bbb", "b");

	/* We can't unregister wrong ones, but can unregister correct one */
	ok1(!opt_unregister("--aaa"));
	ok1(!opt_unregister("-a"));
	ok1(opt_unregister("--aaa|-a"));

	/* Arg parsing works as if we'd never registered it */
	ok1(parse_args(&argc, &argv, "-bbbb", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 1);

	ok1(!parse_args(&argc, &argv, "--aaa", NULL));

	/* We can still add another one OK. */
	opt_register_noarg("-c", test_noarg, NULL, "AAAAAAll");
	ok1(parse_args(&argc, &argv, "-c", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 2);

	/* parse_args allocates argv */
	free(argv);
	return exit_status();
}
