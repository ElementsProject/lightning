/* Make sure we still work with no options registered */
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

	plan_tests(7);

	/* Simple short arg.*/
	ok1(!parse_args(&argc, &argv, "-a", NULL));
	/* Simple long arg.*/
	ok1(!parse_args(&argc, &argv, "--aaa", NULL));

	/* Extra arguments preserved. */
	ok1(parse_args(&argc, &argv, "extra", "args", NULL));
	ok1(argc == 3);
	ok1(argv[0] == myname);
	ok1(strcmp(argv[1], "extra") == 0);
	ok1(strcmp(argv[2], "args") == 0);

	/* parse_args allocates argv */
	free(argv);

	return exit_status();
}

