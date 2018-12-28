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

	plan_tests(215);

	/* Simple short arg.*/
	opt_register_noarg("-a", test_noarg, NULL, "All");
	ok1(parse_args(&argc, &argv, "-a", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 1);

	/* Simple long arg. */
	opt_register_noarg("--aaa", test_noarg, NULL, "AAAAll");
	ok1(parse_args(&argc, &argv, "--aaa", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 2);

	/* Both long and short args. */
	opt_register_noarg("--aaa|-a", test_noarg, NULL, "AAAAAAll");
	ok1(parse_args(&argc, &argv, "--aaa", "-a", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 4);

	/* Extra arguments preserved. */
	ok1(parse_args(&argc, &argv, "--aaa", "-a", "extra", "args", NULL));
	ok1(argc == 3);
	ok1(argv[0] == myname);
	ok1(strcmp(argv[1], "extra") == 0);
	ok1(strcmp(argv[2], "args") == 0);
	ok1(test_cb_called == 6);

	/* Malformed versions. */
	ok1(!parse_args(&argc, &argv, "--aaa=arg", NULL));
	ok1(strstr(err_output, ": --aaa: doesn't allow an argument"));
	ok1(!parse_args(&argc, &argv, "--aa", NULL));
	ok1(strstr(err_output, ": --aa: unrecognized option"));
	ok1(!parse_args(&argc, &argv, "--aaargh", NULL));
	ok1(strstr(err_output, ": --aaargh: unrecognized option"));

	/* Argument variants. */
	reset_options();
	test_cb_called = 0;
	opt_register_arg("-a|--aaa", test_arg, NULL, "aaa", "AAAAAAll");
	ok1(parse_args(&argc, &argv, "--aaa", "aaa", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(test_cb_called == 1);

	ok1(parse_args(&argc, &argv, "--aaa=aaa", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(test_cb_called == 2);

	ok1(parse_args(&argc, &argv, "-a", "aaa", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(test_cb_called == 3);

	/* Malformed versions. */
	ok1(!parse_args(&argc, &argv, "-a", NULL));
	ok1(strstr(err_output, ": -a: requires an argument"));
	ok1(!parse_args(&argc, &argv, "--aaa", NULL));
	ok1(strstr(err_output, ": --aaa: requires an argument"));
	ok1(!parse_args(&argc, &argv, "--aa", NULL));
	ok1(strstr(err_output, ": --aa: unrecognized option"));
	ok1(!parse_args(&argc, &argv, "--aaargh", NULL));
	ok1(strstr(err_output, ": --aaargh: unrecognized option"));

	/* Now, tables. */
	/* Short table: */
	reset_options();
	test_cb_called = 0;
	opt_register_table(short_table, NULL);
	ok1(parse_args(&argc, &argv, "-a", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 1);
	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "-b", NULL) == false);
	ok1(test_cb_called == 1);
	ok1(parse_args(&argc, &argv, "-b", "b", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 2);

	/* Long table: */
	reset_options();
	test_cb_called = 0;
	opt_register_table(long_table, NULL);
	ok1(parse_args(&argc, &argv, "--ddd", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 1);
	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "--eee", NULL) == false);
	ok1(test_cb_called == 1);
	ok1(parse_args(&argc, &argv, "--eee", "eee", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 2);

	/* Short and long, both. */
	reset_options();
	test_cb_called = 0;
	opt_register_table(long_and_short_table, NULL);
	ok1(parse_args(&argc, &argv, "-g", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 1);
	ok1(parse_args(&argc, &argv, "--ggg", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 2);
	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "-h", NULL) == false);
	ok1(test_cb_called == 2);
	ok1(parse_args(&argc, &argv, "-h", "hhh", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 3);
	ok1(parse_args(&argc, &argv, "--hhh", NULL) == false);
	ok1(test_cb_called == 3);
	ok1(parse_args(&argc, &argv, "--hhh", "hhh", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 4);

	/* Those will all work as tables. */
	test_cb_called = 0;
	reset_options();
	opt_register_table(subtables, NULL);
	ok1(parse_args(&argc, &argv, "-a", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 1);
	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "-b", NULL) == false);
	ok1(test_cb_called == 1);
	ok1(parse_args(&argc, &argv, "-b", "b", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 2);

	ok1(parse_args(&argc, &argv, "--ddd", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 3);
	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "--eee", NULL) == false);
	ok1(test_cb_called == 3);
	ok1(parse_args(&argc, &argv, "--eee", "eee", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 4);

	/* Short and long, both. */
	ok1(parse_args(&argc, &argv, "-g", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 5);
	ok1(parse_args(&argc, &argv, "--ggg", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 6);
	/* This one needs an arg. */
	ok1(parse_args(&argc, &argv, "-h", NULL) == false);
	ok1(test_cb_called == 6);
	ok1(parse_args(&argc, &argv, "-h", "hhh", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 7);
	ok1(parse_args(&argc, &argv, "--hhh", NULL) == false);
	ok1(test_cb_called == 7);
	ok1(parse_args(&argc, &argv, "--hhh", "hhh", NULL));
	ok1(argc == 1);
	ok1(argv[0] == myname);
	ok1(argv[1] == NULL);
	ok1(test_cb_called == 8);

	/* Now the tricky one: -? must not be confused with an unknown option */
	test_cb_called = 0;
	reset_options();

	/* glibc's getopt does not handle ? with arguments. */
	opt_register_noarg("-?", test_noarg, NULL, "Help");
	ok1(parse_args(&argc, &argv, "-?", NULL));
	ok1(test_cb_called == 1);
	ok1(parse_args(&argc, &argv, "-a", NULL) == false);
	ok1(test_cb_called == 1);
	ok1(strstr(err_output, ": -a: unrecognized option"));
	ok1(parse_args(&argc, &argv, "--aaaa", NULL) == false);
	ok1(test_cb_called == 1);
	ok1(strstr(err_output, ": --aaaa: unrecognized option"));

	test_cb_called = 0;
	reset_options();

	/* Corner cases involving short arg parsing weirdness. */
	opt_register_noarg("-a|--aaa", test_noarg, NULL, "a");
	opt_register_arg("-b|--bbb", test_arg, NULL, "bbb", "b");
	opt_register_arg("-c|--ccc", test_arg, NULL, "aaa", "c");
	/* -aa == -a -a */
	ok1(parse_args(&argc, &argv, "-aa", NULL));
	ok1(test_cb_called == 2);
	ok1(parse_args(&argc, &argv, "-aab", NULL) == false);
	ok1(test_cb_called == 4);
	ok1(strstr(err_output, ": -b: requires an argument"));
	ok1(parse_args(&argc, &argv, "-bbbb", NULL));
	ok1(test_cb_called == 5);
	ok1(parse_args(&argc, &argv, "-aabbbb", NULL));
	ok1(test_cb_called == 8);
	ok1(parse_args(&argc, &argv, "-aabbbb", "-b", "bbb", NULL));
	ok1(test_cb_called == 12);
	ok1(parse_args(&argc, &argv, "-aabbbb", "--bbb", "bbb", NULL));
	ok1(test_cb_called == 16);
	ok1(parse_args(&argc, &argv, "-aabbbb", "--bbb=bbb", NULL));
	ok1(test_cb_called == 20);
	ok1(parse_args(&argc, &argv, "-aacaaa", NULL));
	ok1(test_cb_called == 23);
	ok1(parse_args(&argc, &argv, "-aacaaa", "-a", NULL));
	ok1(test_cb_called == 27);
	ok1(parse_args(&argc, &argv, "-aacaaa", "--bbb", "bbb", "-aacaaa",
		       NULL));
	ok1(test_cb_called == 34);

	test_cb_called = 0;
	reset_options();

	/* -- and POSIXLY_CORRECT */
	opt_register_noarg("-a|--aaa", test_noarg, NULL, "a");
	ok1(parse_args(&argc, &argv, "-a", "--", "-a", NULL));
	ok1(test_cb_called == 1);
	ok1(argc == 2);
	ok1(strcmp(argv[1], "-a") == 0);
	ok1(!argv[2]);

	unsetenv("POSIXLY_CORRECT");
	ok1(parse_args(&argc, &argv, "-a", "somearg", "-a", "--", "-a", NULL));
	ok1(test_cb_called == 3);
	ok1(argc == 3);
	ok1(strcmp(argv[1], "somearg") == 0);
	ok1(strcmp(argv[2], "-a") == 0);
	ok1(!argv[3]);

	setenv("POSIXLY_CORRECT", "1", 1);
	ok1(parse_args(&argc, &argv, "-a", "somearg", "-a", "--", "-a", NULL));
	ok1(test_cb_called == 4);
	ok1(argc == 5);
	ok1(strcmp(argv[1], "somearg") == 0);
	ok1(strcmp(argv[2], "-a") == 0);
	ok1(strcmp(argv[3], "--") == 0);
	ok1(strcmp(argv[4], "-a") == 0);
	ok1(!argv[5]);

	/* parse_args allocates argv */
	free(argv);
	return exit_status();
}
