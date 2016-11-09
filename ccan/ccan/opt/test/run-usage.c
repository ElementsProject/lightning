#include <ccan/tap/tap.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdarg.h>
#include "utils.h"

/* Ensure width is sane. */
static const char *getenv_override(const char *name UNNEEDED)
{
	return "100";
}

#define getenv getenv_override

#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>

static char *my_cb(void *p UNNEEDED)
{
	return NULL;
}

/* Test helpers. */
int main(void)
{
	char *output;
	char *longname = strdup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	char *shortname = strdup("shortname");

	plan_tests(51);
	opt_register_table(subtables, NULL);
	opt_register_noarg("--kkk|-k", my_cb, NULL, "magic kkk option");
	opt_register_noarg("-?", opt_usage_and_exit, "<MyArgs>...",
			   "This message");
	opt_register_arg("--longname", opt_set_charp, opt_show_charp,
			 &longname, "a really long option default");
	opt_register_arg("--shortname", opt_set_charp, opt_show_charp,
			 &shortname, "a short option default");
	output = opt_usage("my name", "ExTrA Args");
	diag("%s", output);
	ok1(strstr(output, "Usage: my name"));
	ok1(strstr(output, "--jjj|-j|--lll|-l <arg>"));
	ok1(strstr(output, "ExTrA Args"));
	ok1(strstr(output, "-a "));
	ok1(strstr(output, " Description of a\n"));
	ok1(strstr(output, "-b <arg>"));
	ok1(strstr(output, " Description of b (default: b)\n"));
	ok1(strstr(output, "--ddd "));
	ok1(strstr(output, " Description of ddd\n"));
	ok1(strstr(output, "--eee <filename> "));
	ok1(strstr(output, " (default: eee)\n"));
	ok1(strstr(output, "long table options:\n"));
	ok1(strstr(output, "--ggg|-g "));
	ok1(strstr(output, " Description of ggg\n"));
	ok1(strstr(output, "-h|--hhh <arg>"));
	ok1(strstr(output, " Description of hhh\n"));
	ok1(strstr(output, "--kkk|-k"));
	ok1(strstr(output, "magic kkk option"));
	/* This entry is hidden. */
	ok1(!strstr(output, "--mmm|-m"));
	free(output);

	/* NULL should use string from registered options. */
	output = opt_usage("my name", NULL);
	diag("%s", output);
	ok1(strstr(output, "Usage: my name"));
	ok1(strstr(output, "--jjj|-j|--lll|-l <arg>"));
	ok1(strstr(output, "<MyArgs>..."));
	ok1(strstr(output, "-a "));
	ok1(strstr(output, " Description of a\n"));
	ok1(strstr(output, "-b <arg>"));
	ok1(strstr(output, " Description of b (default: b)\n"));
	ok1(strstr(output, "--ddd "));
	ok1(strstr(output, " Description of ddd\n"));
	ok1(strstr(output, "--eee <filename> "));
	ok1(strstr(output, " (default: eee)\n"));
	ok1(strstr(output, "long table options:\n"));
	ok1(strstr(output, "--ggg|-g "));
	ok1(strstr(output, " Description of ggg\n"));
	ok1(strstr(output, "-h|--hhh <arg>"));
	ok1(strstr(output, " Description of hhh\n"));
	ok1(strstr(output, "--kkk|-k"));
	ok1(strstr(output, "magic kkk option"));
	ok1(strstr(output, "--longname"));
	ok1(strstr(output, "a really long option default"));
	ok1(strstr(output, "(default: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"...)"));
	ok1(strstr(output, "--shortname"));
	ok1(strstr(output, "a short option default"));
	ok1(strstr(output, "(default: \"shortname\")"));
	/* This entry is hidden. */
	ok1(!strstr(output, "--mmm|-m"));
	free(output);

	reset_options();
	/* Empty table test. */
	output = opt_usage("nothing", NULL);
	ok1(strstr(output, "Usage: nothing \n"));
	free(output);

	/* No short args. */
	opt_register_noarg("--aaa", test_noarg, NULL, "AAAAll");
	output = opt_usage("onearg", NULL);
	ok1(strstr(output, "Usage: onearg \n"));
	ok1(strstr(output, "--aaa"));
	ok1(strstr(output, "AAAAll"));
	free(output);

	reset_options();
	/* Valgrind nails this to 100 anyway :( */
	setenv("COLUMNS", "100", 1);
	opt_register_noarg("--long", my_cb, NULL, "Extremely long option which requires more than one line for its full description to be shown in the usage message.");
	opt_register_noarg("--split", my_cb, NULL, "New line in\nlong option which requires more than one line for its full description to be shown in the usage message.");
	output = opt_usage("longarg", NULL);
	diag("%s", output);
	ok1(strstr(output, "Usage: longarg \n"));
	ok1(strstr(output, "\n"
		   "--long   Extremely long option which requires more than one line for its full description to be\n"
		   "         shown in the usage message.\n"));
	ok1(strstr(output, "\n"
		   "--split  New line in\n"
		   "         long option which requires more than one line for its full description to be shown in the\n"
		   "         usage message.\n"));
	free(output);

	free(shortname);
	free(longname);
	return exit_status();
}
