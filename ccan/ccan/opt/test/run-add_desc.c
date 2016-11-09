#include <ccan/tap/tap.h>
#include <ccan/opt/opt.c>
#include <ccan/opt/usage.c>
#include <ccan/opt/helpers.c>
#include <ccan/opt/parse.c>

static void show_10(char buf[OPT_SHOW_LEN], const void *arg UNNEEDED)
{
	memset(buf, 'X', 10);
	buf[10] = '\0';
}

static void show_max(char buf[OPT_SHOW_LEN], const void *arg UNNEEDED)
{
	memset(buf, 'X', OPT_SHOW_LEN);
}

/* Test add_desc helper. */
int main(void)
{
	struct opt_table opt;
	char *ret;
	size_t len, max;

	plan_tests(30);

	opt.show = NULL;
	opt.names = "01234";
	opt.desc = "0123456789 0";
	opt.type = OPT_NOARG;
	len = max = 0;

	/* Fits easily. */
	ret = add_desc(NULL, &len, &max, 10, 30, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234     0123456789 0\n") == 0);
	free(ret); len = max = 0;

	/* Name just fits. */
	ret = add_desc(NULL, &len, &max, 7, 30, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234  0123456789 0\n") == 0);
	free(ret); len = max = 0;

	/* Name doesn't fit. */
	ret = add_desc(NULL, &len, &max, 6, 30, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234\n"
		   "      0123456789 0\n") == 0);
	free(ret); len = max = 0;

	/* Description just fits. */
	ret = add_desc(NULL, &len, &max, 7, 19, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234  0123456789 0\n") == 0);
	free(ret); len = max = 0;

	/* Description doesn't quite fit. */
	ret = add_desc(NULL, &len, &max, 7, 18, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234  0123456789\n"
		   "       0\n") == 0);
	free(ret); len = max = 0;

	/* Neither quite fits. */
	ret = add_desc(NULL, &len, &max, 6, 17, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, 
		   "01234\n"
		   "      0123456789\n"
		   "      0\n") == 0);
	free(ret); len = max = 0;

	/* With show function, fits just. */
	opt.show = show_10;
	ret = add_desc(NULL, &len, &max, 7, 41, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234  0123456789 0 (default: XXXXXXXXXX)\n") == 0);
	free(ret); len = max = 0;

	/* With show function, just too long. */
	ret = add_desc(NULL, &len, &max, 7, 40, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234  0123456789 0\n"
		   "        (default: XXXXXXXXXX)\n") == 0);
	free(ret); len = max = 0;

	/* With maximal show function, fits just (we assume OPT_SHOW_LEN = 80. */
	opt.show = show_max;
	ret = add_desc(NULL, &len, &max, 7, 114, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234  0123456789 0 (default: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX...)\n") == 0);
	free(ret); len = max = 0;

	/* With maximal show function, just too long. */
	ret = add_desc(NULL, &len, &max, 7, 113, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234  0123456789 0\n"
		   "        (default: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX...)\n") == 0);
	free(ret); len = max = 0;

	/* With added " <arg>".  Fits, just. */
	opt.show = NULL;
	opt.type = OPT_HASARG;
	ret = add_desc(NULL, &len, &max, 13, 25, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234 <arg>  0123456789 0\n") == 0);
	free(ret); len = max = 0;

	/* With added " <arg>".  Name doesn't quite fit. */
	ret = add_desc(NULL, &len, &max, 12, 25, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234 <arg>\n"
		   "            0123456789 0\n") == 0);
	free(ret); len = max = 0;

	/* With added " <arg>".  Desc doesn't quite fit. */
	ret = add_desc(NULL, &len, &max, 13, 24, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234 <arg>  0123456789\n"
		   "             0\n") == 0);
	free(ret); len = max = 0;

	/* Empty description, with <arg> and default.  Just fits. */
	opt.show = show_10;
	opt.desc = "";
	ret = add_desc(NULL, &len, &max, 13, 35, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret, "01234 <arg>   (default: XXXXXXXXXX)\n") == 0);
	free(ret); len = max = 0;

	/* Empty description, with <arg> and default.  Doesn't quite fit. */
	opt.show = show_10;
	opt.desc = "";
	ret = add_desc(NULL, &len, &max, 13, 34, &opt);
	ok1(len < max);
	ret[len] = '\0';
	ok1(strcmp(ret,
		   "01234 <arg>  \n"
		   "              (default: XXXXXXXXXX)\n") == 0);
	free(ret); len = max = 0;

	return exit_status();
}
