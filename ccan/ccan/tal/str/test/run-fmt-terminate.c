#include <ccan/tal/str/str.h>
#include <stdlib.h>
#include <stdio.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

/* Empty format string: should still terminate! */
int main(void)
{
	char *str;
	const char *fmt = "";

	plan_tests(2);
	/* GCC complains about empty format string, complains about non-literal
	 * with no args... */
	str = tal_fmt(NULL, fmt, "");
	ok1(!strcmp(str, ""));
	ok1(tal_count(str) == strlen(str) + 1);
	tal_free(str);

	return exit_status();
}
