#include <ccan/tal/str/str.h>
#include <stdlib.h>
#include <stdio.h>
#include <ccan/tal/str/str.c>
#include <ccan/tap/tap.h>
#include "helper.h"

int main(int argc, char *argv[])
{
	char *str, *copy;

	plan_tests(1);
	str = malloc(5);
	memcpy(str, "hello", 5);
	/* We should be fine to strndup src without nul terminator. */
	copy = tal_strndup(NULL, str, 5);
	ok1(!strcmp(copy, "hello"));
	tal_free(copy);
	free(str);

	return exit_status();
}
