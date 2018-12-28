#include <ccan/autodata/autodata.h>
/* Include the C files directly. */
#include <ccan/autodata/autodata.c>
#include <ccan/tap/tap.h>

AUTODATA_TYPE(autostrings, char);

AUTODATA(autostrings, "hello");
AUTODATA(autostrings, "world");

int main(void)
{
	char **table;
	size_t num;
	int i, hello = -1, world = -1, helper = -1;

	/* This is how many tests you plan to run */
	plan_tests(4);

	table = autodata_get(autostrings, &num);
	ok1(num == 3);

	for (i = 0; i < num; i++) {
		if (strcmp(table[i], "hello") == 0)
			hello = i;
		else if (strcmp(table[i], "world") == 0)
			world = i;
		else if (strcmp(table[i], "helper") == 0)
			helper = i;
		else
			fail("Unknown entry %s", table[i]);
	}
	ok1(hello != -1);
	ok1(world != -1);
	ok1(helper != -1);

	autodata_free(table);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
