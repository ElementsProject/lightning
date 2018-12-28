#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct cdump_definitions *defs;
	const struct cdump_type *t;
	char *problems;

	/* This is how many tests you plan to run */
	plan_tests(12);

	defs = cdump_extract(NULL, "enum foo { BAR, BAZ, };", &problems);
	ok1(defs);
	ok1(!problems);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.enum_vals) == 2);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(!t->u.enum_vals[0].value);
	ok1(streq(t->u.enum_vals[1].name, "BAZ"));
	ok1(!t->u.enum_vals[1].value);
	tal_free(defs);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
