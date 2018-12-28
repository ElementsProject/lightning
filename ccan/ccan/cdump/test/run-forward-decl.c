#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct cdump_definitions *defs;
	const struct cdump_type *t, *t2;
	char *ctx = tal(NULL, char), *problems;

	/* This is how many tests you plan to run */
	plan_tests(16);

	defs = cdump_extract(ctx, "struct foo { struct bar *bar; };\n"
			     "struct bar { int x; };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	t2 = strmap_get(&defs->structs, "bar");
	ok1(t2);

	ok1(t2->kind == CDUMP_STRUCT);
	ok1(streq(t2->name, "bar"));
	ok1(tal_count(t2->u.members) == 1);
	ok1(t2->u.members[0].type->kind == CDUMP_UNKNOWN);
	ok1(streq(t2->u.members[0].type->name, "int"));

	ok1(t->kind == CDUMP_STRUCT);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.members) == 1);
	ok1(streq(t->u.members[0].name, "bar"));
	ok1(t->u.members[0].type->kind == CDUMP_POINTER);
	ok1(t->u.members[0].type->u.ptr == t2);

	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
