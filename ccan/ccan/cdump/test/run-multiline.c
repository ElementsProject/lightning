#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct cdump_definitions *defs;
	const struct cdump_type *t;
	char *ctx = tal(NULL, char), *problems;

	/* This is how many tests you plan to run */
	plan_tests(30);

	/* Multi-line preprocessor statement. */
	defs = cdump_extract(ctx,
			     "#if \\\n"
			     "SOME\\\n"
			     "THING\n"
			     "enum foo { BAR };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.enum_vals) == 1);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(!t->u.enum_vals[0].value);

	defs = cdump_extract(ctx,
			     "enum foo {\n"
			     "#if \\\n"
			     "SOME\\\n"
			     "THING\n"
			     " BAR };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.enum_vals) == 1);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(!t->u.enum_vals[0].value);

	/* Multi-line "one-line" comment. */
	defs = cdump_extract(ctx,
			     "enum foo {\n"
			     "// Comment \\\n"
			     "SOME\\\n"
			     "THING\n"
			     " BAR };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.enum_vals) == 1);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(!t->u.enum_vals[0].value);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
