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
	plan_tests(37);

	defs = cdump_extract(ctx, "__attribute__((xxx)) enum foo __attribute__((xxx)) { BAR } __attribute__((xxx));", NULL);
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

	defs = cdump_extract(ctx, "__attribute__((xxx)) struct foo __attribute__((xxx)) { int __attribute__((xxx)) x __attribute__((xxx)); } __attribute__((xxx));", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->enums));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_STRUCT);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.members) == 1);
	ok1(streq(t->u.members[0].name, "x"));
	ok1(t->u.members[0].type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[0].type->name, "int"));

	defs = cdump_extract(ctx, "struct foo { int x, __attribute__((xxx)) y; };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->enums));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_STRUCT);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.members) == 2);

	ok1(streq(t->u.members[0].name, "x"));
	ok1(t->u.members[0].type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[0].type->name, "int"));

	ok1(streq(t->u.members[1].name, "y"));
	ok1(t->u.members[1].type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[1].type->name, "int"));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
