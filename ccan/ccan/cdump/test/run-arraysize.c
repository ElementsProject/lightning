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
	plan_tests(20);

	/* unions and comments. */
	defs = cdump_extract(ctx,
			     "struct foo {\n"
			     "	int x[5 */* Comment */7];\n"
			     "	int y[5// Comment\n"
			     " * 7];\n"
			     "  int z[5 *\n"
			     "#ifdef FOO\n"
			     " 7\n"
			     "#endif\n"
			     "];\n"
			     "};\n", &problems);

	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(tal_count(t->u.members) == 3);
	ok1(streq(t->u.members[0].name, "x"));
	ok1(t->u.members[0].type->kind == CDUMP_ARRAY);
	ok1(streq(t->u.members[0].type->u.arr.size, "5 * 7"));
	ok1(t->u.members[0].type->u.arr.type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[0].type->u.arr.type->name, "int"));

	ok1(streq(t->u.members[1].name, "y"));
	ok1(t->u.members[1].type->kind == CDUMP_ARRAY);
	ok1(streq(t->u.members[1].type->u.arr.size, "5 * 7"));
	ok1(t->u.members[1].type->u.arr.type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[1].type->u.arr.type->name, "int"));

	ok1(streq(t->u.members[2].name, "z"));
	ok1(t->u.members[2].type->kind == CDUMP_ARRAY);
	ok1(streq(t->u.members[2].type->u.arr.size, "5 * 7"));
	ok1(t->u.members[2].type->u.arr.type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[2].type->u.arr.type->name, "int"));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
