#include <ccan/cdump/cdump.h>
/* Include the C files directly. */
#include <ccan/cdump/cdump.c>
#include <ccan/tap/tap.h>

int main(void)
{
	struct cdump_definitions *defs;
	const struct cdump_type *t, *p;
	char *ctx = tal(NULL, char), *problems;

	/* This is how many tests you plan to run */
	plan_tests(111);

	defs = cdump_extract(ctx, "enum foo CDUMP(foo note) { BAR CDUMP(bar note) };", NULL);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->note, "foo note"));
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.enum_vals) == 1);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(!t->u.enum_vals[0].value);
	ok1(streq(t->u.enum_vals[0].note, "bar note"));

	defs = cdump_extract(ctx, "enum foo { BAR CDUMP(bar note) = 7 };",
			     &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.enum_vals) == 1);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(streq(t->u.enum_vals[0].value, "7"));
	ok1(streq(t->u.enum_vals[0].note, "bar note"));

	defs = cdump_extract(ctx, "enum foo {\n"
			     "BAR CDUMP(bar note) = 7,\n"
			     "BAZ CDUMP(baz note),\n"
			     "FUZZ CDUMP(fuzz note) };",
			     &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->structs));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->enums, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_ENUM);
	ok1(streq(t->name, "foo"));
	ok1(t->note == NULL);
	ok1(tal_count(t->u.enum_vals) == 3);
	ok1(streq(t->u.enum_vals[0].name, "BAR"));
	ok1(streq(t->u.enum_vals[0].value, "7"));
	ok1(streq(t->u.enum_vals[0].note, "bar note"));
	ok1(streq(t->u.enum_vals[1].name, "BAZ"));
	ok1(streq(t->u.enum_vals[1].note, "baz note"));
	ok1(!t->u.enum_vals[1].value);
	ok1(streq(t->u.enum_vals[2].name, "FUZZ"));
	ok1(streq(t->u.enum_vals[2].note, "fuzz note"));
	ok1(!t->u.enum_vals[2].value);

	defs = cdump_extract(ctx, "struct foo CDUMP(foo note) { int x CDUMP(x note); };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->enums));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_STRUCT);
	ok1(streq(t->name, "foo"));
	ok1(streq(t->note, "foo note"));
	ok1(tal_count(t->u.members) == 1);
	ok1(streq(t->u.members[0].name, "x"));
	ok1(streq(t->u.members[0].note, "x note"));
	ok1(t->u.members[0].type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[0].type->name, "int"));

	defs = cdump_extract(ctx, "struct foo { int x[5<< 1] CDUMP(x note); struct foo *next CDUMP(next note); struct unknown **ptrs[10] CDUMP(ptrs note); };", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->enums));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_STRUCT);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.members) == 3);

	ok1(streq(t->u.members[0].name, "x"));
	ok1(streq(t->u.members[0].note, "x note"));
	ok1(t->u.members[0].type->kind == CDUMP_ARRAY);
	ok1(streq(t->u.members[0].type->u.arr.size, "5<< 1"));
	ok1(t->u.members[0].type->u.arr.type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[0].type->u.arr.type->name, "int"));

	ok1(streq(t->u.members[1].name, "next"));
	ok1(streq(t->u.members[1].note, "next note"));
	ok1(t->u.members[1].type->kind == CDUMP_POINTER);
	ok1(t->u.members[1].type->u.ptr == t);

	ok1(streq(t->u.members[2].name, "ptrs"));
	ok1(streq(t->u.members[2].note, "ptrs note"));
	p = t->u.members[2].type;
	ok1(p->kind == CDUMP_ARRAY);
	ok1(streq(p->u.arr.size, "10"));
	p = p->u.arr.type;
	ok1(p->kind == CDUMP_POINTER);
	p = p->u.ptr;
	ok1(p->kind == CDUMP_POINTER);
	p = p->u.ptr;
	ok1(p->kind == CDUMP_STRUCT);
	ok1(streq(p->name, "unknown"));
	ok1(p->u.members == NULL);

	/* We don't put undefined structs into definition maps. */
	ok1(!strmap_get(&defs->structs, "unknown"));

	/* unions and comments. */
	defs = cdump_extract(ctx, "#if 0\n"
			     "/* Normal comment */\n"
			     "struct foo { int x[5 * 7/* Comment */]CDUMP(x note/*nocomment*/); };\n"
			     "// One-line comment\n"
			     "union bar CDUMP(bar note) { enum sometype x CDUMP(x note// Comment\n"
		"); union yun// Comment\n"
			     "y;};\n"
			     "#endif", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(t->note == NULL);
	ok1(tal_count(t->u.members) == 1);
	ok1(streq(t->u.members[0].name, "x"));
	ok1(streq(t->u.members[0].note, "x note"));
	ok1(t->u.members[0].type->kind == CDUMP_ARRAY);
	ok1(streq(t->u.members[0].type->u.arr.size, "5 * 7"));
	ok1(t->u.members[0].type->u.arr.type->kind == CDUMP_UNKNOWN);
	ok1(streq(t->u.members[0].type->u.arr.type->name, "int"));

	t = strmap_get(&defs->unions, "bar");
	ok1(t);
	ok1(streq(t->note, "bar note"));

	ok1(tal_count(t->u.members) == 2);
	ok1(streq(t->u.members[0].name, "x"));
	ok1(streq(t->u.members[0].note, "x note"));
	ok1(t->u.members[0].type->kind == CDUMP_ENUM);
	ok1(streq(t->u.members[0].type->name, "sometype"));
	ok1(!t->u.members[0].type->u.enum_vals);
	ok1(streq(t->u.members[1].name, "y"));
	ok1(t->u.members[1].note == NULL);
	ok1(t->u.members[1].type->kind == CDUMP_UNION);
	ok1(streq(t->u.members[1].type->name, "yun"));
	ok1(!t->u.members[1].type->u.members);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
