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
	plan_tests(63);

	defs = cdump_extract(ctx,
			     "struct foo {\n"
			     "	long l;\n"
			     "	long int li;\n"
			     "	unsigned long *ulp;\n"
			     "	unsigned long int *ulip;\n"
			     "};", &problems);
	ok1(defs);
	ok1(tal_parent(defs) == ctx);
	ok1(!problems);

	ok1(strmap_empty(&defs->enums));
	ok1(strmap_empty(&defs->unions));
	t = strmap_get(&defs->structs, "foo");
	ok1(t);
	ok1(t->kind == CDUMP_STRUCT);
	ok1(streq(t->name, "foo"));
	ok1(tal_count(t->u.members) == 4);

	ok1(streq(t->u.members[0].name, "l"));
	p = t->u.members[0].type;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "long"));

	ok1(streq(t->u.members[1].name, "li"));
	p = t->u.members[1].type;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "long int"));

	ok1(streq(t->u.members[2].name, "ulp"));
	p = t->u.members[2].type;
	ok1(p->kind == CDUMP_POINTER);
	p = p->u.ptr;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "unsigned long"));

	ok1(streq(t->u.members[3].name, "ulip"));
	p = t->u.members[3].type;
	ok1(p->kind == CDUMP_POINTER);
	p = p->u.ptr;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "unsigned long int"));

	defs = cdump_extract(ctx,
			     "struct foo {\n"
			     "	volatile long vl;\n"
			     "	const long cl;\n"
			     "	volatile const long long int *vclli;\n"
			     "};", &problems);
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

	ok1(streq(t->u.members[0].name, "vl"));
	ok1(streq(t->u.members[0].qualifiers, "volatile"));
	p = t->u.members[0].type;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "long"));

	ok1(streq(t->u.members[1].name, "cl"));
	ok1(streq(t->u.members[1].qualifiers, "const"));
	p = t->u.members[1].type;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "long"));

	ok1(streq(t->u.members[2].name, "vclli"));
	ok1(streq(t->u.members[2].qualifiers, "volatile const"));
	p = t->u.members[2].type;
	ok1(p->kind == CDUMP_POINTER);
	p = p->u.ptr;
	ok1(p->kind == CDUMP_UNKNOWN);
	ok1(streq(p->name, "long long int"));

	defs = cdump_extract(ctx,
			     "struct foo {\n"
			     "	volatile struct bar *a, b;\n"
			     "};", &problems);
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

	ok1(streq(t->u.members[0].name, "a"));
	ok1(streq(t->u.members[0].qualifiers, "volatile"));
	p = t->u.members[0].type;
	ok1(p->kind == CDUMP_POINTER);
	p = p->u.ptr;
	ok1(p->kind == CDUMP_STRUCT);
	ok1(streq(p->name, "bar"));

	ok1(streq(t->u.members[1].name, "b"));
	ok1(streq(t->u.members[1].qualifiers, "volatile"));
	p = t->u.members[1].type;
	ok1(p->kind == CDUMP_STRUCT);
	ok1(streq(p->name, "bar"));

	tal_free(ctx);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
