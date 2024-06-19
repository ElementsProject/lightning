#include <ccan/cdump/cdump.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/err/err.h>

static bool dump_map(const char *name, void *t, void *unused)
{
	size_t i;
	struct cdump_type *tt;

	printf("struct {\n"
	       "	enum %s v;\n"
	       "	const char *name;\n"
	       "} enum_%s_names[] = {\n", name, name);

	tt = (struct cdump_type *)t;
	for (i = 0; i < tal_count(tt->u.enum_vals); i++)
		printf("	{ %s, \"%s\" },\n",
		       tt->u.enum_vals[i].name,
		       tt->u.enum_vals[i].name);
	printf("	{ 0, NULL } };\n");
	return true;
}

int main(int argc, char *argv[])
{
	char *code, *problems;
	struct cdump_definitions *defs;

	if (argc < 2)
		errx(1, "Usage: cdump-enumstr <filename> [<enums>...]");

	code = grab_file(NULL, streq(argv[1], "-") ? NULL : argv[1]);
	if (!code)
		err(1, "Reading %s", argv[1]);

	defs = cdump_extract(code, code, &problems);
	if (!defs)
		errx(1, "Parsing %s:\n%s", argv[1], problems);

	if (argc == 2)
		strmap_iterate(&defs->enums, dump_map, NULL);
	else {
		unsigned int i;
		struct cdump_type *t;

		for (i = 2; i < argc; i++) {
			t = strmap_get(&defs->enums, argv[i]);
			if (!t)
				errx(1, "Enum %s not found", argv[i]);
			dump_map(argv[i], t, NULL);
		}
	}
	return 0;
}
