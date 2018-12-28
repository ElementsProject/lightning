/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_CDUMP_H
#define CCAN_CDUMP_H
#include <ccan/strmap/strmap.h>
#include <ccan/tal/tal.h>

enum cdump_type_kind {
	CDUMP_STRUCT,
	CDUMP_UNION,
	CDUMP_ENUM,
	CDUMP_ARRAY,
	CDUMP_POINTER,
	CDUMP_UNKNOWN
};

struct cdump_member {
	const char *name;
	const char *note;
	/* const, volatile */
	const char *qualifiers;
	struct cdump_type *type;
};

struct cdump_enum_val {
	const char *name;
	const char *note;
	/* Either NULL, or whatever follows '=' sign */
	const char *value;
};

struct cdump_array {
	const char *size;
	struct cdump_type *type;
};

struct cdump_type {
	enum cdump_type_kind kind;
	const char *name;
	const char *note;
	union {
		/* CDUMP_STRUCT / CDUMP_UNION: array */
		struct cdump_member *members;
		/* CDUMP_ENUM: array */
		struct cdump_enum_val *enum_vals;
		/* CDUMP_ARRAY */
		struct cdump_array arr;
		/* CDUMP_POINTER */
		const struct cdump_type *ptr;
	} u;
};

/* The map of typenames to definitions */
typedef STRMAP(struct cdump_type *) cdump_map_t;

struct cdump_definitions {
	cdump_map_t enums;
	cdump_map_t structs;
	cdump_map_t unions;
};

/**
 * cdump_extract - extract definitions from simple C code.
 * @ctx: context to tal() the return and @problems from (or NULL)
 * @code: a nul-terminated string of C definitions
 * @problems: a pointer to a char * to report problems (or NULL)
 *
 * This function parses @code and extracts enum, struct and union definitions
 * into the return.  If there is a parse error, it will return NULL and
 * allocate a problem string for human consumption.
 *
 * Annotations can be attached to structures, unions, enums, members
 * and enum values using CDUMP().  This comes after the name (or
 * after [] for array member declarations) and usually is removed from
 * C compilation using "#define CDUMP(x)".
 *
 * Example:
 *	// Returns name of first field of 'struct @name' in @code.
 *	static const char *first_field_of_struct(const char *code,
 *						 const char *name)
 *	{
 *		char *problems;
 *		struct cdump_definitions *defs;
 *		struct cdump_type *t;
 *
 *		defs = cdump_extract(NULL, code, &problems);
 *		if (!defs) {
 *			fprintf(stderr, "%s", problems);
 *			tal_free(problems);
 *			return NULL;
 *		}
 *		t = strmap_get(&defs->structs, name);
 *		if (!t) {
 *			fprintf(stderr, "Couldn't find struct %s", name);
 *			return NULL;
 *		}
 *		assert(t->kind == CDUMP_STRUCT);
 *		if (t->note)
 *			printf("Note on struct %s: %s\n", name, t->note);
 *		return t->u.members[0].name;
 *	}
 */
struct cdump_definitions *cdump_extract(const tal_t *ctx, const char *code,
					char **problems);
#endif /* CCAN_CDUMP_H */
