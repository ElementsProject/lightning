#ifndef LIGHTNING_COMMON_GRAPHQL_UTIL_H
#define LIGHTNING_COMMON_GRAPHQL_UTIL_H
#include "config.h"
#include <external/jsmn/jsmn.h>

struct command;
struct json_stream;
struct graphql_field;
struct gqlcb_fieldspec;
struct gqlcb_data;

typedef struct command_result *(*param_parser_func)(
	struct command *cmd, const char *buffer, jsmntok_t *params,
	struct gqlcb_data *d);

typedef struct command_result *(*prep_func)(
	struct command *cmd, const char *buffer, struct graphql_field *field,
	struct gqlcb_fieldspec *f, struct gqlcb_data *parent);

typedef void (*json_emitter)(
	struct json_stream *response,
	struct gqlcb_data *d,
	const void *object);

/* This is a generic table entry. Normally, an identical type-specialized
 * version will be used, declared via provided macros.
 */
struct gqlcb_fieldspec {
	const char *field_name;
	bool disable_alias, disable_subfield_selection, has_subfields;
	param_parser_func arg_parser;
	prep_func subfield_prepper;
	struct gqlcb_fieldspec *subtable;
	json_emitter json_emitter;
};

// GraphQL CallBack data
struct gqlcb_data {
	const char *name; // i.e. alias, if specified, otherwise name
	struct gqlcb_data *parent; // next level up, or null
	const struct gqlcb_fieldspec *fieldspec; // the callback's table entry
	struct graphql_field *field; // where we are hanging from in the GraphQL AST

	// execution-time variables
	void *current_object; // the object that will be passed to the callback
};

/* This macro defines the callback and structs for each type of callback table
 * in order to preserve type safety for the callback argument. If macro is used
 * with arguments of declname = foo and structname = bar, the following types
 * would be defined:
 *   typedef foofield_emitter - foo callback type that accepts a pointer to struct bar
 *   struct foo_fieldspec - table entry for foo callbacks
 *   struct foo_field_prep - static prep function for foo callbacks
 */
#define GQLCB_TABLE_TYPES_DECL(declname, structname) \
typedef void (*declname##field_emitter)(struct json_stream *response, \
					struct gqlcb_data *data, \
					const struct structname *object); \
struct declname##_fieldspec { \
	const char *field_name; \
	bool disable_alias, disable_subfield_selection, has_subfields; \
	param_parser_func arg_parser; \
	prep_func subfield_prepper; \
	struct gqlcb_fieldspec *subtable; \
	declname##field_emitter json_emitter; \
}; \

const char *get_alias(struct graphql_field *field);

void convert_args_to_paramtokens(const tal_t *ctx, struct graphql_field *field, jsmntok_t **params);

#define NO_ARGS(cmd, field) \
	if ((field)->args) \
		return command_fail((cmd), GRAPHQL_ARG_ERROR, \
				    "no arguments accepted for '%s'", \
				    (field)->name->token_string) \

#define NO_SUBFIELDS(cmd, field) \
	if ((field)->sel_set) \
		return command_fail((cmd), GRAPHQL_FIELD_ERROR, \
				    "no subfields known for '%s'", \
				    (field)->name->token_string) \

#define NO_SUBFIELD_SELECTION(cmd, field) \
	if ((field)->sel_set) \
		return command_fail((cmd), GRAPHQL_FEATURE_NOT_SUPPORTED, \
				    "subfield selection not supported on field '%s'", \
				    (field)->name->token_string) \

#define NO_ALIAS_SUPPORT(cmd, field) \
	if (!streq((field)->name->token_string, get_alias(field))) \
		return command_fail((cmd), GRAPHQL_FEATURE_NOT_SUPPORTED, \
				    "alias not supported on field '%s'", \
				    (field)->name->token_string) \

#define create_cbd(field, tname, ctx, datatype) \
        ((datatype *)create_cbd_((field), (tname), (ctx), tal((ctx), datatype)))
void *create_cbd_(struct graphql_field *field, const char *tname, void *ctx, void *obj);

#define get_cbd(field, tname, datatype) \
        ((datatype *)get_cbd_((field), (tname)))
void *get_cbd_(const struct graphql_field *field, const char *tname);

struct command_result *
object_prep(struct command *cmd, const char *buffer,
	    struct graphql_field *field, struct gqlcb_fieldspec *table,
	    struct gqlcb_data *d);

#define field_prep(c,b,f,t,p) field_prep_typed((c),(b),(f),(t),(p),NULL,true)
struct command_result *
field_prep_typed(struct command *cmd, const char *buffer,
		 struct graphql_field *field, struct gqlcb_fieldspec *table,
		 void *parent, const char *tname, bool required);

struct gqlcb_fieldspec *gqlcb_search(struct graphql_field *field,
                                     struct gqlcb_fieldspec list[]);

/*
struct command_result *
field_search(struct command *cmd, const char *buffer,
	     struct graphql_field *field, struct gqlcb_fieldspec list[],
             struct gqlcb_data *parent);
*/

#endif /* LIGHTNING_COMMON_GRAPHQL_UTIL_H */
