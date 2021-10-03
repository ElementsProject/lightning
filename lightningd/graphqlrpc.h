#ifndef LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H
#define LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H
#include "config.h"

struct json_stream;
struct command;
struct graphql_field;

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

typedef void (*toplevel_json_add_cb)(struct json_stream *js,
				     const struct graphql_field *field);

struct toplevel_field_data {
	toplevel_json_add_cb json_add_func;
};

#define create_cbd(field, tname, ctx, datatype) \
	((datatype *)create_cbd_((field), (tname), (ctx), tal((ctx), datatype)))
void *create_cbd_(struct graphql_field *field, const char *tname, void *ctx, void *obj);

#define get_cbd(field, tname, datatype) \
	((datatype *)get_cbd_((field), (tname)))
void *get_cbd_(const struct graphql_field *field, const char *tname);

#endif /* LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H */
